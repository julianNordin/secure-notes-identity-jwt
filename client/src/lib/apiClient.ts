import type { ProblemDetails, TokenResponse } from './types'

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5080'

/*
 * The access token lives here and nowhere else: a module-level variable, which
 * means it dies with the tab and cannot be read back by anything that manages to
 * run on this origin later.
 *
 * The refresh token is not in this file at all any more. Until Phase 18 it sat in
 * localStorage, where every script on the origin could read a credential that
 * outlived the tab by two weeks. It is now an httpOnly cookie: the browser holds
 * it, attaches it to /api/auth on its own, and no script here - ours or anybody
 * else's - can read it. There is nothing left to store, which is why the storage
 * code is gone rather than merely tidied.
 */
let accessToken: string | null = null

/*
 * Clear the Phase 17 key once, on load. Moving the token into a cookie does
 * nothing at all for somebody whose browser is still holding the old value: it
 * goes on sitting in localStorage, readable by any script on this origin, until
 * something deletes it. A refactor that leaves the old copy lying around has
 * moved the credential rather than protected it.
 *
 * Guarded, because localStorage throws outright when a browser is set to block
 * site data, and a cleanup that bricks the application on load is a poor trade.
 */
try {
  localStorage.removeItem('securenotes.refresh_token')
} catch {
  // Nothing to clean up if there is no storage to clean it from.
}

/** Called when the session cannot be renewed, so the UI can stop pretending. */
let onSessionEnded: (() => void) | null = null

export function setSessionEndedHandler(handler: (() => void) | null): void {
  onSessionEnded = handler
}

function storeSession(tokens: TokenResponse): void {
  accessToken = tokens.access_token
}

function endSession(): void {
  accessToken = null
  onSessionEnded?.()
}

/** The parsed RFC 9457 body, or a usable fallback when there is not one. */
export async function problemFrom(response: Response): Promise<string> {
  try {
    const problem = (await response.json()) as ProblemDetails
    const fieldErrors = Object.values(problem.errors ?? {}).flat()

    return fieldErrors[0] ?? problem.detail ?? problem.title ?? `Request failed (${response.status}).`
  } catch {
    return `Request failed (${response.status}).`
  }
}

let refreshInFlight: Promise<string | null> | null = null

/*
 * Single-flight, and this is a security control rather than an optimisation.
 *
 * Refresh tokens rotate: presenting one spends it and mints a replacement. So if
 * ten requests all hit a 401 at the same moment - which is exactly what happens
 * when an access token expires while a page is loading - and each starts its own
 * refresh with the same stored token, the first to arrive spends it and the other
 * nine present a token that has already been used. That is precisely the signal
 * Phase 08's reuse detector exists to catch, and it does not ask who is at fault:
 * it revokes the entire token family and logs the user out of every device.
 *
 * The user would be signed out for the crime of loading a page, and the cause
 * would be a client refreshing correctly, ten times at once. Hence one promise
 * that everybody waits on. This is not optional here.
 */
function refresh(): Promise<string | null> {
  refreshInFlight ??= requestRefresh().finally(() => {
    refreshInFlight = null
  })

  return refreshInFlight
}

async function requestRefresh(): Promise<string | null> {
  // No body, and nothing read from storage. The refresh token rides along as a
  // cookie the browser attaches by itself, which is the entire point: this code
  // could not send the token if it wanted to, and neither could an attacker's.
  const response = await fetch(`${baseUrl}/api/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  })

  if (!response.ok) {
    // Refused. Either it expired, or it was replayed and the family is gone.
    // Both mean this browser no longer has a session, whatever the UI thinks.
    endSession()
    return null
  }

  const tokens = (await response.json()) as TokenResponse
  storeSession(tokens)

  return tokens.access_token
}

function send(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers)

  if (accessToken !== null) {
    headers.set('Authorization', `Bearer ${accessToken}`)
  }

  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  // credentials: 'include' on every request, because a cross-origin fetch does
  // not send or store cookies without it - and that includes storing the
  // Set-Cookie that login replies with. In practice the cookie only ever rides on
  // /api/auth, because that is the Path the server scoped it to.
  return fetch(`${baseUrl}${path}`, { ...init, headers, credentials: 'include' })
}

/**
 * Sends a request, and on a 401 refreshes once and replays it.
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const response = await send(path, init)

  // Nothing to renew if this browser was never signed in. The client can no
  // longer look for a stored refresh token to decide - it cannot see the cookie -
  // so the question it can still answer is whether it ever held an access token.
  if (response.status !== 401 || accessToken === null) {
    return response
  }

  const renewed = await refresh()
  if (renewed === null) {
    return response
  }

  // Replayed once, and once only. A request that 401s again holding a token
  // minted a moment ago is not suffering from staleness, and retrying harder
  // turns one refused request into a loop.
  return send(path, init)
}

/** RFC 6749's password grant, under another name. */
export async function signIn(email: string, password: string): Promise<void> {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),

    // Without this the browser throws the Set-Cookie away. A cross-origin fetch
    // does not store cookies unless it asks to, and it fails silently: login
    // returns 200, the access token works, everything looks right, and the
    // session simply does not survive the first reload.
    credentials: 'include',
  })

  if (!response.ok) {
    throw new Error(await problemFrom(response))
  }

  storeSession((await response.json()) as TokenResponse)
}

/**
 * Registration answers 202 whether or not the address was already taken, so
 * there is nothing here to report except that the request was accepted. That is
 * the server refusing to be an oracle, and the client must not invent the answer
 * it withheld.
 */
export async function signUp(email: string, password: string, displayName: string): Promise<void> {
  const response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, displayName: displayName || null }),
  })

  if (!response.ok) {
    throw new Error(await problemFrom(response))
  }
}

export async function signOut(): Promise<void> {
  // Best effort. If the network is gone the server keeps a live refresh token
  // until it expires, but this tab has still forgotten its access token - so the
  // local half of logging out must not depend on the remote half succeeding. The
  // server clears the cookie in its response, which is the only way it can be
  // cleared now that no script can touch it.
  await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  }).catch(() => undefined)

  endSession()
}

/**
 * Rebuilds a session after a reload. The access token was in memory and the
 * reload destroyed it, which is the price of keeping it out of storage - and the
 * cookie is what buys it back.
 */
export async function restoreSession(): Promise<boolean> {
  // Always asks, because it can no longer check first: whether a refresh cookie
  // exists is knowledge the browser deliberately withholds from script. One 401
  // on a cold start is the honest cost of that, and it is cheaper than the thing
  // it bought.
  return (await refresh()) !== null
}
