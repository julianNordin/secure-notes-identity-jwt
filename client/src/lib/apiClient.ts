import type { ProblemDetails, TokenResponse } from './types'

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5080'

const refreshTokenKey = 'securenotes.refresh_token'

/*
 * The access token lives here and nowhere else: a module-level variable, which
 * means it dies with the tab and cannot be read back by anything that manages to
 * run on this origin later. Deliberately not in localStorage - a token in storage
 * outlives the tab, and any XSS on this origin can read it at leisure.
 *
 * The refresh token, by contrast, IS in localStorage below, which is worse in
 * exactly the same way and worse again because it lives for days rather than
 * fifteen minutes. That is not an oversight. It is the naive version, shipped
 * honestly, so that Phase 18's move to an httpOnly cookie has a "before" to point
 * at - the diff is the argument, and writing it correctly now would leave nothing
 * to show.
 */
let accessToken: string | null = null

/** Called when the session cannot be renewed, so the UI can stop pretending. */
let onSessionEnded: (() => void) | null = null

export function setSessionEndedHandler(handler: (() => void) | null): void {
  onSessionEnded = handler
}

export function hasStoredSession(): boolean {
  return localStorage.getItem(refreshTokenKey) !== null
}

function storeSession(tokens: TokenResponse): void {
  accessToken = tokens.access_token
  localStorage.setItem(refreshTokenKey, tokens.refresh_token)
}

function endSession(): void {
  accessToken = null
  localStorage.removeItem(refreshTokenKey)
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
  const refreshToken = localStorage.getItem(refreshTokenKey)
  if (refreshToken === null) {
    return null
  }

  const response = await fetch(`${baseUrl}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
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

  return fetch(`${baseUrl}${path}`, { ...init, headers })
}

/**
 * Sends a request, and on a 401 refreshes once and replays it.
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const response = await send(path, init)

  if (response.status !== 401 || !hasStoredSession()) {
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
  const refreshToken = localStorage.getItem(refreshTokenKey)

  if (refreshToken !== null) {
    // Best effort. If the network is gone the server keeps a live refresh token
    // until it expires, but this browser has still forgotten it - so the local
    // half of logging out must not depend on the remote half succeeding.
    await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => undefined)
  }

  endSession()
}

/**
 * Rebuilds a session after a reload. The access token was in memory and the
 * reload destroyed it, which is the price of keeping it out of storage - and the
 * refresh token is what buys it back. Returns false when the browser has nothing
 * to trade.
 */
export async function restoreSession(): Promise<boolean> {
  return hasStoredSession() && (await refresh()) !== null
}
