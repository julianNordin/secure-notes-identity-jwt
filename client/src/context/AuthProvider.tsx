import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { fetchMe } from '../lib/api'
import {
  restoreSession,
  setSessionEndedHandler,
  signIn as postLogin,
  signOut as postLogout,
  signUp as postRegister,
} from '../lib/apiClient'
import { AuthContext } from './auth'
import type { AuthStatus, AuthValue } from './auth'
import type { Me } from '../lib/types'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null)
  const [status, setStatus] = useState<AuthStatus>('restoring')

  // The server can end a session the client still believes in: a refresh token
  // that expired, or one that was replayed and took its whole family down with
  // it. However it happens, the client finds out here rather than by rendering a
  // notes page that answers 401 to everything on it.
  useEffect(() => {
    setSessionEndedHandler(() => {
      setUser(null)
      setStatus('anonymous')
    })

    return () => setSessionEndedHandler(null)
  }, [])

  useEffect(() => {
    let cancelled = false

    async function restore() {
      // The reload destroyed the in-memory access token, which is the price of
      // keeping it out of storage, and the refresh token is what buys it back.
      //
      // StrictMode runs this effect twice in development. Both calls join the
      // one refresh inside apiClient rather than racing it - the single-flight
      // promise earning its keep before the application has rendered anything.
      const restored = await restoreSession()
      if (cancelled) {
        return
      }

      if (!restored) {
        setStatus('anonymous')
        return
      }

      try {
        setUser(await fetchMe())
        setStatus('authenticated')
      } catch {
        setStatus('anonymous')
      }
    }

    void restore()

    return () => {
      cancelled = true
    }
  }, [])

  const signIn = useCallback(async (email: string, password: string) => {
    await postLogin(email, password)
    setUser(await fetchMe())
    setStatus('authenticated')
  }, [])

  const signOut = useCallback(async () => {
    await postLogout()
    setUser(null)
    setStatus('anonymous')
  }, [])

  const value = useMemo<AuthValue>(
    () => ({ user, status, signIn, signUp: postRegister, signOut }),
    [user, status, signIn, signOut],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}
