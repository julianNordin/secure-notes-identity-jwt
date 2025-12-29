import { createContext, useContext } from 'react'
import type { Me } from '../lib/types'

export type AuthStatus = 'restoring' | 'authenticated' | 'anonymous'

export interface AuthValue {
  user: Me | null
  status: AuthStatus
  signIn: (email: string, password: string) => Promise<void>
  signUp: (email: string, password: string, displayName: string) => Promise<void>
  signOut: () => Promise<void>
}

export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)

  if (value === null) {
    throw new Error('useAuth was called outside an AuthProvider.')
  }

  return value
}
