import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useAuth } from '../context/auth'
import styles from './AuthForm.module.css'

export default function RegisterPage() {
  const { status, signUp } = useAuth()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [accepted, setAccepted] = useState(false)
  const [busy, setBusy] = useState(false)

  if (status === 'authenticated') {
    return <Navigate to="/notes" replace />
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError(null)

    try {
      await signUp(email, password, displayName)
      setAccepted(true)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Registration failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={styles.shell}>
      <form className={styles.card} onSubmit={submit}>
        <h1 className={styles.title}>Register</h1>
        <p className={styles.subtitle}>SecureNotes</p>

        {error !== null && <p className={styles.error}>{error}</p>}

        {/*
          Worded to match what the server actually promised. Registration answers
          202 whether or not the address was already taken, so "check your email"
          is the only truthful thing to say - "account created" would be a claim
          the client cannot make, and "that address is already registered" would
          be the enumeration oracle the 202 exists to withhold. The server sends
          that sentence to the address itself, where only its owner can read it.
        */}
        {accepted && (
          <p className={styles.notice}>
            If that address can be registered, a confirmation email is on its way. Check your
            inbox - or, in development, the API log.
          </p>
        )}

        <label className={styles.field}>
          <span className={styles.label}>Email</span>
          <input
            type="email"
            value={email}
            autoComplete="username"
            required
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>

        <label className={styles.field}>
          <span className={styles.label}>Display name (optional)</span>
          <input
            type="text"
            value={displayName}
            autoComplete="nickname"
            onChange={(event) => setDisplayName(event.target.value)}
          />
        </label>

        <label className={styles.field}>
          <span className={styles.label}>Password (at least 12 characters)</span>
          <input
            type="password"
            value={password}
            autoComplete="new-password"
            required
            minLength={12}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>

        <button className={styles.submit} type="submit" disabled={busy}>
          {busy ? 'Registering...' : 'Register'}
        </button>

        <p className={styles.footer}>
          Already registered? <Link to="/login">Sign in</Link>
        </p>
      </form>
    </div>
  )
}
