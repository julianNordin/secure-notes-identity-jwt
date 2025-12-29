import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/auth'
import styles from './AuthForm.module.css'

export default function LoginPage() {
  const { status, signIn } = useAuth()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (status === 'authenticated') {
    return <Navigate to="/notes" replace />
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError(null)

    try {
      await signIn(email, password)
      navigate('/notes', { replace: true })
    } catch (failure) {
      // Whatever the server said, verbatim. A wrong password and an address that
      // has never registered produce a byte-identical 401 on purpose, and the
      // client must not be more helpful than the server was willing to be -
      // "no account with that email" here would hand back the exact oracle the
      // API spent Phase 04 and Phase 05 refusing to be.
      setError(failure instanceof Error ? failure.message : 'Sign in failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={styles.shell}>
      <form className={styles.card} onSubmit={submit}>
        <h1 className={styles.title}>Sign in</h1>
        <p className={styles.subtitle}>SecureNotes</p>

        {error !== null && <p className={styles.error}>{error}</p>}

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
          <span className={styles.label}>Password</span>
          <input
            type="password"
            value={password}
            autoComplete="current-password"
            required
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>

        <button className={styles.submit} type="submit" disabled={busy}>
          {busy ? 'Signing in...' : 'Sign in'}
        </button>

        <p className={styles.footer}>
          No account? <Link to="/register">Register</Link>
        </p>
      </form>
    </div>
  )
}
