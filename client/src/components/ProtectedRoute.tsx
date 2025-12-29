import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '../context/auth'

/**
 * The route guard - and it is worth being exact about what it does, because the
 * name oversells it. It decides what to render. It does not decide what the
 * caller may have. Every route behind it is also protected by [Authorize] on the
 * server, and that is the check that counts; this one only stops the browser
 * rendering a page whose every request would come back 401.
 */
export default function ProtectedRoute() {
  const { status } = useAuth()

  // 'restoring' is neither yes nor no, and collapsing it into "no" is the bug
  // that makes an application forget you every time you reload it: the access
  // token lives in memory, so immediately after a reload there is genuinely no
  // session yet - one promise away from there being one.
  if (status === 'restoring') {
    return <p>Restoring your session...</p>
  }

  if (status === 'anonymous') {
    return <Navigate to="/login" replace />
  }

  return <Outlet />
}
