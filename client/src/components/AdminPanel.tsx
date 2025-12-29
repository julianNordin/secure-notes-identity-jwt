import { useEffect, useState } from 'react'
import { fetchAllNotes } from '../lib/api'
import type { AdminNote } from '../lib/types'
import styles from '../pages/NotesPage.module.css'

/**
 * Every note in the system, with its owner.
 */
/*
 * This component is rendered only when the signed-in user's roles contain Admin,
 * and that check is cosmetic. It is worth saying plainly, because a rendered
 * button is the thing people mistake for a permission:
 *
 *   - the roles come from the server, but the decision to render is made here,
 *     in code the user is running and can edit;
 *   - anyone can call GET /api/admin/notes directly, and the server answers 403
 *     unless the token carries the Admin role;
 *   - hiding this panel from a non-admin is a courtesy to honest users, not a
 *     control against dishonest ones.
 *
 * If the only thing stopping a request were the absence of a button, there would
 * be nothing stopping it at all.
 */
export default function AdminPanel() {
  const [notes, setNotes] = useState<AdminNote[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    fetchAllNotes()
      .then((page) => !cancelled && setNotes(page.items))
      .catch((failure: Error) => !cancelled && setError(failure.message))

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <section className={styles.panel}>
      <h2 className={styles.panelTitle}>Every note (admin)</h2>

      {error !== null && <p className={styles.error}>{error}</p>}

      {error === null && notes.length === 0 && (
        <p className={styles.empty}>Nobody has written anything yet.</p>
      )}

      {notes.map((note) => (
        <article key={note.id} className={styles.note}>
          <div className={styles.noteHead}>
            <h3 className={styles.noteTitle}>{note.title}</h3>
            <span className={styles.owner}>{note.ownerEmail}</span>
          </div>
          <p className={styles.noteBody}>{note.content}</p>
        </article>
      ))}
    </section>
  )
}
