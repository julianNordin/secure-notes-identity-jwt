import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import AdminPanel from '../components/AdminPanel'
import { useAuth } from '../context/auth'
import { createNote, deleteNote, fetchNotes } from '../lib/api'
import type { Note } from '../lib/types'
import styles from './NotesPage.module.css'

export default function NotesPage() {
  const { user, signOut } = useAuth()

  const [notes, setNotes] = useState<Note[]>([])
  const [search, setSearch] = useState('')
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async (term: string) => {
    try {
      setNotes((await fetchNotes(term)).items)
      setError(null)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not load notes.')
    }
  }, [])

  // The first load, guarded against an unmount that beats the response back -
  // the same shape AdminPanel uses. Deliberately not routed through load(),
  // because an effect that fires setState with no way to cancel is how a page
  // that was navigated away from repopulates itself.
  useEffect(() => {
    let cancelled = false

    fetchNotes('')
      .then((page) => !cancelled && setNotes(page.items))
      .catch((failure: Error) => !cancelled && setError(failure.message))

    return () => {
      cancelled = true
    }
  }, [])

  async function submitNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    try {
      await createNote(title, content)
      setTitle('')
      setContent('')
      await load(search)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not save the note.')
    }
  }

  async function remove(id: string) {
    try {
      await deleteNote(id)
      await load(search)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not delete the note.')
    }
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void load(search)
  }

  // The server returns only this user's notes - the filter is a WHERE clause,
  // not a decision made here. The list would be just as correct if this
  // component tried to show somebody else's note: it would simply be empty.
  const isAdmin = user?.roles.includes('Admin') === true

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <strong>SecureNotes</strong>
          <div className={styles.identity}>
            {user?.email}
            {user?.roles.map((role) => (
              <span key={role} className={styles.roles}>
                {role}
              </span>
            ))}
          </div>
        </div>
        <button onClick={() => void signOut()}>Sign out</button>
      </header>

      {error !== null && <p className={styles.error}>{error}</p>}

      <section className={styles.panel}>
        <h2 className={styles.panelTitle}>New note</h2>
        <form onSubmit={submitNote}>
          <div className={styles.row}>
            <input
              type="text"
              value={title}
              placeholder="Title"
              required
              maxLength={200}
              onChange={(event) => setTitle(event.target.value)}
            />
          </div>
          <div className={styles.row}>
            <textarea
              value={content}
              placeholder="Content"
              required
              rows={3}
              onChange={(event) => setContent(event.target.value)}
            />
          </div>
          <button type="submit">Save</button>
        </form>
      </section>

      <section className={styles.panel}>
        <form className={styles.row} onSubmit={submitSearch}>
          <input
            type="search"
            value={search}
            placeholder="Search your notes"
            onChange={(event) => setSearch(event.target.value)}
          />
          <button type="submit">Search</button>
        </form>

        {notes.length === 0 ? (
          <p className={styles.empty}>Nothing here yet.</p>
        ) : (
          notes.map((note) => (
            <article key={note.id} className={styles.note}>
              <div className={styles.noteHead}>
                <h3 className={styles.noteTitle}>{note.title}</h3>
                <button className={styles.delete} onClick={() => void remove(note.id)}>
                  Delete
                </button>
              </div>
              <p className={styles.noteBody}>{note.content}</p>
            </article>
          ))
        )}
      </section>

      {isAdmin && <AdminPanel />}
    </div>
  )
}
