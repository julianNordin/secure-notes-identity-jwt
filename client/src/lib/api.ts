import { apiFetch, problemFrom } from './apiClient'
import type { AdminNote, Me, Note, Paged } from './types'

async function json<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(await problemFrom(response))
  }

  return (await response.json()) as T
}

export async function fetchMe(): Promise<Me> {
  return json<Me>(await apiFetch('/api/auth/me'))
}

export async function fetchNotes(search: string): Promise<Paged<Note>> {
  const trimmed = search.trim()
  const query = trimmed === '' ? '' : `?search=${encodeURIComponent(trimmed)}`

  return json<Paged<Note>>(await apiFetch(`/api/notes${query}`))
}

export async function createNote(title: string, content: string): Promise<Note> {
  return json<Note>(
    await apiFetch('/api/notes', { method: 'POST', body: JSON.stringify({ title, content }) }),
  )
}

export async function deleteNote(id: string): Promise<void> {
  const response = await apiFetch(`/api/notes/${id}`, { method: 'DELETE' })

  if (!response.ok) {
    throw new Error(await problemFrom(response))
  }
}

/** Admin only. A non-admin reaching this gets 403 from the server, which is the point. */
export async function fetchAllNotes(): Promise<Paged<AdminNote>> {
  return json<Paged<AdminNote>>(await apiFetch('/api/admin/notes'))
}
