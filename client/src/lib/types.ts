/** The OAuth2 token response, RFC 6749 section 5.1 - which is why these are snake_case. */
export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token: string
}

export interface Me {
  id: string
  email: string
  displayName: string | null
  roles: string[]
}

export interface Note {
  id: string
  title: string
  content: string
  createdAt: string
  updatedAt: string
}

export interface Paged<T> {
  items: T[]
  page: number
  pageSize: number
  totalCount: number
  totalPages: number
}

/** RFC 9457. The API answers every failure in this shape, so the client parses one. */
export interface ProblemDetails {
  title?: string
  detail?: string
  status?: number
  errors?: Record<string, string[]>
}

/**
 * The admin view of a note. Its own type rather than an optional owner field on
 * Note, mirroring the server: the only thing keeping owner identities out of
 * ordinary responses should not be remembering to null a field.
 */
export interface AdminNote extends Note {
  ownerId: string
  ownerEmail: string
}
