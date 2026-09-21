const BASE_URL = import.meta.env.VITE_API_URL || '/api'
const API_KEY = import.meta.env.VITE_API_KEY || ''

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
    ...(options.headers as Record<string, string> || {}),
  }

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers })

  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status}: ${body}`)
  }

  // Guard against empty bodies (e.g. 204 responses), which res.json() rejects.
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

export { BASE_URL, API_KEY }

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}
