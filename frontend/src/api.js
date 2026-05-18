export const API = 'http://localhost:8000';

const TOKEN_KEY = 'sentineliq_token';

export const getToken   = ()  => localStorage.getItem(TOKEN_KEY);
export const setToken   = (t) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = ()  => localStorage.removeItem(TOKEN_KEY);

/** Returns the stored token only if it exists and has not expired. */
export function getValidToken() {
  const token = getToken();
  if (!token) return null;
  try {
    const { exp } = JSON.parse(atob(token.split('.')[1]));
    if (exp * 1000 < Date.now()) {
      clearToken();
      return null;
    }
    return token;
  } catch {
    clearToken();
    return null;
  }
}

/**
 * Authenticated fetch wrapper. Automatically attaches the Bearer token
 * from localStorage and dispatches 'sentineliq:logout' on 401 so the App
 * component transitions to the login screen without a full page reload.
 */
export async function apiFetch(url, opts = {}) {
  const token = getToken();
  const headers = {
    ...(opts.headers || {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(url, { ...opts, headers });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('sentineliq:logout'));
    return res;
  }
  return res;
}

/**
 * POST /api/auth/login with form-encoded credentials.
 * Stores the returned JWT on success.
 */
export async function login(username, password) {
  const body = new URLSearchParams({ username, password });
  const res = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Invalid credentials');
  }
  const data = await res.json();
  setToken(data.access_token);
  return data;
}
