// Le jeton d'accès reste en mémoire (jamais dans localStorage) : une XSS ne peut pas le voler durablement.
let accessToken = null;

export function setToken(token) {
  accessToken = token;
}

export async function api(path, { method = "GET", body, headers = {} } = {}) {
  const resp = await fetch(`/api${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = resp.status === 204 ? null : await resp.json().catch(() => null);
  if (!resp.ok) {
    const detail = Array.isArray(data?.detail) ? data.detail.map((d) => d.msg).join(", ") : data?.detail;
    throw new Error(detail || `Erreur ${resp.status}`);
  }
  return data;
}

export const euros = (cents) =>
  (cents / 100).toLocaleString("fr-FR", { style: "currency", currency: "EUR" });
