import { useCallback, useEffect, useState } from "react";
import { api, euros, setToken } from "./api.js";

function Field({ label, ...props }) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-slate-600">{label}</span>
      <input
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
        {...props}
      />
    </label>
  );
}

function Button({ children, ...props }) {
  return (
    <button
      className="w-full rounded-lg bg-indigo-600 px-4 py-2 font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
      {...props}
    >
      {children}
    </button>
  );
}

function Login({ onLogged }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "register") await api("/auth/register", { method: "POST", body: { email, password } });
      const tokens = await api("/auth/login", { method: "POST", body: { email, password } });
      setToken(tokens.access_token);
      onLogged(email);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto mt-24 max-w-sm rounded-2xl bg-white p-8 shadow-lg">
      <h1 className="text-2xl font-bold text-slate-900">RESILIENCE Pay</h1>
      <p className="mb-6 text-sm text-slate-500">Plateforme de paiement fictive — démonstrateur</p>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <Field
          label="Mot de passe (12 caractères min.)"
          type="password"
          minLength={12}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {error && <p className="rounded bg-red-50 p-2 text-sm text-red-700">{error}</p>}
        <Button disabled={busy}>{mode === "login" ? "Se connecter" : "Créer mon compte"}</Button>
      </form>
      <button
        className="mt-4 w-full text-sm text-indigo-600 hover:underline"
        onClick={() => setMode(mode === "login" ? "register" : "login")}
      >
        {mode === "login" ? "Pas de compte ? Inscription" : "Déjà inscrit ? Connexion"}
      </button>
    </div>
  );
}

function Transfer({ onDone }) {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [label, setLabel] = useState("");
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const tx = await api("/payments", {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: { to_account: to.trim().toUpperCase(), amount_cents: Math.round(parseFloat(amount) * 100), label },
      });
      setMsg({ ok: true, text: `Virement effectué — ${tx.transaction_id.slice(0, 8)}…` });
      setAmount("");
      setLabel("");
      onDone();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-2xl bg-white p-6 shadow">
      <h2 className="text-lg font-semibold">Nouveau virement</h2>
      <Field label="IBAN destinataire" value={to} onChange={(e) => setTo(e.target.value)} required />
      <Field
        label="Montant (€)"
        type="number"
        step="0.01"
        min="0.01"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        required
      />
      <Field label="Libellé" maxLength={140} value={label} onChange={(e) => setLabel(e.target.value)} />
      {msg && (
        <p className={`rounded p-2 text-sm ${msg.ok ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
          {msg.text}
        </p>
      )}
      <Button disabled={busy}>Envoyer</Button>
    </form>
  );
}

function Dashboard({ email, onLogout }) {
  const [account, setAccount] = useState(null);
  const [txs, setTxs] = useState([]);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [acc, list] = await Promise.all([api("/accounts/me"), api("/payments?limit=15")]);
      setAccount(acc);
      setTxs(list);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className="mx-auto max-w-4xl p-6">
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">RESILIENCE Pay</h1>
        <div className="flex items-center gap-4 text-sm text-slate-600">
          {email}
          <button className="text-indigo-600 hover:underline" onClick={onLogout}>
            Déconnexion
          </button>
        </div>
      </header>
      {error && <p className="mb-4 rounded bg-red-50 p-3 text-red-700">{error}</p>}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-2xl bg-indigo-600 p-6 text-white shadow">
          <p className="text-sm opacity-80">Solde disponible</p>
          <p className="mt-2 text-4xl font-bold">{account ? euros(account.balance_cents) : "—"}</p>
          <p className="mt-4 font-mono text-sm opacity-80">{account?.iban}</p>
        </div>
        <Transfer onDone={refresh} />
      </div>
      <section className="mt-6 rounded-2xl bg-white p-6 shadow">
        <h2 className="mb-3 text-lg font-semibold">Dernières opérations</h2>
        {txs.length === 0 && <p className="text-sm text-slate-500">Aucune opération.</p>}
        <ul className="divide-y divide-slate-100">
          {txs.map((t) => {
            const out = t.from_iban === account?.iban;
            return (
              <li key={t.transaction_id} className="flex justify-between py-2 text-sm">
                <span>
                  <span className="font-medium">{t.label || (out ? `Vers ${t.to_iban}` : `De ${t.from_iban}`)}</span>
                  <span className="ml-2 text-slate-400">{new Date(t.created_at).toLocaleString("fr-FR")}</span>
                </span>
                <span className={out ? "text-red-600" : "text-emerald-600"}>
                  {out ? "−" : "+"}
                  {euros(t.amount_cents)}
                </span>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}

export default function App() {
  const [email, setEmail] = useState(null);
  return email ? (
    <Dashboard
      email={email}
      onLogout={() => {
        setToken(null);
        setEmail(null);
      }}
    />
  ) : (
    <Login onLogged={setEmail} />
  );
}
