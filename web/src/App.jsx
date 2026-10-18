import { useCallback, useEffect, useRef, useState } from 'react'
import './App.css'

// Display only. The browser cannot verify a signature and must not try —
// this exists so you can see what the server put in the token.
function decodeJwt(tok) {
    try {
        const payload = tok.split('.')[1]
        const b64 = payload.replace(/-/g, '+').replace(/_/g, '/')
        const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
        return JSON.parse(atob(padded))
    } catch {
        return null
    }
}

function unixNow() {
    return Math.floor(Date.now() / 1000)
}

export default function App() {
    const [email, setEmail] = useState('dev@example.com')
    const [password, setPassword] = useState('')
    const [accessToken, setAccessToken] = useState(null)
    const [claims, setClaims] = useState(null)
    const [now, setNow] = useState(unixNow)
    const [meResult, setMeResult] = useState(null)
    const [log, setLog] = useState([])

    const addLog = useCallback((line) => {
        setLog((prev) => [
            { at: new Date().toLocaleTimeString(), line },
            ...prev.slice(0, 19),
        ])
    }, [])

    const applyToken = useCallback((tok) => {
        setAccessToken(tok)
        setClaims(decodeJwt(tok))
        setMeResult(null)
    }, [])

    const clearSession = useCallback(() => {
        setAccessToken(null)
        setClaims(null)
        setMeResult(null)
    }, [])

    const login = useCallback(async () => {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password }),
        })
        if (!res.ok) {
            addLog(`login failed: ${res.status} ${(await res.text()).trim()}`)
            return
        }
        const data = await res.json()
        applyToken(data.access_token)
        addLog('logged in; refresh cookie set by the server')
    }, [email, password, addLog, applyToken])

    const refresh = useCallback(
        async (quiet = false) => {
            const res = await fetch('/refresh', {
                method: 'POST',
                credentials: 'include',
            })
            if (!res.ok) {
                if (!quiet) {
                    addLog(`refresh failed: ${res.status} — session is over, log in again`)
                }
                clearSession()
                return false
            }
            const data = await res.json()
            applyToken(data.access_token)
            addLog('refreshed; the server rotated the cookie to a new token')
            return true
        },
        [addLog, applyToken, clearSession],
    )

    const callMe = useCallback(async () => {
        if (!accessToken) return
        const res = await fetch('/me', {
            credentials: 'include',
            headers: { Authorization: `Bearer ${accessToken}` },
        })
        if (!res.ok) {
            setMeResult({ ok: false, text: `${res.status} ${(await res.text()).trim()}` })
            addLog(`/me rejected: ${res.status}`)
            return
        }
        const data = await res.json()
        setMeResult({ ok: true, text: JSON.stringify(data) })
        addLog('/me accepted the access token')
    }, [accessToken, addLog])

    const logout = useCallback(async () => {
        await fetch('/logout', { method: 'POST', credentials: 'include' })
        clearSession()
        addLog('logged out; the whole token family was revoked')
    }, [addLog, clearSession])

    // On load the access token is gone (it lived in memory) but the cookie
    // survived, so the app silently re-authenticates. StrictMode runs effects
    // twice in dev, and a second /refresh with the pre-rotation cookie looks
    // exactly like a replay — which would revoke the family. The ref stops it.
    const didInit = useRef(false)
    useEffect(() => {
        if (didInit.current) return
        didInit.current = true
        refresh(true)
    }, [refresh])

    // The only external system here is the clock. Everything else is derived
    // during render, so there is no setState inside an effect.
    useEffect(() => {
        const id = setInterval(() => setNow(unixNow()), 1000)
        return () => clearInterval(id)
    }, [])

    const secondsLeft = claims?.exp ? claims.exp - now : null
    const expired = secondsLeft !== null && secondsLeft <= 0

    return (
        <div className="app">
            <header>
                <h1>JWT auth</h1>
                <p className="sub">
                    Short-lived access token in memory. Long-lived refresh token in an
                    HttpOnly cookie, rotated on every use.
                </p>
            </header>

            {!accessToken ? (
                <section className="card">
                    <h2>Log in</h2>
                    <label>
                        Email
                        <input
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            autoComplete="username"
                        />
                    </label>
                    <label>
                        Password
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && login()}
                            autoComplete="current-password"
                        />
                    </label>
                    <button onClick={login} disabled={!password}>
                        Log in
                    </button>
                </section>
            ) : (
                <>
                    <section className="card">
                        <h2>Access token</h2>
                        <div className={`countdown ${expired ? 'dead' : ''}`}>
                            {expired ? 'expired' : `expires in ${secondsLeft}s`}
                        </div>
                        <pre className="token">{accessToken}</pre>
                        <h3>Decoded payload</h3>
                        <pre className="claims">{JSON.stringify(claims, null, 2)}</pre>
                        <p className="note">
                            Not verified here. The browser decodes the payload for display;
                            only the server checks the signature.
                        </p>
                    </section>

                    <section className="card">
                        <h2>Refresh token</h2>
                        <p className="note">
                            <code>document.cookie</code> reads:{' '}
                            <code>{document.cookie || '(nothing)'}</code>
                        </p>
                        <p className="note">
                            The cookie is there — the browser sends it on every request to
                            this origin — but <code>HttpOnly</code> means JavaScript cannot
                            read it. That is the point: an XSS can steal the short-lived
                            access token and still cannot renew it.
                        </p>
                    </section>

                    <section className="card actions">
                        <button onClick={callMe}>GET /me</button>
                        <button onClick={() => refresh()}>POST /refresh</button>
                        <button onClick={logout} className="danger">
                            POST /logout
                        </button>
                    </section>

                    {meResult && (
                        <section className={`card result ${meResult.ok ? 'ok' : 'bad'}`}>
                            <h2>/me</h2>
                            <pre>{meResult.text}</pre>
                            {!meResult.ok && (
                                <p className="note">
                                    Wait for the countdown to hit zero, call /me, then refresh and
                                    call it again.
                                </p>
                            )}
                        </section>
                    )}
                </>
            )}

            <section className="card">
                <h2>Log</h2>
                {log.length === 0 ? (
                    <p className="note">Nothing yet.</p>
                ) : (
                    <ul className="log">
                        {log.map((entry, i) => (
                            <li key={i}>
                                <span className="at">{entry.at}</span>
                                {entry.line}
                            </li>
                        ))}
                    </ul>
                )}
            </section>
        </div>
    )
}