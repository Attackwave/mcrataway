import { useState } from 'react'
import { setAuthToken, hasAuthToken } from '../api/client'

export default function SettingsPage() {
  const [token, setToken] = useState('')
  const [saved, setSaved] = useState(false)
  const [hasToken, setHasToken] = useState(hasAuthToken())

  const handleSave = () => {
    setAuthToken(token.trim() || null)
    setSaved(true)
    setHasToken(!!token.trim())
    setToken('')
    setTimeout(() => setSaved(false), 2000)
  }

  const handleClear = () => {
    setAuthToken(null)
    setHasToken(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="space-y-6">
      <section className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Settings</h2>

        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium mb-2">Authentication Token</h3>
            <p className="text-sm text-[var(--text-secondary)] mb-3">
              If the mcrataway server was started with a token file
              (<code className="text-xs bg-[var(--bg-tertiary)] px-1 rounded">~/.mcrataway/token</code>),
              enter the token here to authenticate API and WebSocket requests.
            </p>
            <div className="flex gap-2">
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Enter token..."
                className="flex-1 px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border-color)] rounded-md text-sm font-mono focus:outline-none focus:border-[var(--accent)]"
              />
              <button
                onClick={handleSave}
                className="px-4 py-2 rounded-md font-medium text-sm bg-[var(--accent)] text-white hover:opacity-90"
              >
                Save
              </button>
              {hasToken && (
                <button
                  onClick={handleClear}
                  className="px-4 py-2 rounded-md font-medium text-sm bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  Clear
                </button>
              )}
            </div>
            {saved && (
              <p className="text-sm text-[var(--success)] mt-2">Token saved.</p>
            )}
            <p className="text-xs text-[var(--text-secondary)] mt-2">
              Status: {hasToken ? 'Token configured' : 'No token set (open mode)'}
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
