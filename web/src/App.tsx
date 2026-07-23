import { useState } from 'react'
import ScanPage from './pages/ScanPage'
import FindingsPage from './pages/FindingsPage'
import RulesPage from './pages/RulesPage'
import QuarantinePage from './pages/QuarantinePage'
import SettingsPage from './pages/SettingsPage'

type Page = 'scan' | 'findings' | 'rules' | 'quarantine' | 'settings'

const navItems: { id: Page; label: string; icon: string }[] = [
  { id: 'scan', label: 'Scan', icon: '🔍' },
  { id: 'findings', label: 'Findings', icon: '⚠️' },
  { id: 'rules', label: 'Rules', icon: '📋' },
  { id: 'quarantine', label: 'Quarantine', icon: '🔒' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
]

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('scan')

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)]">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <h1 className="text-xl font-bold text-[var(--accent)]">mcrataway</h1>
          <nav className="flex gap-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  currentPage === item.id
                    ? 'bg-[var(--bg-tertiary)] text-[var(--text-primary)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]'
                }`}
              >
                <span className="mr-1.5">{item.icon}</span>
                {item.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        {currentPage === 'scan' && <ScanPage />}
        {currentPage === 'findings' && <FindingsPage />}
        {currentPage === 'rules' && <RulesPage />}
        {currentPage === 'quarantine' && <QuarantinePage />}
        {currentPage === 'settings' && <SettingsPage />}
      </main>

      <footer className="border-t border-[var(--border-color)] py-3 text-center text-sm text-[var(--text-secondary)]">
        mcrataway v0.1.0 — Minecraft mod malware scanner
      </footer>
    </div>
  )
}
