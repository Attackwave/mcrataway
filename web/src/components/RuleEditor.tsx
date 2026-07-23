import { SeverityBadge } from './Badges'

interface Rule {
  id: string
  family: string
  severity: string
  description: string
}

interface RulePack {
  pack_id: string
  rule_count: number
  rules: Rule[]
}

interface RuleEditorProps {
  packs: RulePack[]
  isLoading: boolean
}

export function RuleEditor({ packs, isLoading }: RuleEditorProps) {
  if (isLoading) {
    return <p className="text-[var(--text-secondary)]">Loading rules...</p>
  }

  if (packs.length === 0) {
    return <p className="text-[var(--text-secondary)]">No rule packs loaded</p>
  }

  return (
    <div className="grid gap-4">
      {packs.map((pack) => (
        <div
          key={pack.pack_id}
          className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium">{pack.pack_id}</h3>
            <span className="text-sm text-[var(--text-secondary)]">
              {pack.rule_count} rule(s)
            </span>
          </div>

          <div className="space-y-2">
            {pack.rules.map((rule) => (
              <div key={rule.id} className="bg-[var(--bg-primary)] rounded p-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={rule.severity} />
                  <span className="text-xs font-mono text-[var(--accent)]">{rule.id}</span>
                  {rule.family && (
                    <span className="text-xs text-[var(--text-secondary)]">
                      family: {rule.family}
                    </span>
                  )}
                </div>
                <p className="text-sm">{rule.description}</p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
