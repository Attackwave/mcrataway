import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge, VerdictBadge, ConfidenceMeter } from '@/components/Badges'

describe('SeverityBadge', () => {
  it('renders with CRITICAL severity', () => {
    render(<SeverityBadge severity="CRITICAL" />)
    const badge = screen.getByText('CRITICAL')
    expect(badge).toBeInTheDocument()
    expect(badge.className).toContain('text-xs')
  })

  it('renders with HIGH severity', () => {
    render(<SeverityBadge severity="HIGH" />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('renders with MEDIUM severity', () => {
    render(<SeverityBadge severity="MEDIUM" />)
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
  })

  it('renders with LOW severity', () => {
    render(<SeverityBadge severity="LOW" />)
    expect(screen.getByText('LOW')).toBeInTheDocument()
  })
})

describe('VerdictBadge', () => {
  it('renders MALICIOUS verdict', () => {
    render(<VerdictBadge verdict="MALICIOUS" />)
    const badge = screen.getByText('MALICIOUS')
    expect(badge).toBeInTheDocument()
  })

  it('renders CLEAN verdict', () => {
    render(<VerdictBadge verdict="CLEAN" />)
    expect(screen.getByText('CLEAN')).toBeInTheDocument()
  })

  it('renders SUSPICIOUS verdict', () => {
    render(<VerdictBadge verdict="SUSPICIOUS" />)
    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument()
  })
})

describe('ConfidenceMeter', () => {
  it('renders with 0.8 confidence', () => {
    render(<ConfidenceMeter confidence={0.8} />)
    expect(screen.getByText('80%')).toBeInTheDocument()
  })

  it('renders with 0.5 confidence', () => {
    render(<ConfidenceMeter confidence={0.5} />)
    expect(screen.getByText('50%')).toBeInTheDocument()
  })
})
