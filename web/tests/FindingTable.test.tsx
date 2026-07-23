import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingTable } from '@/components/FindingTable'
import type { Verdict } from '@/api/client'

const mockFindings: Verdict[] = [
  {
    file_path: '/mods/suspicious.jar',
    sha256: 'abc123',
    verdict: 'MALICIOUS',
    confidence: 0.95,
    findings: [
      {
        detector_id: 'D01',
        severity: 'CRITICAL',
        description: 'Process execution detected',
        class_name: 'Main',
        method_name: 'run',
        matched_value: 'Runtime.getRuntime().exec',
      },
    ],
  },
  {
    file_path: '/mods/clean.jar',
    sha256: 'def456',
    verdict: 'CLEAN',
    confidence: 0.99,
    findings: [],
  },
]

describe('FindingTable', () => {
  it('renders findings', () => {
    render(<FindingTable findings={mockFindings} />)
    expect(screen.getByText('suspicious.jar')).toBeInTheDocument()
    expect(screen.getByText('clean.jar')).toBeInTheDocument()
  })

  it('shows MALICIOUS badge', () => {
    render(<FindingTable findings={mockFindings} />)
    expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
  })

  it('shows CLEAN badge', () => {
    render(<FindingTable findings={mockFindings} />)
    expect(screen.getAllByText('CLEAN')).toHaveLength(1)
  })

  it('expands finding on click', () => {
    render(<FindingTable findings={mockFindings} />)
    const row = screen.getByText('suspicious.jar').closest('button')
    if (row) {
      fireEvent.click(row)
      expect(screen.getByText('Process execution detected')).toBeInTheDocument()
    }
  })

  it('shows empty state when no findings', () => {
    render(<FindingTable findings={[]} />)
    expect(screen.getByText('No findings to display')).toBeInTheDocument()
  })
})
