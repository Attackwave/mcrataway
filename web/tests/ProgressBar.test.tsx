import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ProgressBar } from '@/components/ProgressBar'

describe('ProgressBar', () => {
  it('renders with 50% progress', () => {
    render(<ProgressBar progress={50} scanned={5} total={10} />)
    expect(screen.getByText('50%')).toBeInTheDocument()
  })

  it('renders with 100% progress', () => {
    render(<ProgressBar progress={100} scanned={10} total={10} />)
    expect(screen.getByText('100%')).toBeInTheDocument()
  })

  it('shows 0% when no progress', () => {
    render(<ProgressBar progress={0} scanned={0} total={10} />)
    expect(screen.getByText('0%')).toBeInTheDocument()
  })

  it('shows file count', () => {
    render(<ProgressBar progress={25} scanned={2} total={8} />)
    expect(screen.getByText('2 / 8 files')).toBeInTheDocument()
  })
})
