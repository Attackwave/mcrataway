import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ScanPage from '@/pages/ScanPage'

vi.mock('@/api/client', () => ({
  getRoots: vi.fn().mockResolvedValue(['/home/user/.minecraft']),
  startScan: vi.fn().mockResolvedValue({
    job_id: 'test-job-123',
    status: 'PENDING',
    progress: 0,
    total_files: 0,
    scanned_files: 0,
  }),
  getJob: vi.fn().mockResolvedValue({
    job_id: 'test-job-123',
    status: 'COMPLETED',
    progress: 100,
    total_files: 10,
    scanned_files: 10,
  }),
  connectJobStream: vi.fn(() => ({
    onmessage: null,
    onerror: null,
    onclose: null,
    close: vi.fn(),
  })),
}))

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>)
}

describe('ScanPage', () => {
  it('renders scan form', () => {
    renderWithClient(<ScanPage />)
    expect(screen.getByText('Scan')).toBeInTheDocument()
    expect(screen.getByText('Start Scan')).toBeInTheDocument()
  })

  it('shows Start Scan button', () => {
    renderWithClient(<ScanPage />)
    expect(screen.getByText('Start Scan')).toBeInTheDocument()
  })

  it('shows discovered roots when loaded', async () => {
    renderWithClient(<ScanPage />)
    await waitFor(() => {
      expect(screen.getByText('/home/user/.minecraft')).toBeInTheDocument()
    })
  })
})
