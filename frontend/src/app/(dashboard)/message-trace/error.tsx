'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error('Message Trace Error:', error)
  }, [error])

  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
      <div className="w-16 h-16 rounded-full bg-red-900/20 border border-red-700/30 flex items-center justify-center mb-6">
        <AlertTriangle size={32} className="text-red-400" />
      </div>
      <h2 className="text-xl font-bold text-white mb-2">Something went wrong</h2>
      <p className="text-sm text-slate-400 mb-6 max-w-md">
        An error occurred while loading the message details. This might be a temporary issue.
      </p>
      <button
        onClick={reset}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-[#e94560] hover:bg-[#c73652] text-white transition-colors"
      >
        <RefreshCw size={14} /> Try again
      </button>
      {error.digest && (
        <p className="text-xs text-slate-600 mt-4">Error ID: {error.digest}</p>
      )}
    </div>
  )
}
