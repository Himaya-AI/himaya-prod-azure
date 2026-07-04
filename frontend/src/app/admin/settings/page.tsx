'use client'
import { Settings } from 'lucide-react'

export default function AdminSettings() {
  return (
    <div className="space-y-6">
      <h1 className="text-white text-2xl font-bold">Settings</h1>
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 max-w-lg">
        <div className="flex items-center gap-3 mb-4">
          <Settings className="w-5 h-5 text-[var(--accent)]" />
          <h2 className="text-white font-semibold">Admin Configuration</h2>
        </div>
        <div className="space-y-3 text-sm">
          {[
            ['API Endpoint', process.env.NEXT_PUBLIC_API_URL || 'https://app.himaya.ai'],
            ['Admin Email', 'admin@himayahelios.io'],
            ['Default Billing Rate', '$8.00/mailbox/month'],
            ['Default Mailbox Limit', '100'],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between py-2 border-b border-gray-800">
              <span className="text-gray-400">{k}</span>
              <span className="text-gray-200 font-mono">{v}</span>
            </div>
          ))}
        </div>
        <p className="text-gray-600 text-xs mt-4">Configuration is managed via environment variables in production.</p>
      </div>
    </div>
  )
}
