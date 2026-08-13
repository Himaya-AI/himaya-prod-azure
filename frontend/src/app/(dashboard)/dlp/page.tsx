'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  BarChart3,
  FileText,
  Inbox,
  Lock,
  Mail,
  RefreshCw,
  Settings,
  Shield,
} from 'lucide-react'

import DlpMessagesTab from './_components/DlpMessagesTab'
import DlpOverviewTab from './_components/DlpOverviewTab'
import DlpPolicyTab from './_components/DlpPolicyTab'
import DlpSettingsTab from './_components/DlpSettingsTab'
import {
  getActiveDlpPolicy,
  getDlpErrorMessage,
  getDlpPolicyDraft,
  getDlpSettings,
  getDlpStatus,
  listDlpMessages,
} from '@/lib/dlp/api'
import type {
  DlpMessageSummary,
  DlpStatus,
  DlpTenantSettings,
  PolicyVersion,
} from '@/lib/dlp/types'
import { getUser } from '@/lib/auth'

type Tab = 'overview' | 'policy' | 'queue' | 'messages' | 'settings'

const TABS: Array<{ key: Tab; label: string; icon: typeof BarChart3 }> = [
  { key: 'overview', label: 'Overview', icon: BarChart3 },
  { key: 'policy', label: 'Policy', icon: FileText },
  { key: 'queue', label: 'Queue', icon: Inbox },
  { key: 'messages', label: 'Messages', icon: Mail },
  { key: 'settings', label: 'Settings', icon: Settings },
]

function UpgradePrompt() {
  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center gap-6 p-6">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[#3b6ef6]/10">
        <Lock size={28} className="text-[#3b6ef6]" />
      </div>
      <div className="max-w-md text-center">
        <h1 className="mb-2 text-xl font-semibold text-[var(--foreground)]">
          Data Loss Prevention — Enterprise Feature
        </h1>
        <p className="text-[14px] leading-relaxed text-[#71717a]">
          Upgrade to configure policy enforcement, monitor outbound messages,
          and review held mail.
        </p>
      </div>
      <a
        href="mailto:sales@himaya.ai?subject=Enterprise Upgrade — DLP"
        className="rounded-lg bg-[#3b6ef6] px-6 py-2.5 text-[14px] font-medium text-white transition-colors hover:bg-[#2d5fe0]"
      >
        Contact Sales to Upgrade
      </a>
    </div>
  )
}

function LoadingPage() {
  return (
    <div className="space-y-6">
      <div className="h-8 w-56 animate-pulse rounded-lg bg-white/[0.04]" />
      <div className="h-11 w-[28rem] max-w-full animate-pulse rounded-xl bg-white/[0.04]" />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="h-32 animate-pulse rounded-xl bg-white/[0.03]" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="h-64 animate-pulse rounded-xl bg-white/[0.03]" />
        <div className="h-64 animate-pulse rounded-xl bg-white/[0.03]" />
      </div>
    </div>
  )
}

export default function DlpPage() {
  const user = getUser()
  const isEnterprise = ['enterprise', 'enterprise trial'].includes(
    (user?.tier ?? '').toLowerCase(),
  )
  const canManage = ['admin', 'superadmin', 'super_admin'].includes(
    String(user?.role ?? '').toLowerCase(),
  )

  const [tab, setTab] = useState<Tab>('overview')
  const [status, setStatus] = useState<DlpStatus | null>(null)
  const [settings, setSettings] = useState<DlpTenantSettings | null>(null)
  const [activePolicy, setActivePolicy] = useState<PolicyVersion | null>(null)
  const [draftPolicy, setDraftPolicy] = useState<PolicyVersion | null>(null)
  const [recentMessages, setRecentMessages] = useState<DlpMessageSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadPage = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    setError(null)
    try {
      const [
        nextStatus,
        nextSettings,
        nextActivePolicy,
        nextDraftPolicy,
        nextMessages,
      ] = await Promise.all([
        getDlpStatus(),
        getDlpSettings(),
        getActiveDlpPolicy(),
        getDlpPolicyDraft(),
        listDlpMessages({ limit: 10 }),
      ])
      setStatus(nextStatus)
      setSettings(nextSettings)
      setActivePolicy(nextActivePolicy)
      setDraftPolicy(nextDraftPolicy)
      setRecentMessages(nextMessages.items)
    } catch (requestError) {
      setError(getDlpErrorMessage(requestError, 'Could not load DLP.'))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  const reloadPolicies = useCallback(async () => {
    try {
      const [nextActive, nextDraft, nextSettings] = await Promise.all([
        getActiveDlpPolicy(),
        getDlpPolicyDraft(),
        getDlpSettings(),
      ])
      setActivePolicy(nextActive)
      setDraftPolicy(nextDraft)
      setSettings(nextSettings)
    } catch (requestError) {
      setError(getDlpErrorMessage(requestError, 'Could not refresh DLP policy.'))
    }
  }, [])

  useEffect(() => {
    if (isEnterprise) void loadPage()
    else setLoading(false)
  }, [isEnterprise, loadPage])

  if (!isEnterprise) return <UpgradePrompt />

  if (loading) return <LoadingPage />

  if (error || !status || !settings || !activePolicy) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-500/10">
          <Shield size={21} className="text-red-400" />
        </div>
        <div>
          <h1 className="text-base font-medium text-white">DLP is unavailable</h1>
          <p className="mt-1 max-w-lg text-sm text-[#71717a]">
            {error ?? 'The DLP control plane returned an incomplete response.'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadPage()}
          className="inline-flex items-center gap-2 rounded-lg border border-white/[0.08] px-4 py-2 text-[13px] text-white hover:bg-white/[0.04]"
        >
          <RefreshCw size={14} /> Retry
        </button>
      </div>
    )
  }

  return (
    <div className="min-h-screen">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">
          Data Loss Prevention
        </h1>
        <button
          type="button"
          title="Refresh"
          aria-label="Refresh"
          disabled={refreshing}
          onClick={() => void loadPage(true)}
          className="rounded-lg border border-white/[0.08] p-2 text-[#71717a] transition-colors hover:bg-white/[0.04] hover:text-white disabled:opacity-50"
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : undefined} />
        </button>
      </div>

      <div
        role="tablist"
        aria-label="DLP sections"
        className="mb-5 flex w-fit max-w-full items-center gap-1 overflow-x-auto rounded-xl border border-white/[0.06] bg-[#13131a] p-1"
      >
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-4 py-2 text-[13px] font-medium transition-all ${
              tab === key
                ? 'bg-[#3b6ef6]/15 text-[var(--foreground)]'
                : 'text-[#71717a] hover:bg-white/[0.04] hover:text-[var(--foreground)]'
            }`}
          >
            <Icon size={13} className={tab === key ? 'text-[#3b6ef6]' : 'text-current'} />
            {label}
            {key === 'queue' && (status.reviewable_count ?? 0) > 0 && (
              <span
                title="Held messages awaiting review"
                className="rounded-full border border-orange-500/30 bg-orange-500/20 px-1.5 py-0.5 text-[10px] font-bold text-orange-400"
              >
                {status.reviewable_count}
              </span>
            )}
          </button>
        ))}
      </div>

      <div role="tabpanel">
        {tab === 'overview' && (
          <DlpOverviewTab
            status={status}
            settings={settings}
            activePolicy={activePolicy}
            recentMessages={recentMessages}
          />
        )}
        {tab === 'policy' && (
          <DlpPolicyTab
            activePolicy={activePolicy}
            draftPolicy={draftPolicy}
            canManage={canManage}
            onChanged={reloadPolicies}
          />
        )}
        {tab === 'queue' && (
          <DlpMessagesTab
            key="queue"
            canManage={canManage}
            defaultFilter="reviewable"
            variant="queue"
          />
        )}
        {tab === 'messages' && (
          <DlpMessagesTab
            key="messages"
            canManage={canManage}
            defaultFilter=""
            variant="messages"
          />
        )}
        {tab === 'settings' && (
          <DlpSettingsTab
            settings={settings}
            status={status}
            canManage={canManage}
            onUpdated={setSettings}
          />
        )}
      </div>
    </div>
  )
}
