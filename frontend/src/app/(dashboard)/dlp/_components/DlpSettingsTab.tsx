'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Lock, Save, Shield, ShieldCheck } from 'lucide-react'

import Button from '@/components/ui/Button'
import { toast } from '@/components/ui/Toast'
import { getDlpErrorMessage, updateDlpSettings } from '@/lib/dlp/api'
import type {
  DlpMode,
  DlpStatus,
  DlpTenantSettings,
  DlpTenantSettingsUpdate,
} from '@/lib/dlp/types'

interface Props {
  settings: DlpTenantSettings
  status: DlpStatus
  canManage: boolean
  onUpdated: (settings: DlpTenantSettings) => void
}

function normalizeDomains(value: string): string[] {
  return [...new Set(
    value
      .split(/[\n,]/)
      .map((domain) => domain.trim().toLowerCase().replace(/\.$/, ''))
      .filter(Boolean),
  )].sort()
}

export default function DlpSettingsTab({
  settings,
  status,
  canManage,
  onUpdated,
}: Props) {
  const [enabled, setEnabled] = useState(settings.enabled)
  const [mode, setMode] = useState<DlpMode>(settings.mode)
  const [domainsText, setDomainsText] = useState(settings.domains.join('\n'))
  const [lexiconVersion, setLexiconVersion] = useState(settings.lexicon_version)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setEnabled(settings.enabled)
    setMode(settings.mode)
    setDomainsText(settings.domains.join('\n'))
    setLexiconVersion(settings.lexicon_version)
  }, [settings])

  const domains = useMemo(() => normalizeDomains(domainsText), [domainsText])
  const invalidDomains = domains.filter((domain) => {
    const labels = domain.split('.')
    return (
      domain.includes('@') ||
      domain.includes('/') ||
      /\s/.test(domain) ||
      domain.length > 253 ||
      labels.some(
        (label) =>
          !label ||
          !/^[a-z0-9-]+$/.test(label) ||
          !/[a-z0-9]/.test(label),
      )
    )
  })
  const dirty =
    enabled !== settings.enabled ||
    mode !== settings.mode ||
    JSON.stringify(domains) !== JSON.stringify([...settings.domains].sort()) ||
    lexiconVersion.trim() !== settings.lexicon_version
  const valid =
    invalidDomains.length === 0 &&
    domains.length <= 100 &&
    lexiconVersion.trim().length > 0 &&
    lexiconVersion.trim().length <= 64

  async function save() {
    if (!canManage || !valid) return
    if (
      settings.mode === 'monitor' &&
      mode === 'enforce' &&
      !window.confirm(
        'Switch to enforce mode? Published policy can hold or stop outbound messages.',
      )
    ) {
      return
    }
    const payload: DlpTenantSettingsUpdate = {
      enabled,
      mode,
      domains,
      lexicon_version: lexiconVersion.trim(),
    }
    setSaving(true)
    try {
      const updated = await updateDlpSettings(payload)
      onUpdated(updated)
      toast.success('DLP settings saved.')
    } catch (error) {
      toast.error(getDlpErrorMessage(error, 'Could not save DLP settings.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      {enabled ? (
        <div className="rounded-xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/20">
                <ShieldCheck size={20} className="text-emerald-400" />
              </div>
              <div>
                <h3 className="text-[14px] font-semibold text-emerald-400">
                  DLP Protection Active
                </h3>
                <p className="mt-0.5 text-[11px] text-[#a1a1aa]">
                  {mode === 'enforce' ? 'Enforcing published policy' : 'Monitoring only'}
                  {dirty ? ' · unsaved changes' : ''}
                </p>
              </div>
            </div>
            <button
              type="button"
              disabled={!canManage}
              onClick={() => setEnabled(false)}
              className="rounded px-2 py-1 text-[11px] text-red-400 transition-colors hover:bg-red-500/10 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Disable
            </button>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#3b6ef6]/10">
                <Shield size={20} className="text-[#3b6ef6]" />
              </div>
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--foreground)]">
                  DLP Protection Disabled
                </h3>
                <p className="mt-0.5 text-[11px] text-[#71717a]">
                  Enable to evaluate outbound messages against published policy
                  {dirty ? ' · unsaved changes' : ''}
                </p>
              </div>
            </div>
            <button
              type="button"
              disabled={!canManage}
              onClick={() => setEnabled(true)}
              className="rounded-lg bg-[#3b6ef6] px-3 py-1.5 text-[12px] font-medium text-white hover:bg-[#2d5fe0] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Enable
            </button>
          </div>
        </div>
      )}

      <section className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h3 className="mb-3 text-[13px] font-semibold text-[var(--foreground)]">
          Runtime health
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg bg-black/20 p-3">
            <div className="mb-1 text-[11px] text-[#71717a]">Gateway pipeline</div>
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${
                status.pipeline_enabled ? 'bg-emerald-400' : 'bg-red-400'
              }`} />
              <span className="text-[13px] text-[var(--foreground)]">
                {status.pipeline_enabled ? 'Ready' : 'Disabled'}
              </span>
            </div>
          </div>
          <div className="rounded-lg bg-black/20 p-3">
            <div className="mb-1 text-[11px] text-[#71717a]">Classifier</div>
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${
                status.classifier_url_configured ? 'bg-emerald-400' : 'bg-amber-400'
              }`} />
              <span className="text-[13px] text-[var(--foreground)]">
                {status.classifier_url_configured ? 'Configured' : 'Not configured'}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h2 className="text-[14px] font-semibold text-[var(--foreground)]">
          Enforcement mode
        </h2>
        <p className="mt-1 text-[12px] text-[#71717a]">
          Control whether published policy can hold or stop outbound mail.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {(['monitor', 'enforce'] as DlpMode[]).map((value) => (
            <button
              key={value}
              type="button"
              disabled={!canManage}
              onClick={() => setMode(value)}
              className={`rounded-xl border p-4 text-left transition-colors disabled:cursor-not-allowed ${
                mode === value
                  ? 'border-[#3b6ef6]/50 bg-[#3b6ef6]/10'
                  : 'border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.04]'
              }`}
            >
              <div className="flex items-center gap-2">
                {value === 'monitor' ? (
                  <ShieldCheck size={15} className="text-[#3b6ef6]" />
                ) : (
                  <AlertTriangle size={15} className="text-amber-400" />
                )}
                <span className="text-sm font-medium capitalize text-white">{value}</span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-[#71717a]">
                {value === 'monitor'
                  ? 'Record intended decisions while allowing delivery.'
                  : 'Apply published allow, hold, and stop decisions.'}
              </p>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h2 className="text-[14px] font-semibold text-[var(--foreground)]">
          Internal domains
        </h2>
        <p className="mt-1 text-[12px] text-[#71717a]">
          One domain per line. These determine whether recipients are external.
        </p>
        <textarea
          value={domainsText}
          disabled={!canManage}
          onChange={(event) => setDomainsText(event.target.value)}
          rows={6}
          placeholder={'example.com\nsubsidiary.example'}
          className="mt-4 w-full resize-y rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-sm text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
        />
        {invalidDomains.length > 0 && (
          <p className="mt-2 text-xs text-red-400">
            Invalid domain: {invalidDomains[0]}
          </p>
        )}
        {domains.length > 100 && (
          <p className="mt-2 text-xs text-red-400">Maximum 100 domains.</p>
        )}
      </section>

      <section className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <label className="block min-w-[220px] flex-1">
            <span className="text-[14px] font-semibold text-[var(--foreground)]">
              Lexicon version
            </span>
            <p className="mt-1 text-[12px] text-[#71717a]">
              Tenant confidential-term data used by classification.
            </p>
            <input
              value={lexiconVersion}
              disabled={!canManage}
              maxLength={64}
              onChange={(event) => setLexiconVersion(event.target.value)}
              className="mt-4 w-full max-w-sm rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-sm text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
            />
          </label>
          <div className="rounded-lg bg-black/20 px-4 py-3">
            <p className="text-[11px] text-[#71717a]">Active policy</p>
            <p className="mt-0.5 text-[15px] font-semibold text-white">
              {settings.active_policy_version ?? 'Built-in'}
            </p>
          </div>
        </div>
      </section>

      {!canManage && (
        <div className="flex gap-2 rounded-xl border border-white/[0.06] bg-[#13131a] p-4">
          <Lock size={14} className="mt-0.5 text-[#71717a]" />
          <p className="text-xs leading-relaxed text-[#71717a]">
            Administrator permission is required to change DLP settings.
          </p>
        </div>
      )}

      <div className="flex justify-end">
        <Button
          onClick={save}
          loading={saving}
          disabled={!canManage || !dirty || !valid}
        >
          <Save size={14} />
          Save settings
        </Button>
      </div>
    </div>
  )
}
