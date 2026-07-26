'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Lock, Save, ShieldCheck } from 'lucide-react'

import Button from '@/components/ui/Button'
import { toast } from '@/components/ui/Toast'
import { getDlpErrorMessage, updateDlpSettings } from '@/lib/dlp/api'
import type {
  DlpMode,
  DlpTenantSettings,
  DlpTenantSettingsUpdate,
} from '@/lib/dlp/types'

interface Props {
  settings: DlpTenantSettings
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
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="space-y-5">
        <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-5">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <h2 className="text-sm font-medium text-[var(--foreground)]">
                Tenant protection
              </h2>
              <p className="mt-1 text-xs text-[#71717a]">
                Control whether the v2 worker evaluates this tenant’s messages.
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={enabled}
              disabled={!canManage}
              onClick={() => setEnabled((value) => !value)}
              className={`relative h-6 w-11 rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                enabled ? 'bg-[#3b6ef6]' : 'bg-white/10'
              }`}
            >
              <span
                className={`absolute top-1 h-4 w-4 rounded-full bg-white transition-transform ${
                  enabled ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>

          <label className="mb-2 block text-xs font-medium text-[#a1a1aa]">
            Enforcement mode
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
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

        <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-5">
          <h2 className="text-sm font-medium text-[var(--foreground)]">
            Internal domains
          </h2>
          <p className="mt-1 text-xs text-[#71717a]">
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

        <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-5">
          <label className="block text-sm font-medium text-[var(--foreground)]">
            Lexicon version
          </label>
          <p className="mt-1 text-xs text-[#71717a]">
            Version of tenant confidential-term data used by classification.
          </p>
          <input
            value={lexiconVersion}
            disabled={!canManage}
            maxLength={64}
            onChange={(event) => setLexiconVersion(event.target.value)}
            className="mt-4 w-full max-w-sm rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-sm text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
          />
        </section>

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

      <aside className="space-y-4">
        <div className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
          <p className="text-xs text-[#71717a]">Active policy version</p>
          <p className="mt-1 text-lg font-semibold text-white">
            {settings.active_policy_version ?? 'Built-in'}
          </p>
        </div>
        {!canManage && (
          <div className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
            <div className="flex gap-2">
              <Lock size={14} className="mt-0.5 text-[#71717a]" />
              <p className="text-xs leading-relaxed text-[#71717a]">
                Administrator permission is required to change DLP settings.
              </p>
            </div>
          </div>
        )}
      </aside>
    </div>
  )
}
