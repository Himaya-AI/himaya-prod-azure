'use client'
import { useEffect, useState } from 'react'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import { Badge } from '@/components/ui/Badge'
import Button from '@/components/ui/Button'
import Input from '@/components/ui/Input'
import { Modal } from '@/components/ui/Modal'
import api from '@/lib/api'
import { getUser } from '@/lib/auth'
import type { User } from '@/lib/types'
import { t } from '@/lib/i18n'
import { useLang } from '@/lib/LangContext'
import { useTheme } from '@/contexts/ThemeContext'
import { Building2, Users, Bell, CheckCircle2, AlertTriangle, Info, Sun, Moon, Send, ShieldCheck, Clock } from 'lucide-react'

const TABS = ['Organization', 'Users', 'Alerts', 'Workspace Security'] as const
type Tab = typeof TABS[number]

const TabIcon: Record<Tab, React.ReactNode> = {
  Organization: <Building2 size={14} />,
  Users: <Users size={14} />,
  Alerts: <Bell size={14} />,
  'Workspace Security': <ShieldCheck size={14} />,
}

interface AlertPrefs {
  critical_threat: boolean
  daily_digest: boolean
  weekly_digest: boolean
  // Workspace-security specific toggles (Adnan 2026-06-17)
  saas_public_share?: boolean
  saas_external_share?: boolean
  saas_dlp_match?: boolean
  saas_posture_drift?: boolean
  cspm_critical?: boolean
  cspm_high?: boolean
  github_secret?: boolean
  github_branch_protection?: boolean
  // Added 2026-06-23 (Adnan): sensitive-upload / cross-region / malware
  // toggles. The backend respects these in the alert sink — see
  // `_should_emit_alert` in saas_security.py.
  saas_sensitive_upload?: boolean
  saas_cross_region_access?: boolean
  saas_malware_upload?: boolean
  saas_ransomware_indicator?: boolean
}

const DEFAULT_ALERT_PREFS: AlertPrefs = {
  critical_threat: true,
  daily_digest: true,
  weekly_digest: true,
  saas_public_share: true,
  saas_external_share: true,
  saas_dlp_match: true,
  saas_posture_drift: true,
  cspm_critical: true,
  cspm_high: true,
  github_secret: true,
  github_branch_protection: true,
  saas_sensitive_upload: true,
  saas_cross_region_access: true,
  saas_malware_upload: true,
  saas_ransomware_indicator: true,
}

interface SecuritySettings {
  session_timeout_minutes: number
}
const DEFAULT_SECURITY_SETTINGS: SecuritySettings = {
  // 2026-06-17: Adnan asked the platform to auto-logout after 2h
  // (was 1h) and be configurable from settings.
  session_timeout_minutes: 120,
}

export default function SettingsPage() {
  const { lang, isRtl, setLang } = useLang()
  const { theme, setTheme } = useTheme()
  const [tab, setTab] = useState<Tab>('Organization')
  const [users, setUsers] = useState<User[]>([])
  const [loadingUsers, setLoadingUsers] = useState(false)
  const [inviteOpen, setInviteOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('analyst')
  const [roleUpdating, setRoleUpdating] = useState<string | null>(null)
  const [inviting, setInviting] = useState(false)
  const [mfaEnforced, setMfaEnforced] = useState(false)
  const [orgName, setOrgName] = useState('')
  const [savingOrg, setSavingOrg] = useState(false)
  const [orgSaveSuccess, setOrgSaveSuccess] = useState(false)
  const [alertPrefs, setAlertPrefs] = useState<AlertPrefs>(DEFAULT_ALERT_PREFS)
  const [loadingAlerts, setLoadingAlerts] = useState(false)
  const [savingAlerts, setSavingAlerts] = useState(false)
  const [alertSaveSuccess, setAlertSaveSuccess] = useState(false)
  const [alertSaveError, setAlertSaveError] = useState('')
  const [testingDigest, setTestingDigest] = useState(false)
  const [digestTestMsg, setDigestTestMsg] = useState('')
  const [removingUser, setRemovingUser] = useState<string | null>(null)
  const [confirmRemoveUser, setConfirmRemoveUser] = useState<User | null>(null)
  const [securitySettings, setSecuritySettings] = useState<SecuritySettings>(DEFAULT_SECURITY_SETTINGS)
  const [savingSecurity, setSavingSecurity] = useState(false)
  const [securitySaveSuccess, setSecuritySaveSuccess] = useState(false)

  const currentUser = getUser()
  const isAdmin = currentUser?.role === 'admin'

  // Load org settings on mount
  useEffect(() => {
    api.get('/api/settings/org')
      .then(r => {
        if (r.data?.name) setOrgName(r.data.name)
        if (r.data?.mfa_enforced != null) setMfaEnforced(r.data.mfa_enforced)
      })
      .catch(() => {})
  }, [])

  // Load alert prefs when alerts tab is active
  useEffect(() => {
    if (tab === 'Alerts') {
      setLoadingAlerts(true)
      api.get('/api/settings/alerts')
        .then(r => setAlertPrefs({ ...DEFAULT_ALERT_PREFS, ...r.data }))
        .catch(() => {})
        .finally(() => setLoadingAlerts(false))
    }
    if (tab === 'Workspace Security') {
      api.get('/api/settings/security')
        .then(r => setSecuritySettings({ ...DEFAULT_SECURITY_SETTINGS, ...r.data }))
        .catch(() => {})
    }
  }, [tab])

  const saveSecuritySettings = async (next: Partial<SecuritySettings>) => {
    const updated = { ...securitySettings, ...next }
    setSecuritySettings(updated)
    setSavingSecurity(true)
    setSecuritySaveSuccess(false)
    try {
      await api.patch('/api/settings/security', updated)
      setSecuritySaveSuccess(true)
      setTimeout(() => setSecuritySaveSuccess(false), 2500)
    } catch {
      // revert on failure
      setSecuritySettings(securitySettings)
    } finally {
      setSavingSecurity(false)
    }
  }

  const updateUserRole = async (userId: string, newRole: string) => {
    setRoleUpdating(userId)
    try {
      await api.patch(`/api/settings/users/${userId}`, { role: newRole })
      setUsers(u => u.map(x => x.id === userId ? { ...x, role: newRole as User['role'] } : x))
    } catch { /* silent */ } finally {
      setRoleUpdating(null)
    }
  }

  const removeUser = async (userId: string) => {
    setRemovingUser(userId)
    try {
      await api.delete(`/api/settings/users/${userId}`)
      setUsers(u => u.filter(x => x.id !== userId))
      setConfirmRemoveUser(null)
    } catch { /* silent */ } finally {
      setRemovingUser(null)
    }
  }

  // Load users when users tab is active
  useEffect(() => {
    if (tab === 'Users') {
      setLoadingUsers(true)
      api.get('/api/settings/users')
        .then(r => setUsers(Array.isArray(r.data) ? r.data : []))
        .catch(() => {})
        .finally(() => setLoadingUsers(false))
    }
  }, [tab])

  const saveOrg = async () => {
    setSavingOrg(true)
    setOrgSaveSuccess(false)
    try {
      await api.put('/api/settings/org', { name: orgName, mfa_enforced: mfaEnforced })
      setOrgSaveSuccess(true)
      setTimeout(() => setOrgSaveSuccess(false), 3000)
    } catch {}
    setSavingOrg(false)
  }

  const toggleAlert = async (key: keyof AlertPrefs, value: boolean) => {
    const updated = { ...alertPrefs, [key]: value }
    setAlertPrefs(updated)
    // Auto-save on toggle
    try {
      await api.put('/api/settings/alerts', { [key]: value })
    } catch (e: any) {
      // Revert on error
      setAlertPrefs(alertPrefs)
      setAlertSaveError('Failed to save preference')
      setTimeout(() => setAlertSaveError(''), 3000)
    }
  }

  const invite = async () => {
    if (!inviteEmail) return
    setInviting(true)
    try {
      await api.post('/api/settings/invite', { email: inviteEmail, role: inviteRole })
      setInviteOpen(false)
      setInviteEmail('')
      // Reload users
      const r = await api.get('/api/settings/users')
      setUsers(Array.isArray(r.data) ? r.data : [])
    } catch {}
    setInviting(false)
  }

  const testWeeklyDigest = async () => {
    setTestingDigest(true)
    setDigestTestMsg('')
    try {
      const r = await api.post('/api/settings/test-weekly-digest')
      setDigestTestMsg(r.data?.message || 'Weekly digest sent — check your inbox!')
    } catch {
      setDigestTestMsg('Failed to send test digest')
    } finally {
      setTestingDigest(false)
      setTimeout(() => setDigestTestMsg(''), 6000)
    }
  }

  const testDailyDigest = async () => {
    setTestingDigest(true)
    setDigestTestMsg('')
    try {
      const r = await api.post('/api/settings/test-daily-digest')
      setDigestTestMsg(r.data?.message || 'Daily digest sent — check your inbox!')
    } catch {
      setDigestTestMsg('Failed to send test daily digest')
    } finally {
      setTestingDigest(false)
      setTimeout(() => setDigestTestMsg(''), 6000)
    }
  }

  const alertRows: { key: keyof AlertPrefs; label: string; desc: string }[] = [
    { key: 'critical_threat', label: 'Critical threat detected', desc: 'Immediate email alert when a threat with risk score ≥ 80 is detected' },
    { key: 'daily_digest', label: 'Daily digest', desc: 'Threat summary email delivered at 8:00 AM UTC every day' },
    { key: 'weekly_digest', label: 'Weekly digest', desc: 'Full weekly report every Monday — inboxes affected, threat origins, discovered links' },
    // Workspace Security alert toggles (Adnan 2026-06-17)
    { key: 'saas_public_share', label: 'Public file share detected', desc: 'Alert when a SharePoint / OneDrive / Teams file is shared with anyone-with-the-link or anonymous access' },
    { key: 'saas_external_share', label: 'External sharing with unfamiliar domain', desc: 'Alert when SaaS content is shared with a domain not on the org allowlist' },
    { key: 'saas_dlp_match', label: 'Sensitive data exposure (DLP match)', desc: 'Alert when the Himaya Data Posture agent classifies a SaaS resource as confidential / highly confidential and it is externally accessible' },
    { key: 'saas_sensitive_upload', label: 'Sensitive data uploaded or newly discovered', desc: 'Alert when a confidential / highly-confidential file is uploaded to a connected SaaS or appears in a discovery sweep on AWS / GCP / Azure / Databricks' },
    { key: 'saas_cross_region_access', label: 'Sensitive data accessed from outside its region', desc: 'Alert when a user signs in from a country / region different from where the data resides (e.g. EU customer data accessed from outside the EU)' },
    { key: 'saas_malware_upload', label: 'Malware uploaded to a connected SaaS / cloud', desc: 'Alert when an uploaded file matches a known-bad hash, dangerous extension, or malicious-signature heuristic on SharePoint / OneDrive / Teams / S3' },
    { key: 'saas_ransomware_indicator', label: 'Ransomware indicators on shared / cloud storage', desc: 'Alert on bulk-rename, mass-encryption extension changes (.locked, .encrypted, .crypto, .lockbit…), ransom-note files, or known ransomware-family extensions in a connected store' },
    { key: 'saas_posture_drift', label: 'SaaS posture drift', desc: 'Alert when a previously-passing posture check moves to fail / warning' },
    { key: 'cspm_critical', label: 'CSPM critical finding', desc: 'Alert on any new CRITICAL finding from AWS / GCP / Azure / Oracle / Databricks' },
    { key: 'cspm_high', label: 'CSPM high finding', desc: 'Alert on any new HIGH finding from cloud connectors' },
    { key: 'github_secret', label: 'GitHub secret detected', desc: 'Alert when secret scanning surfaces an exposed credential in a connected GitHub repo' },
    { key: 'github_branch_protection', label: 'GitHub branch protection disabled', desc: 'Alert when the default branch of a connected repo loses branch protection' },
  ]

  return (
    <div className="space-y-5">
      <div className={isRtl ? 'text-right' : ''}>
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">{t(lang, 'settings')}</h1>
      </div>

      {/* Tabs */}
      <div className={`flex gap-0.5 border-b border-white/[0.06] ${isRtl ? 'flex-row-reverse' : ''}`}>
        {TABS.map(tabName => (
          <button
            key={tabName}
            onClick={() => setTab(tabName)}
            className={`flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium border-b-2 transition-all ${
              tab === tabName
                ? 'border-[#3b6ef6] text-white'
                : 'border-transparent text-[#71717a] hover:text-[#a1a1aa]'
            }`}
          >
            {TabIcon[tabName]} {tabName}
          </button>
        ))}
      </div>

      {/* Organization */}
      {tab === 'Organization' && (
        <div className="max-w-2xl space-y-5">
          <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5 space-y-4">
            <h2 className={`text-[13px] font-semibold text-[#a1a1aa] uppercase tracking-wide ${isRtl ? 'text-right' : ''}`}>
              {t(lang, 'orgDetails')}
            </h2>

            <Input
              label="Organization Name"
              value={orgName}
              onChange={e => setOrgName(e.target.value)}
              placeholder="e.g. Himaya Technologies"
            />
            <p className="text-[12px] text-[#52525b] -mt-2">This name appears in the sidebar and all Himaya email alerts sent to your team.</p>

            {/* Language preference */}
            <div className="space-y-1.5">
              <label className={`block text-[13px] font-medium text-[#d4d4d8] ${isRtl ? 'text-right' : ''}`}>
                {t(lang, 'defaultLanguage')}
              </label>
              <div className={`flex gap-2 ${isRtl ? 'flex-row-reverse' : ''}`}>
                {(['en', 'ar'] as const).map(l => (
                  <button
                    key={l}
                    onClick={() => setLang(l as 'en' | 'ar')}
                    className={`px-4 py-2 rounded-lg text-[13px] font-medium transition-all ${
                      lang === l
                        ? 'bg-[#3b6ef6] text-white'
                        : 'bg-[#1e1e24] text-[#71717a] border border-white/[0.08] hover:text-[#a1a1aa]'
                    }`}
                  >
                    {l === 'en' ? 'English' : 'العربية'}
                  </button>
                ))}
              </div>
            </div>

            {/* Dark / Light mode toggle */}
            <div className={`flex items-center justify-between py-1 ${isRtl ? 'flex-row-reverse' : ''}`}>
              <div className={isRtl ? 'text-right' : ''}>
                <div className="text-[13px] font-medium text-[#d4d4d8]">Interface Theme</div>
                <div className="text-[12px] text-[#71717a] mt-0.5">Switch between dark and light mode</div>
              </div>
              <div className="flex items-center gap-1.5 bg-[#1e1e24] rounded-lg p-1 border border-white/[0.08]">
                <button
                  onClick={() => setTheme('dark')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[12px] font-medium transition-all ${
                    theme === 'dark'
                      ? 'bg-[#3b6ef6] text-white'
                      : 'text-[#71717a] hover:text-[#a1a1aa]'
                  }`}
                >
                  <Moon size={12} /> Dark
                </button>
                <button
                  onClick={() => setTheme('light')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[12px] font-medium transition-all ${
                    theme === 'light'
                      ? 'bg-[#3b6ef6] text-white'
                      : 'text-[#71717a] hover:text-[#a1a1aa]'
                  }`}
                >
                  <Sun size={12} /> Light
                </button>
              </div>
            </div>



            {orgSaveSuccess && (
              <div className="flex items-center gap-2 text-[13px] text-emerald-400">
                <CheckCircle2 size={14} /> Organization name saved.
              </div>
            )}

            <Button loading={savingOrg} onClick={saveOrg}>
              {t(lang, 'saveChanges')}
            </Button>
          </div>
        </div>
      )}

      {/* Users */}
      {tab === 'Users' && (
        <div className="space-y-4">
          {/* Info note */}
          <div className="flex items-start gap-3 px-4 py-3 bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl text-[12px] text-[#93b4fd]">
            <Info size={13} className="mt-0.5 flex-shrink-0" />
            <span>This tab shows <strong>portal admin accounts</strong> only — people who can log into Himaya. Monitored employee mailboxes are managed in the <strong>People</strong> tab.</span>
          </div>

          <div className={`flex ${isRtl ? 'justify-start' : 'justify-end'}`}>
            {isAdmin && (
              <Button size="sm" onClick={() => setInviteOpen(true)}>
                {t(lang, 'inviteUser')}
              </Button>
            )}
          </div>

          <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
            <Table>
              <Thead>
                <Tr>
                  <Th>{t(lang, 'name')}</Th>
                  <Th>{t(lang, 'email')}</Th>
                  <Th>{t(lang, 'role')}</Th>
                  <Th>{t(lang, 'status')}</Th>
                  {isAdmin && <Th></Th>}
                </Tr>
              </Thead>
              <Tbody>
                {loadingUsers
                  ? [...Array(3)].map((_, i) => (
                    <Tr key={i}>
                      {[...Array(isAdmin ? 5 : 4)].map((_, j) => (
                        <Td key={j}><div className="h-4 animate-pulse bg-white/[0.05] rounded w-20" /></Td>
                      ))}
                    </Tr>
                  ))
                  : users
                    .filter(u => ['admin', 'analyst', 'viewer'].includes(u.role))
                    .map(u => (
                    <Tr key={u.id}>
                      <Td className="font-medium text-[var(--foreground)]">{u.name ?? u.full_name ?? '—'}</Td>
                      <Td className="text-[13px] text-[var(--muted)]">{u.email}</Td>
                      <Td>
                        {isAdmin && u.id !== currentUser?.id ? (
                          <select
                            value={u.role}
                            disabled={roleUpdating === u.id}
                            onChange={e => updateUserRole(u.id, e.target.value)}
                            className="text-[12px] bg-[var(--card)] border border-[var(--border)] text-[var(--foreground)] rounded-md px-2 py-1 cursor-pointer focus:outline-none focus:ring-1 focus:ring-[#3b6ef6] disabled:opacity-50"
                          >
                            <option value="admin">admin</option>
                            <option value="analyst">analyst</option>
                            <option value="viewer">viewer</option>
                          </select>
                        ) : (
                          <Badge variant="info">{u.role}</Badge>
                        )}
                      </Td>
                      <Td>
                        <Badge variant={u.is_active ? 'success' : 'neutral'}>
                          {u.is_active ? t(lang, 'active') : t(lang, 'inactive')}
                        </Badge>
                      </Td>
                      {isAdmin && (
                        <Td>
                          {u.id !== currentUser?.id && (
                            <button
                              onClick={() => setConfirmRemoveUser(u)}
                              className="text-[11px] text-red-400/70 hover:text-red-400 transition-colors px-2 py-1 rounded hover:bg-red-500/10"
                              title="Remove user"
                            >
                              Remove
                            </button>
                          )}
                        </Td>
                      )}
                    </Tr>
                  ))
                }
                {!loadingUsers && users.filter(u => ['admin', 'analyst', 'viewer'].includes(u.role)).length === 0 && (
                  <Tr>
                    <Td colSpan={isAdmin ? 5 : 4} className={`text-center text-[#71717a] py-10 text-[13px] ${isRtl ? 'text-right px-4' : ''}`}>
                      {t(lang, 'noUsers')}
                    </Td>
                  </Tr>
                )}
              </Tbody>
            </Table>
          </div>

          {isAdmin && (
            <>
            <Modal open={inviteOpen} onClose={() => setInviteOpen(false)} title={t(lang, 'inviteUser')}>
              <div className="space-y-4">
                <Input
                  label={t(lang, 'emailAddress')}
                  type="email"
                  placeholder="colleague@company.com"
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                />
                <div>
                  <label className="block text-[12px] text-[var(--muted)] mb-1.5">Role</label>
                  <select
                    value={inviteRole}
                    onChange={e => setInviteRole(e.target.value)}
                    className="w-full text-[13px] bg-[var(--card)] border border-[var(--border)] text-[var(--foreground)] rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
                  >
                    <option value="analyst">Analyst — can view threats, run reports, receive digests</option>
                    <option value="admin">Admin — full access + manage users + configure integrations</option>
                    <option value="viewer">Viewer — read-only, no digests</option>
                  </select>
                </div>
                <div className="flex gap-2 justify-end pt-1">
                  <Button variant="ghost" onClick={() => setInviteOpen(false)}>{t(lang, 'cancel')}</Button>
                  <Button loading={inviting} onClick={invite}>{t(lang, 'sendInvite')}</Button>
                </div>
              </div>
            </Modal>

            {/* Confirm Remove User Modal */}
            <Modal
              open={!!confirmRemoveUser}
              onClose={() => setConfirmRemoveUser(null)}
              title="Remove User"
            >
              <div className="space-y-4">
                <p className="text-[13px] text-[#a1a1aa]">
                  Are you sure you want to remove <strong className="text-[#e4e4e7]">{confirmRemoveUser?.email}</strong>?
                  They will immediately lose access to the portal.
                </p>
                <div className="flex gap-2 justify-end">
                  <Button variant="ghost" onClick={() => setConfirmRemoveUser(null)}>Cancel</Button>
                  <button
                    onClick={() => confirmRemoveUser && removeUser(confirmRemoveUser.id)}
                    disabled={removingUser === confirmRemoveUser?.id}
                    className="px-3 py-1.5 rounded-lg text-[13px] font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50"
                  >
                    {removingUser === confirmRemoveUser?.id ? 'Removing…' : 'Remove User'}
                  </button>
                </div>
              </div>
            </Modal>
            </>
          )}
        </div>
      )}

      {/* Alerts */}
      {tab === 'Alerts' && (
        <div className="max-w-2xl space-y-4">
          <div className="flex items-start gap-3 px-4 py-3 bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl text-[12px] text-[#93b4fd]">
            <Info size={13} className="mt-0.5 flex-shrink-0" />
            <span>Alert emails are sent from <strong>noreply@notify.himaya.ai</strong> with Himaya branding. Make sure your inbox isn't filtering them. Changes save automatically.</span>
          </div>

          {alertSaveError && (
            <div className="flex items-center gap-2 text-[13px] text-red-400">
              <AlertTriangle size={14} /> {alertSaveError}
            </div>
          )}

          <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5 space-y-1">
            <h2 className={`text-[13px] font-semibold text-[#a1a1aa] uppercase tracking-wide mb-4 ${isRtl ? 'text-right' : ''}`}>
              {t(lang, 'alertPreferences')}
            </h2>
            {loadingAlerts ? (
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => <div key={i} className="h-10 animate-pulse bg-white/[0.04] rounded" />)}
              </div>
            ) : (
              alertRows.map(({ key, label, desc }) => (
                <div key={key} className={`flex items-center justify-between py-3 border-b border-white/[0.05] last:border-0 ${isRtl ? 'flex-row-reverse' : ''}`}>
                  <div className={isRtl ? 'text-right' : ''}>
                    <div className="text-[13px] font-medium text-[#d4d4d8]">{label}</div>
                    <div className="text-[12px] text-[#71717a] mt-0.5">{desc}</div>
                  </div>
                  <button
                    onClick={() => toggleAlert(key, !alertPrefs[key])}
                    className={`relative inline-flex h-5 w-9 rounded-full transition-colors flex-shrink-0 ${alertPrefs[key] ? 'bg-[#3b6ef6]' : 'bg-[#3f3f46]'}`}
                  >
                    <span className={`inline-block w-4 h-4 m-0.5 bg-white rounded-full transition-transform ${alertPrefs[key] ? 'translate-x-4' : 'translate-x-0'}`} />
                  </button>
                </div>
              ))
            )}
          </div>

          {/* Test digest buttons */}
          {isAdmin && (
            <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 space-y-3">
              <div className="text-[11px] text-[var(--muted)] uppercase tracking-wide font-semibold">Test Digests</div>
              <div className={`flex items-center justify-between ${isRtl ? 'flex-row-reverse' : ''}`}>
                <div className={isRtl ? 'text-right' : ''}>
                  <div className="text-[13px] font-medium text-[var(--foreground)]">Weekly Digest</div>
                  <div className="text-[12px] text-[var(--muted)] mt-0.5">Send this week's full report to all admins now</div>
                </div>
                <Button size="sm" variant="ghost" loading={testingDigest} onClick={testWeeklyDigest}>
                  <Send size={12} className="mr-1.5" /> Send Test
                </Button>
              </div>
              <div className={`flex items-center justify-between border-t border-[var(--border)] pt-3 ${isRtl ? 'flex-row-reverse' : ''}`}>
                <div className={isRtl ? 'text-right' : ''}>
                  <div className="text-[13px] font-medium text-[var(--foreground)]">Daily Digest</div>
                  <div className="text-[12px] text-[var(--muted)] mt-0.5">Send today's threat summary to all admins now</div>
                </div>
                <Button size="sm" variant="ghost" loading={testingDigest} onClick={testDailyDigest}>
                  <Send size={12} className="mr-1.5" /> Send Test
                </Button>
              </div>
              {digestTestMsg && (
                <div className="flex items-center gap-2 text-[13px] text-emerald-400 mt-2">
                  <CheckCircle2 size={14} /> {digestTestMsg}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {tab === 'Workspace Security' && (
        <div className="space-y-5">
          {/* Session Timeout */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Clock size={14} className="text-[#3b6ef6]" />
              <div className="text-[11px] text-[var(--muted)] uppercase tracking-wide font-semibold">Session</div>
              {securitySaveSuccess && (
                <span className="flex items-center gap-1 text-[11px] text-emerald-400 ml-auto">
                  <CheckCircle2 size={12} /> Saved
                </span>
              )}
            </div>
            <div>
              <label className="block text-[13px] font-medium text-[var(--foreground)] mb-1">
                Automatic logout
              </label>
              <p className="text-[12px] text-[var(--muted)] mb-3">
                Sign users out after this much idle time. Default is 2 hours; the platform used to log you out after 1 hour.
              </p>
              <div className="flex items-center gap-3">
                <select
                  value={securitySettings.session_timeout_minutes}
                  disabled={!isAdmin || savingSecurity}
                  onChange={e => saveSecuritySettings({ session_timeout_minutes: Number(e.target.value) })}
                  className="bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] text-[13px] rounded-lg px-3 py-2 outline-none focus:border-[#3b6ef6]"
                >
                  <option value={30}>30 minutes</option>
                  <option value={60}>1 hour</option>
                  <option value={120}>2 hours (default)</option>
                  <option value={240}>4 hours</option>
                  <option value={480}>8 hours</option>
                  <option value={1440}>24 hours</option>
                </select>
                {!isAdmin && (
                  <span className="text-[11px] text-[var(--muted)]">Admin only</span>
                )}
              </div>
            </div>
          </div>

          {/* Pointer to the alert toggles in the Alerts tab */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-2">
              <Bell size={14} className="text-[#3b6ef6]" />
              <div className="text-[11px] text-[var(--muted)] uppercase tracking-wide font-semibold">Workspace Security Alerts</div>
            </div>
            <p className="text-[12px] text-[var(--muted)] mb-3">
              Toggle which Workspace Security alerts you want to receive (public shares, DLP matches, posture drift, CSPM findings, GitHub secrets, etc).
            </p>
            <Button size="sm" variant="ghost" onClick={() => setTab('Alerts')}>
              Open Alerts settings →
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
