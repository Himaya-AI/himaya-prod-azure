'use client'
import { useEffect, useState, useCallback } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useTheme } from '@/contexts/ThemeContext'
import {
  CheckCircle2, AlertCircle, Unplug, ShieldCheck, Users, Mail, Copy,
  RefreshCw, Zap, Database, Activity, Clock, ArrowRight, ExternalLink,
  Info, AlertTriangle, ChevronDown, ChevronUp, Plug, BarChart2, Fish,
  MousePointerClick, ArrowUpFromLine, ShieldAlert, Brain, Download, Inbox,
} from 'lucide-react'
import Button from '@/components/ui/Button'
import api from '@/lib/api'

interface ProviderStatus {
  connected: boolean
  org_domain?: string
  mailbox_count: number
  status: string
  connected_at: string | null
}
interface Connections {
  m365: ProviderStatus
  google: ProviderStatus
}

// ── Logo Components ────────────────────────────────────────────────────────────
function M365Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none">
      <rect width="32" height="32" rx="8" fill="#0078D4" fillOpacity="0.12" />
      <path d="M7 7h8.5v8.5H7z" fill="#F25022" />
      <path d="M16.5 7H25v8.5h-8.5z" fill="#7FBA00" />
      <path d="M7 16.5h8.5V25H7z" fill="#00A4EF" />
      <path d="M16.5 16.5H25V25h-8.5z" fill="#FFB900" />
    </svg>
  )
}

function GoogleLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none">
      <rect width="32" height="32" rx="8" fill="#4285F4" fillOpacity="0.10" />
      <path d="M24.5 16.2c0-.6-.1-1.2-.2-1.7H16v3.3h4.8c-.2 1.1-.9 2-1.9 2.6v2.2h3.1c1.8-1.7 2.5-4.2 2.5-6.4z" fill="#4285F4" />
      <path d="M16 25c2.4 0 4.4-.8 5.9-2.2l-3.1-2.2c-.8.5-1.8.8-2.8.8-2.2 0-4-1.4-4.7-3.4h-3.2v2.3C9.6 22.9 12.6 25 16 25z" fill="#34A853" />
      <path d="M11.3 18c-.2-.5-.3-1-.3-1.5s.1-1 .3-1.5v-2.3H8.1C7.4 14 7 15 7 16s.4 2 1.1 2.8l3.2-2.3z" fill="#FBBC05" />
      <path d="M16 11.6c1.2 0 2.3.4 3.2 1.2l2.4-2.4C20.4 9.1 18.4 8.2 16 8.2c-3.4 0-6.4 2.1-7.9 5.2l3.2 2.3c.7-2 2.5-4.1 4.7-4.1z" fill="#EA4335" />
    </svg>
  )
}

// ── Stat Card ──────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color, icon }: {
  label: string; value: string; sub?: string | null
  color: string; icon: React.ReactNode
}) {
  return (
    <div className="bg-[#0d1b2e] border border-[#1a2744]/60 rounded-xl p-4 flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="text-slate-500">{icon}</span>
        <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider">{label}</span>
      </div>
      <p className="text-2xl font-bold leading-none" style={{ color }}>{value}</p>
      {sub && <p className="text-[11px] text-slate-600">{sub}</p>}
    </div>
  )
}

// ── Progress Bar ───────────────────────────────────────────────────────────────
function ProgressBar({ pct, label }: { pct: number; label: string }) {
  const color = pct >= 100 ? '#4ade80' : pct > 0 ? '#3b6ef6' : '#3f3f46'
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-[12px]">
        <span className="text-slate-400">{label}</span>
        <span className="font-semibold" style={{ color }}>{pct >= 100 ? '✓ Complete' : `${pct}%`}</span>
      </div>
      <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(100, pct)}%`, backgroundColor: color }}
        />
      </div>
    </div>
  )
}

// ── Provider Card ──────────────────────────────────────────────────────────────
function ProviderCard({
  name, logo, status, onConnect, onDisconnect, connecting, disconnecting,
  requiresAdmin, permissions, setupSteps, accentColor,
}: {
  name: string
  logo: React.ReactNode
  status: ProviderStatus
  onConnect: () => void
  onDisconnect: () => void
  connecting: boolean
  disconnecting: boolean
  requiresAdmin: string
  permissions: { scope: string; label: string; reason: string }[]
  setupSteps?: { title: string; steps: { label: string; value?: string; note?: string }[] }[]
  accentColor: string
}) {
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [showSetup, setShowSetup] = useState(false)

  return (
    <div className={`bg-[#0d1324] border rounded-2xl overflow-hidden transition-all ${
      status.connected
        ? 'border-[#1a3a6a] shadow-lg shadow-black/20'
        : 'border-white/[0.06]'
    }`}>
      {/* Card header */}
      <div className="px-6 py-5 flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          {logo}
          <div>
            <div className="flex items-center gap-2.5">
              <h3 className="text-[15px] font-semibold text-white">{name}</h3>
              {status.connected ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
                  Connected
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-800 text-slate-500 border border-slate-700">
                  Not connected
                </span>
              )}
            </div>
            {status.connected && status.org_domain && (
              <p className="text-[12px] text-slate-400 mt-0.5 font-mono">{status.org_domain}</p>
            )}
          </div>
        </div>

        {/* Connection action */}
        <div className="flex-shrink-0">
          {status.connected ? (
            <div className="flex items-center gap-2">
              {!confirmDisconnect ? (
                <button
                  onClick={() => setConfirmDisconnect(true)}
                  className="flex items-center gap-1.5 text-[12px] text-slate-500 hover:text-red-400 border border-slate-700/60 hover:border-red-700/40 px-3 py-1.5 rounded-lg transition-all"
                >
                  <Unplug size={12} /> Disconnect
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="text-[12px] text-slate-400">Disconnect?</span>
                  <Button size="sm" variant="danger" loading={disconnecting} onClick={onDisconnect}>
                    Yes, remove
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setConfirmDisconnect(false)}>
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <Button
              loading={connecting}
              onClick={onConnect}
              style={{ '--btn-accent': accentColor } as any}
            >
              <ExternalLink size={13} /> Connect {name}
            </Button>
          )}
        </div>
      </div>

      {/* Connected stats */}
      {status.connected && (
        <div className="px-6 pb-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#0a1628] border border-[#1a2744] rounded-xl p-3 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#3b6ef6]/10 flex items-center justify-center flex-shrink-0">
                <Users size={15} className="text-[#3b6ef6]" />
              </div>
              <div>
                <p className="text-[11px] text-slate-500">Mailboxes Monitored</p>
                <p className="text-[15px] font-bold text-white">{status.mailbox_count.toLocaleString()}</p>
              </div>
            </div>
            <div className="bg-[#0a1628] border border-[#1a2744] rounded-xl p-3 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                <Clock size={15} className="text-emerald-400" />
              </div>
              <div>
                <p className="text-[11px] text-slate-500">Connected Since</p>
                <p className="text-[13px] font-semibold text-white">
                  {status.connected_at
                    ? new Date(status.connected_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                    : 'Unknown'}
                </p>
              </div>
            </div>
          </div>

          {/* Setup steps (e.g. DWD for Google) */}
          {setupSteps && (
            <div className="border border-[#1a2744] rounded-xl overflow-hidden">
              <button
                onClick={() => setShowSetup(v => !v)}
                className="w-full flex items-center justify-between px-4 py-3 text-[12px] font-semibold text-[#93b4fd] hover:bg-[#0a1628] transition-colors"
              >
                <span className="flex items-center gap-1.5">
                  <ShieldCheck size={13} />
                  Advanced Setup (Domain-Wide Delegation)
                </span>
                {showSetup ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
              </button>
              {showSetup && setupSteps.map(section => (
                <div key={section.title} className="px-4 pb-4 pt-1 bg-[#0a1628] space-y-3">
                  <ol className="space-y-3">
                    {section.steps.map((step, i) => (
                      <li key={i} className="flex gap-3">
                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-[#3b6ef6]/20 text-[#93b4fd] text-[10px] font-bold flex items-center justify-center mt-0.5">
                          {i + 1}
                        </span>
                        <div className="min-w-0">
                          <p className="text-[12px] text-slate-300 leading-relaxed">{step.label}</p>
                          {step.value && (
                            <div className="mt-1.5 flex items-center gap-2 bg-[#141417] border border-white/[0.07] rounded-lg px-3 py-2">
                              <code className="text-[11px] font-mono text-emerald-400 break-all flex-1 select-all">{step.value}</code>
                              <button
                                onClick={() => navigator.clipboard.writeText(step.value!)}
                                className="flex-shrink-0 text-slate-500 hover:text-white transition-colors"
                              >
                                <Copy size={12} />
                              </button>
                            </div>
                          )}
                          {step.note && <p className="text-[11px] text-slate-500 mt-1 leading-relaxed">{step.note}</p>}
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Disconnected — setup info */}
      {!status.connected && (
        <div className="px-6 pb-6 space-y-4 border-t border-white/[0.04] pt-4">
          {/* Admin notice */}
          <div className="flex items-start gap-3 px-4 py-3 bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl">
            <Info size={14} className="text-[#93b4fd] mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-[12px] font-semibold text-[#93b4fd]">Admin authorization required</p>
              <p className="text-[12px] text-[#7a9fd6] mt-0.5 leading-relaxed">{requiresAdmin}</p>
            </div>
          </div>

          {/* Permissions */}
          <div>
            <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">Permissions requested</p>
            <div className="space-y-2">
              {permissions.map(p => (
                <div key={p.scope} className="flex items-start gap-3">
                  <ShieldCheck size={13} className="text-[#3b6ef6] mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-[12px] text-slate-300 font-medium">{p.label}</p>
                    <p className="text-[11px] text-slate-500">{p.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Phish Report Tab ─────────────────────────────────────────────────────────
const APPS_SCRIPT_CODE = `var HELIOS_API = 'https://app.himaya.ai';
var PHISH_REPORT_KEY = '{{PHISH_REPORT_KEY}}';  // replaced with your key below

function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var card = CardService.newCardBuilder()
    .setName('Helios Phish Reporter')
    .setHeader(CardService.newCardHeader()
      .setTitle('Helios Security')
      .setSubtitle('AI-Powered Email Protection'))
    .addSection(CardService.newCardSection()
      .setHeader('Report this email')
      .addWidget(CardService.newTextParagraph()
        .setText('If this email looks suspicious, report it to your security team.'))
      .addWidget(CardService.newTextButton()
        .setText('Report as Phishing')
        .setBackgroundColor('#ef4444')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction()
          .setFunctionName('reportPhishing')
          .setParameters({'messageId': messageId, 'accessToken': accessToken}))))
    .build();
  return [card];
}

function reportPhishing(e) {
  var messageId = e.parameters.messageId;
  GmailApp.setCurrentMessageAccessToken(e.parameters.accessToken);
  var message = GmailApp.getMessageById(messageId);
  if (!message) return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Could not access email.')).build();
  var payload = {
    reporter_email: Session.getActiveUser().getEmail(),
    subject: message.getSubject(),
    sender: message.getFrom(),
    sender_domain: message.getFrom().includes('@') ? message.getFrom().split('@').pop().replace('>', '').trim() : '',
    body_preview: message.getPlainBody().substring(0, 500),
    message_id: messageId,
    received_at: message.getDate().toISOString(),
    provider: 'gmail'
  };
  var response = UrlFetchApp.fetch(HELIOS_API + '/api/phish-report/submit', {
    method: 'post', contentType: 'application/json',
    headers: { 'X-Phish-Report-Key': PHISH_REPORT_KEY },
    payload: JSON.stringify(payload), muteHttpExceptions: true
  });
  if (response.getResponseCode() === 200) {
    message.moveToTrash();
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Reported! Helios is investigating.'))
      .setStateChanged(true).build();
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Report failed. Try again.')).build();
}`

const APPS_SCRIPT_MANIFEST = `{
  "timeZone": "UTC",
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email"
  ],
  "gmail": {
    "name": "Helios Phish Reporter",
    "logoUrl": "https://app.himaya.ai/himaya-logo.png",
    "primaryColor": "#1a2744",
    "secondaryColor": "#3b6ef6",
    "contextualTriggers": [{ "unconditional": {}, "onTriggerFunction": "onGmailMessageOpen" }]
  }
}`

function PhishReportTab() {
  const [phishKey, setPhishKey] = useState<string | null>(null)
  const [orgId, setOrgId] = useState<string>('')
  const [loadingKey, setLoadingKey] = useState(true)
  const [rotating, setRotating] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)
  const [copiedScript, setCopiedScript] = useState(false)
  const [copiedManifest, setCopiedManifest] = useState(false)

  useEffect(() => {
    api.get('/api/phish-report/key')
      .then(r => { setPhishKey(r.data.key); setOrgId(r.data.org_id) })
      .catch(() => {})
      .finally(() => setLoadingKey(false))
  }, [])

  const rotateKey = async () => {
    setRotating(true)
    try {
      const r = await api.post('/api/phish-report/key/rotate')
      setPhishKey(r.data.key)
    } catch {}
    setRotating(false)
  }

  const copyText = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const downloadManifest = () => {
    if (!phishKey || !orgId) return
    const taskpaneUrl = `https://app.himaya.ai/addons/outlook/taskpane.html?key=${phishKey}`
    const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:bt="http://schemas.microsoft.com/office/officeappbasictypes/1.0"
           xmlns:mailappor="http://schemas.microsoft.com/office/mailappversionoverrides/1.0"
           xsi:type="MailApp">
  <Id>${orgId}</Id>
  <Version>1.0.0.1</Version>
  <ProviderName>Himaya Technologies</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="Helios Phish Reporter"/>
  <Description DefaultValue="Report suspicious emails to your Helios security platform"/>
  <IconUrl DefaultValue="https://app.himaya.ai/himaya-3-32.png"/>
  <HighResolutionIconUrl DefaultValue="https://app.himaya.ai/himaya-3-80.png"/>
  <SupportUrl DefaultValue="https://app.himaya.ai"/>
  <AppDomains>
    <AppDomain>app.himaya.ai</AppDomain>
  </AppDomains>
  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>
  <Requirements>
    <Sets>
      <Set Name="Mailbox" MinVersion="1.1"/>
    </Sets>
  </Requirements>
  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="${taskpaneUrl}"/>
        <RequestedHeight>250</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>
  <Permissions>ReadWriteItem</Permissions>
  <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>
  <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides" xsi:type="VersionOverridesV1_0">
    <Requirements>
      <bt:Sets DefaultMinVersion="1.3">
        <bt:Set Name="Mailbox"/>
      </bt:Sets>
    </Requirements>
    <Hosts>
      <Host xsi:type="MailHost">
        <DesktopFormFactor>
          <ExtensionPoint xsi:type="MessageReadCommandSurface">
            <OfficeTab id="TabDefault">
              <Group id="helios.group.report">
                <Label resid="Group.Label"/>
                <Control xsi:type="Button" id="helios.button.reportPhishing">
                  <Label resid="Button.Label"/>
                  <Supertip>
                    <Title resid="Button.Label"/>
                    <Description resid="Button.Tooltip"/>
                  </Supertip>
                  <Icon>
                    <bt:Image size="16" resid="Icon.16x16"/>
                    <bt:Image size="32" resid="Icon.32x32"/>
                    <bt:Image size="80" resid="Icon.80x80"/>
                  </Icon>
                  <Action xsi:type="ShowTaskpane">
                    <SourceLocation resid="Taskpane.Url"/>
                  </Action>
                </Control>
              </Group>
            </OfficeTab>
          </ExtensionPoint>
        </DesktopFormFactor>
      </Host>
    </Hosts>
    <Resources>
      <bt:Images>
        <bt:Image id="Icon.16x16" DefaultValue="https://app.himaya.ai/himaya-3-16.png"/>
        <bt:Image id="Icon.32x32" DefaultValue="https://app.himaya.ai/himaya-3-32.png"/>
        <bt:Image id="Icon.80x80" DefaultValue="https://app.himaya.ai/himaya-3-80.png"/>
      </bt:Images>
      <bt:Urls>
        <bt:Url id="Taskpane.Url" DefaultValue="${taskpaneUrl}"/>
      </bt:Urls>
      <bt:ShortStrings>
        <bt:String id="Group.Label" DefaultValue="Helios Security"/>
        <bt:String id="Button.Label" DefaultValue="Report Phishing"/>
      </bt:ShortStrings>
      <bt:LongStrings>
        <bt:String id="Button.Tooltip" DefaultValue="Report this email as suspicious to your Helios security platform."/>
      </bt:LongStrings>
    </Resources>
  </VersionOverrides>
</OfficeApp>`
    const blob = new Blob([xml], { type: 'text/xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'helios-phish-reporter-manifest.xml'
    a.click()
    URL.revokeObjectURL(url)
  }

  const scriptWithKey = phishKey ? APPS_SCRIPT_CODE.replace("'{{PHISH_REPORT_KEY}}'", `'${phishKey}'`) : APPS_SCRIPT_CODE

  return (
    <div className="p-5 space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Fish size={16} className="text-[#3b6ef6]" />
          <h3 className="text-[14px] font-bold text-[var(--foreground)]">Employee Phish Report Add-on</h3>
        </div>
        <p className="text-[12px] text-[var(--muted)]">
          Let employees report suspicious emails directly from Gmail or Outlook.
          Reports go straight into your Helios threat queue for AI investigation.
        </p>
      </div>

      {/* API Key Card */}
      <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-4 space-y-3">
        <p className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider">Your Phish Report Key</p>
        {loadingKey ? (
          <div className="h-9 animate-pulse bg-white/[0.03] rounded-lg" />
        ) : (
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[12px] font-mono bg-[var(--card)] border border-[var(--border)] rounded-lg px-3 py-2 text-emerald-400 truncate">
              {phishKey || 'Not generated'}
            </code>
            <button
              onClick={() => phishKey && copyText(phishKey, setCopiedKey)}
              className="flex items-center gap-1.5 text-[11px] px-3 py-2 bg-[var(--card)] border border-[var(--border)] rounded-lg text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
            >
              <Copy size={11} />
              {copiedKey ? 'Copied!' : 'Copy'}
            </button>
            <button
              onClick={rotateKey}
              disabled={rotating}
              className="flex items-center gap-1.5 text-[11px] px-3 py-2 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400 hover:text-amber-300 transition-colors disabled:opacity-50"
            >
              <RefreshCw size={11} className={rotating ? 'animate-spin' : ''} />
              {rotating ? 'Rotating…' : 'Rotate Key'}
            </button>
          </div>
        )}
        <p className="text-[11px] text-[var(--muted)]">
          This key is unique to your organization. Each add-on installation uses this key to authenticate reports.
          Rotating it invalidates all existing add-on configurations — you&apos;ll need to redeploy with the new key.
        </p>
      </div>

      {/* Setup sections */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Gmail Setup */}
        <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Mail size={14} className="text-[#3b6ef6] flex-shrink-0" />
            <h4 className="text-[13px] font-bold text-[var(--foreground)]">Gmail Add-on Setup</h4>
          </div>
          <div className="bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 rounded-lg px-3 py-2 mb-2">
            <p className="text-[11px] text-[#3b6ef6] font-medium leading-relaxed">
              The Helios Phish Reporter add-on is published by <strong>Himaya Technologies</strong> from a single shared GCP project.
              Your org key (above) ties each report to your tenant. Install it once from your Google Workspace Admin console.
            </p>
          </div>
          <ol className="space-y-2 text-[11px] text-[var(--muted)]">
            <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">1.</span><span>Sign in to your <strong>Google Workspace Admin Console</strong> (<a href="https://admin.google.com" target="_blank" rel="noreferrer" className="text-[#3b6ef6] hover:underline">admin.google.com</a>) as a super admin</span></li>
            <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">2.</span><span>Go to <strong>Apps → Google Workspace Marketplace apps → Add app to domain install list</strong></span></li>
            <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">3.</span><span>Search for <strong>&quot;Helios Phish Reporter&quot;</strong> by Himaya Technologies, click Install</span></li>
            <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">4.</span><span>Select the OUs or users to deploy to, then click <strong>Finish</strong></span></li>
            <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">5.</span><span>Employees will see the Helios panel the next time they open an email in Gmail</span></li>
          </ol>
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
            <p className="text-[11px] text-amber-400 leading-relaxed">
              <strong>Developer note:</strong> Until the add-on is published to the Marketplace, use the Apps Script code below to manually deploy a private copy for testing — paste Code.gs and appsscript.json into <a href="https://script.google.com" target="_blank" rel="noreferrer" className="text-amber-400 hover:underline">script.google.com</a>, link it to your Workspace domain under Deploy → Test Deployments.
            </p>
          </div>

          {/* Apps Script code */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider">Code.gs</p>
              <button
                onClick={() => copyText(scriptWithKey, setCopiedScript)}
                className="flex items-center gap-1 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
              >
                <Copy size={9} /> {copiedScript ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="text-[10px] font-mono bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 overflow-auto max-h-32 text-emerald-400 whitespace-pre-wrap break-all">{scriptWithKey}</pre>
          </div>

          {/* appsscript.json */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider">appsscript.json</p>
              <button
                onClick={() => copyText(APPS_SCRIPT_MANIFEST, setCopiedManifest)}
                className="flex items-center gap-1 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
              >
                <Copy size={9} /> {copiedManifest ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="text-[10px] font-mono bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 overflow-auto max-h-24 text-blue-300 whitespace-pre-wrap">{APPS_SCRIPT_MANIFEST}</pre>
          </div>
        </div>

        {/* Outlook Setup */}
        <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Inbox size={14} className="text-[#3b6ef6] flex-shrink-0" />
            <h4 className="text-[13px] font-bold text-[var(--foreground)]">Outlook Add-in Setup</h4>
          </div>

          {/* URL method */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 space-y-2">
            <ol className="space-y-1.5 text-[11px] text-[var(--muted)]">
              <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">1.</span><span>Copy your manifest URL below</span></li>
              <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">2.</span><span>Go to <strong className="text-[var(--foreground)]">Microsoft 365 Admin Center</strong> → Settings → Integrated apps → Upload custom app</span></li>
              <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">3.</span><span>Choose <strong className="text-[var(--foreground)]">&quot;Provide link to manifest file&quot;</strong> and paste the URL</span></li>
              <li className="flex gap-2"><span className="text-[#3b6ef6] font-bold flex-shrink-0">4.</span><span>Assign to users or deploy org-wide</span></li>
            </ol>
            {phishKey ? (
              <div className="flex items-center gap-2 mt-2">
                <code className="flex-1 text-[10px] font-mono bg-[var(--background)] border border-[var(--border)] rounded px-2 py-1.5 text-emerald-400 truncate">
                  {`https://app.himaya.ai/api/phish-report/manifest.xml?key=${phishKey}`}
                </code>
                <button
                  onClick={() => copyText(`https://app.himaya.ai/api/phish-report/manifest.xml?key=${phishKey}`, setCopiedManifest)}
                  className="flex-shrink-0 flex items-center gap-1 text-[11px] px-2.5 py-1.5 bg-[#3b6ef6] text-white rounded hover:bg-[#2d5de0] transition-colors"
                >
                  {copiedManifest ? '✓ Copied' : 'Copy URL'}
                </button>
              </div>
            ) : (
              <div className="h-8 animate-pulse bg-white/[0.03] rounded" />
            )}
            <p className="text-[10px] text-[var(--muted)] pt-1">Note: it may take up to 72 hours for the add-in to appear in Outlook after deployment.</p>
          </div>
        </div>
      </div>

      {/* How it works */}
      <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-4 space-y-3">
        <p className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider">How it works</p>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {[
            { Icon: MousePointerClick, label: 'Employee clicks "Report as Phishing" on any email' },
            { Icon: ArrowUpFromLine, label: 'Email is moved out of inbox while Helios investigates' },
            { Icon: ShieldAlert, label: 'Helios AI investigates: VT, threat feeds, sender history' },
            { Icon: CheckCircle2, label: 'If clean (DISMISS), email is automatically restored to inbox' },
            { Icon: Brain, label: 'All reports train the AI model to get smarter over time' },
          ].map(({ Icon, label }, i) => (
            <div key={i} className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 text-center">
              <div className="flex justify-center mb-2"><Icon size={16} className="text-[#3b6ef6]" /></div>
              <p className="text-[10px] text-[var(--muted)] leading-relaxed">{label}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────
export default function OnboardingPage() {
  const router = useRouter()
  const { theme } = useTheme()
  const isLight = theme === 'light'
  const searchParams = useSearchParams()
  const connectedParam = searchParams.get('connected')
  const errorParam = searchParams.get('error')

  const [connections, setConnections] = useState<Connections | null>(null)
  const [loading, setLoading] = useState(true)
  const [connecting, setConnecting] = useState<string | null>(null)
  const [disconnecting, setDisconnecting] = useState<string | null>(null)
  const [baselineProgress, setBaselineProgress] = useState(0)
  const [mailboxCount, setMailboxCount] = useState<number | null>(null)
  const [syncHistory, setSyncHistory] = useState<any>(null)
  const [dwdStatus, setDwdStatus] = useState<{ dwd_active: boolean; admin_email?: string; error?: string; monitored_mailboxes?: number } | null>(null)
  const [recheckingDwd, setRecheckingDwd] = useState(false)
  const [intTab, setIntTab] = useState<'providers' | 'sync' | 'phish'>('providers')
  const [confirmDisconnectProvider, setConfirmDisconnectProvider] = useState<string | null>(null)
  const [scopeGroups, setScopeGroups] = useState<Record<string, {id:string,name:string}|null>>({})
  const [scopeSearch, setScopeSearch] = useState<Record<string, string>>({})
  const [scopeResults, setScopeResults] = useState<Record<string, any[]>>({})
  const [scopeLoading, setScopeLoading] = useState<Record<string, boolean>>({})
  const [scopeOpen, setScopeOpen] = useState<Record<string, boolean>>({})

  const fetchConnections = useCallback(async () => {
    try {
      const r = await api.get('/api/onboarding/connections')
      setConnections(r.data)
    } catch {}
  }, [])

  const checkDwd = useCallback(async () => {
    try {
      const r = await api.get('/api/onboarding/dwd/test')
      setDwdStatus(r.data)
    } catch {}
    setLoading(false)
  }, [])

  const recheckDwd = async () => {
    setRecheckingDwd(true)
    await checkDwd()
    setRecheckingDwd(false)
  }

  useEffect(() => { fetchConnections() }, [fetchConnections])

  useEffect(() => {
    const fetchSyncHistory = async () => {
      try {
        const r = await api.get('/api/onboarding/sync/history')
        setSyncHistory(r.data)
      } catch {}
    }
    fetchSyncHistory()
    const t = setInterval(fetchSyncHistory, 30000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const r = await api.get('/api/onboarding/baseline/status')
        setBaselineProgress(r.data?.progress ?? 0)
        if (r.data?.emails_processed) setMailboxCount(r.data.emails_processed)
        return r.data?.status
      } catch {}
    }
    fetchStatus().then(status => {
      if (status === 'complete' || status === 'not_started') return
      const poll = setInterval(async () => {
        const s = await fetchStatus()
        if (s === 'complete' || baselineProgress >= 100) clearInterval(poll)
      }, 2000)
      return () => clearInterval(poll)
    })
  }, [])

  const loadScopeGroup = useCallback(async (prov: string) => {
    try {
      const r = await api.get(`/api/onboarding/scope-group/${prov}`)
      setScopeGroups(s => ({ ...s, [prov]: r.data.scope_group_id ? { id: r.data.scope_group_id, name: r.data.scope_group_name || r.data.scope_group_id } : null }))
    } catch {}
  }, [])

  useEffect(() => {
    if (connections?.google?.connected) { checkDwd(); loadScopeGroup('google') }
    else setLoading(false)
    if (connections?.m365?.connected) loadScopeGroup('m365')
  }, [connections?.google?.connected, connections?.m365?.connected, checkDwd, loadScopeGroup])

  const searchScopeGroups = async (prov: string, q: string) => {
    setScopeLoading(s => ({ ...s, [prov]: true }))
    try {
      const r = await api.get(`/api/onboarding/scope-group/${prov}/search?q=${encodeURIComponent(q)}`)
      setScopeResults(s => ({ ...s, [prov]: r.data.groups || [] }))
    } catch {}
    setScopeLoading(s => ({ ...s, [prov]: false }))
  }

  const setScopeGroup = async (prov: string, group: {id:string,name:string}|null) => {
    try {
      await api.post('/api/onboarding/scope-group', { provider: prov, group_id: group?.id || null, group_name: group?.name || null })
      setScopeGroups(s => ({ ...s, [prov]: group }))
      setScopeResults(s => ({ ...s, [prov]: [] }))
      setScopeSearch(s => ({ ...s, [prov]: '' }))
    } catch {}
  }

  const connectProvider = async (provider: 'm365' | 'google') => {
    setConnecting(provider)
    try {
      const r = await api.get(`/api/onboarding/connect/${provider}/url`)
      if (r.data?.auth_url) window.location.href = r.data.auth_url
    } catch { setConnecting(null) }
  }

  const disconnectProvider = async (provider: string) => {
    setDisconnecting(provider)
    try {
      await api.delete(`/api/onboarding/connect/${provider}`)
      await fetchConnections()
    } catch {}
    setDisconnecting(null)
  }

  const isGoogleConnected = connections?.google?.connected
  const isM365Connected = connections?.m365?.connected
  const anyConnected = isGoogleConnected || isM365Connected
  const dwdOk = dwdStatus?.dwd_active || (dwdStatus?.monitored_mailboxes ?? 0) > 1

  // ── Post-connect success screen ────────────────────────────────────────────
  if (connectedParam) {
    const providerName = connectedParam === 'm365' ? 'Microsoft 365' : 'Google Workspace'
    return (
      <div className="max-w-md mx-auto py-16 text-center space-y-6">
        <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto">
          <CheckCircle2 size={30} className="text-emerald-400" />
        </div>
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">{providerName} Connected</h1>
        </div>
        <ProgressBar pct={baselineProgress} label="Email scan progress" />
        {mailboxCount != null && mailboxCount > 0 && (
          <p className="text-sm text-emerald-400 font-medium">{mailboxCount.toLocaleString()} emails processed</p>
        )}
        <Button onClick={() => router.push('/dashboard')}>
          Go to Dashboard <ArrowRight size={14} />
        </Button>
      </div>
    )
  }

  return (
    <div className="max-w-3xl space-y-6">

      {/* Page header */}
      <div>
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Email Provider Integrations</h1>
      </div>

      {/* Error banner */}
      {errorParam && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-900/20 border border-red-700/30 rounded-xl text-sm text-red-300">
          <AlertCircle size={15} className="flex-shrink-0" />
          Authorization was cancelled or denied by the provider. Please try again.
        </div>
      )}

      {/* Baseline scan progress — shown when connected and in progress */}
      {anyConnected && baselineProgress > 0 && baselineProgress < 100 && (
        <div className="bg-[#0d1b2e] border border-[#1a2744] rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-[#3b6ef6]" />
              <span className="text-[13px] font-semibold text-white">Baseline Scan</span>
            </div>
            {mailboxCount != null && mailboxCount > 0 && (
              <span className="text-[12px] text-emerald-400 font-medium">{mailboxCount.toLocaleString()} emails scanned</span>
            )}
          </div>
          <ProgressBar
            pct={baselineProgress}
            label={baselineProgress >= 100 ? 'Scan complete — full threat history loaded' : baselineProgress > 0 ? 'Scanning last 90 days of email…' : 'Waiting to start…'}
          />
        </div>
      )}

      {/* Loading skeleton */}
      {loading ? (
        <div className="space-y-4">
          {[1, 2].map(i => <div key={i} className="h-36 animate-pulse bg-white/[0.03] rounded-2xl border border-white/[0.04]" />)}
        </div>
      ) : (
        <div className="space-y-4">
          <ProviderCard
            name="Microsoft 365"
            logo={<M365Logo />}
            accentColor="#0078D4"
            status={connections?.m365 ?? { connected: false, mailbox_count: 0, status: 'not_connected', connected_at: null }}
            onConnect={() => connectProvider('m365')}
            onDisconnect={() => disconnectProvider('m365')}
            connecting={connecting === 'm365'}
            disconnecting={disconnecting === 'm365'}
            requiresAdmin="Requires a Microsoft 365 Global Admin or Exchange Admin. They will see a tenant-wide consent prompt during authorization."
            permissions={[
              { scope: 'Mail.ReadWrite', label: 'Read & modify all mailboxes (WRITE — required for quarantine)', reason: 'Without Mail.ReadWrite, Helios can detect threats but cannot physically move emails into quarantine folders. Mail.Read alone is NOT sufficient.' },
              { scope: 'MailboxSettings.Read', label: 'Read mailbox settings', reason: 'Understand delivery rules and forwarding' },
              { scope: 'User.Read.All', label: 'List all users', reason: 'Build recipient risk profiles for all employees' },
              { scope: 'Directory.Read.All', label: 'Read directory', reason: 'Map organizational hierarchy for impersonation detection' },
            ]}
          />

          <ProviderCard
            name="Google Workspace"
            logo={<GoogleLogo />}
            accentColor="#4285F4"
            status={connections?.google ?? { connected: false, mailbox_count: 0, status: 'not_connected', connected_at: null }}
            onConnect={() => connectProvider('google')}
            onDisconnect={() => disconnectProvider('google')}
            connecting={connecting === 'google'}
            disconnecting={disconnecting === 'google'}
            requiresAdmin="Requires a Google Workspace Super Admin. This grants access to list all users via the Admin SDK Directory API."
            permissions={[
              { scope: 'gmail.modify', label: 'Read & modify Gmail messages (WRITE — required for quarantine & blocking)', reason: 'Without this scope Helios can detect threats but cannot physically move emails out of inboxes. gmail.readonly is NOT sufficient.' },
              { scope: 'admin.directory.user.readonly', label: 'List all users in org', reason: 'Build recipient risk profiles for all employees' },
            ]}
            setupSteps={[{
              title: 'Enable Domain-Wide Delegation for full mailbox scanning',
              steps: [
                {
                  label: 'Go to Google Admin Console → Security → Access and data control → API controls → Domain-wide Delegation.',
                  note: 'Direct path: admin.google.com → Security → API Controls → Domain-wide Delegation'
                },
                {
                  label: 'Click "Add new" and enter the Helios Service Account Client ID:',
                  value: '114733393163502940734',
                },
                {
                  label: 'Paste these OAuth scopes (include both — modify is required for quarantine):',
                  value: 'https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.user.readonly',
                  note: '⚠️ gmail.modify is required for quarantine to work. gmail.readonly only lets Helios read — it cannot move emails out of inboxes.',
                },
                {
                  label: 'Click Authorize. Helios will now scan and protect all mailboxes in your org.',
                  note: 'This is a one-time setup per tenant. The same Client ID is shared across all Helios deployments — you are only granting access to your own org\'s data.'
                },
              ]
            }]}
          />
        </div>
      )}

      {/* DWD Status Banner */}
      {isGoogleConnected && dwdStatus && (
        <div style={{
          background: dwdOk
            ? (isLight ? 'rgba(16,185,129,0.08)' : 'rgba(16,185,129,0.06)')
            : (isLight ? 'rgba(245,158,11,0.10)' : 'rgba(245,158,11,0.07)'),
          border: `1px solid ${dwdOk
            ? (isLight ? 'rgba(16,185,129,0.35)' : 'rgba(16,185,129,0.25)')
            : (isLight ? 'rgba(245,158,11,0.45)' : 'rgba(245,158,11,0.30)')}`,
        }} className="rounded-xl px-5 py-4 flex items-start gap-3">
          {dwdOk
            ? <CheckCircle2 size={18} className="text-emerald-400 mt-0.5 shrink-0" />
            : <AlertTriangle size={18} className="text-amber-400 mt-0.5 shrink-0" />
          }
          <div className="flex-1 min-w-0">
            {dwdOk ? (
              <>
                <p className="text-sm font-semibold" style={{ color: isLight ? '#065f46' : '#6ee7b7' }}>
                  Domain-Wide Delegation active
                </p>
                <p className="text-xs mt-0.5 leading-relaxed" style={{ color: isLight ? '#047857' : '#a7f3d0' }}>
                  Helios is scanning all mailboxes in your domain and can quarantine threats directly.
                  {(dwdStatus.monitored_mailboxes ?? 0) > 1 && (
                    <> Currently protecting{' '}
                      <strong style={{ color: isLight ? '#065f46' : '#6ee7b7' }}>
                        {dwdStatus.monitored_mailboxes?.toLocaleString()} mailboxes
                      </strong>. New inboxes are auto-enrolled on every delta sync.</>
                  )}
                </p>
              </>
            ) : (
              <>
                <p className="text-sm font-semibold" style={{ color: isLight ? '#92400e' : '#fcd34d' }}>
                  Domain-Wide Delegation not confirmed
                </p>
                <p className="text-xs mt-1 leading-relaxed" style={{ color: isLight ? '#b45309' : '#fde68a' }}>
                  Without DWD, Helios can only scan{' '}
                  <strong style={{ color: isLight ? '#92400e' : '#fcd34d' }}>
                    {dwdStatus.admin_email ?? 'the admin mailbox'}
                  </strong>{' '}
                  and <strong>cannot quarantine emails</strong>.
                  Follow the setup steps in the Google Workspace card above to enable full protection.
                </p>
              </>
            )}
          </div>
          <button
            onClick={recheckDwd}
            disabled={recheckingDwd}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white px-3 py-1.5 rounded-lg border border-slate-700 hover:border-slate-500 transition-colors flex-shrink-0 disabled:opacity-50"
          >
            <RefreshCw size={11} className={recheckingDwd ? 'animate-spin' : ''} />
            Re-check
          </button>
        </div>
      )}

      {/* ── 4-Tab Panel ─────────────────────────────────────────────── */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-2xl overflow-hidden">

        {/* Tab bar */}
        <div className="flex border-b border-[var(--border)]">
          {([
            { id: 'providers', label: 'Providers',                  Icon: Plug      },
            { id: 'sync',      label: 'Sync & Audit',               Icon: BarChart2 },
            { id: 'phish',     label: 'Employee Phish Report Add-on', Icon: Fish     },
          ] as const).map(({ id: t, label, Icon }) => (
            <button key={t} onClick={() => setIntTab(t as any)}
              className={`flex items-center gap-1.5 px-5 py-3 text-[12px] font-semibold border-b-2 transition-colors ${
                intTab === t
                  ? 'border-[#3b6ef6] text-[#3b6ef6]'
                  : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
              }`}>
              <Icon size={12} />
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Providers ────────────────────────────────────────── */}
        {intTab === 'providers' && (
          <div className="p-5 space-y-4">
            {loading ? (
              [1,2].map(i => <div key={i} className="h-32 animate-pulse bg-white/[0.03] rounded-xl" />)
            ) : (
              <>
                {/* Provider summary cards */}
                {(['google', 'm365'] as const).map(prov => {
                  const info = connections?.[prov]
                  const isConn = info?.connected
                  const provLabel = prov === 'google' ? 'Google Workspace' : 'Microsoft 365'
                  const provColor = prov === 'google' ? '#4285F4' : '#0078D4'
                  return (
                    <div key={prov} className={`rounded-xl border p-4 flex flex-col gap-3 ${
                      isConn ? 'border-emerald-500/20 bg-emerald-500/[0.03]' : 'border-[var(--border)]'
                    }`}>
                      <div className="flex items-center gap-4">
                      <div className="flex-shrink-0">
                        {prov === 'google' ? <GoogleLogo size={36} /> : <M365Logo size={36} />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[13px] font-semibold text-[var(--foreground)]">{provLabel}</span>
                          {isConn
                            ? <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400">Connected</span>
                            : <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-slate-700/40 text-slate-500">Not connected</span>
                          }
                        </div>
                        {isConn && (
                          <div className="mt-1 flex items-center gap-3 text-[11px] text-[var(--muted)]">
                            <span>{info?.org_domain || '—'}</span>
                            <span>·</span>
                            <span style={{ color: provColor }} className="font-semibold">{(info?.mailbox_count ?? 0).toLocaleString()} mailboxes</span>
                            {(info as any)?.groups_count > 0 && <><span>·</span><span>{(info as any).groups_count} groups</span></>}
                            {(info as any)?.aliases_count > 0 && <><span>·</span><span>{(info as any).aliases_count} aliases</span></>}
                          </div>
                        )}
                        {isConn && info?.connected_at && (
                          <p className="text-[10px] text-[var(--muted)] mt-0.5">
                            Connected {new Date(info.connected_at).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                      {isConn ? (
                        confirmDisconnectProvider === prov ? (
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] text-slate-400">Disconnect?</span>
                            <button
                              onClick={() => { setConfirmDisconnectProvider(null); disconnectProvider(prov) }}
                              disabled={disconnecting === prov}
                              className="text-[11px] text-white bg-red-600 hover:bg-red-500 rounded-lg px-3 py-1.5 font-semibold transition-colors disabled:opacity-50"
                            >
                              {disconnecting === prov ? 'Disconnecting…' : 'Yes, remove'}
                            </button>
                            <button
                              onClick={() => setConfirmDisconnectProvider(null)}
                              className="text-[11px] text-slate-400 hover:text-slate-200 border border-slate-700 rounded-lg px-3 py-1.5 transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                        <button
                          onClick={() => setConfirmDisconnectProvider(prov)}
                          disabled={disconnecting === prov}
                          className="flex-shrink-0 text-[11px] text-red-400 hover:text-red-300 border border-red-500/20 rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50"
                        >
                          Disconnect
                        </button>
                        )
                      ) : (
                        <button
                          onClick={() => connectProvider(prov)}
                          disabled={connecting === prov}
                          style={{ background: provColor }}
                          className="flex-shrink-0 text-[11px] text-white rounded-lg px-3 py-1.5 font-semibold disabled:opacity-50"
                        >
                          {connecting === prov ? 'Connecting…' : 'Connect'}
                        </button>
                      )}
                      </div>{/* end flex header row */}

                    {/* ── Scoped Group Monitoring ─────────────────────────── */}
                    {isConn && (
                      <div className="border-t border-[var(--border)] pt-2">
                        <button
                          onClick={() => setScopeOpen(s => ({ ...s, [prov]: !s[prov] }))}
                          className="flex items-center gap-1.5 text-[11px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors w-full text-left"
                        >
                          <Users size={11} />
                          <span className="font-semibold">Scoped Monitoring</span>
                          {scopeGroups[prov]
                            ? <span className="ml-1 text-emerald-400">· {scopeGroups[prov]!.name}</span>
                            : <span className="ml-1 text-[var(--muted)]">· All users</span>}
                          <ChevronDown size={10} className={`ml-auto transition-transform ${scopeOpen[prov] ? 'rotate-180' : ''}`} />
                        </button>

                        {scopeOpen[prov] && (
                          <div className="mt-2 space-y-2">
                            <p className="text-[11px] text-[var(--muted)] leading-relaxed">
                              Limit monitoring to a specific security group or distribution list.
                              Only members of this group will be scanned. Leave empty to monitor all users.
                            </p>

                            {scopeGroups[prov] && (
                              <div className="flex items-center gap-2 px-2.5 py-1.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                                <span className="text-[11px] text-emerald-400 flex-1">
                                  ✓ Scoped to: <strong>{scopeGroups[prov]!.name}</strong>
                                </span>
                                <button
                                  onClick={() => setScopeGroup(prov, null)}
                                  className="text-[10px] text-red-400 hover:text-red-300"
                                >Remove</button>
                              </div>
                            )}

                            <div className="flex gap-2">
                              <input
                                type="text"
                                placeholder="Search groups…"
                                value={scopeSearch[prov] || ''}
                                onChange={e => setScopeSearch(s => ({ ...s, [prov]: e.target.value }))}
                                className="flex-1 text-[11px] bg-[var(--background)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-[var(--foreground)] placeholder:text-[var(--muted)] outline-none focus:border-[#3b6ef6]"
                              />
                              <button
                                onClick={() => searchScopeGroups(prov, scopeSearch[prov] || '')}
                                disabled={scopeLoading[prov]}
                                className="text-[11px] px-3 py-1.5 bg-[#3b6ef6] text-white rounded-lg font-semibold disabled:opacity-50"
                              >
                                {scopeLoading[prov] ? '…' : 'Search'}
                              </button>
                            </div>

                            {(scopeResults[prov] || []).length > 0 && (
                              <div className="bg-[var(--background)] border border-[var(--border)] rounded-lg overflow-hidden">
                                {(scopeResults[prov] || []).map((g: any) => (
                                  <button
                                    key={g.id}
                                    onClick={() => setScopeGroup(prov, { id: g.id, name: g.name || g.email })}
                                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-[#3b6ef6]/10 text-left border-b border-[var(--border)] last:border-0 transition-colors"
                                  >
                                    <Mail size={11} className="text-[#3b6ef6] flex-shrink-0" />
                                    <div className="min-w-0">
                                      <p className="text-[11px] font-semibold text-[var(--foreground)] truncate">{g.name}</p>
                                      {g.email && <p className="text-[10px] text-[var(--muted)] truncate">{g.email}</p>}
                                    </div>
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  )
                })}

                {/* Directory counts - groups, shared, aliases (don't count toward seat cost) */}
                {anyConnected && (
                  <div className="mt-2">
                    <p className="text-[10px] text-[var(--muted)] uppercase tracking-wider font-semibold mb-2">Directory Objects (not billed)</p>
                    <div className="grid grid-cols-3 gap-3">
                      {(['google', 'm365'] as const).filter(p => connections?.[p]?.connected).map(prov => {
                        const c = connections![prov] as any
                        return (
                          <div key={prov} className="col-span-3 grid grid-cols-3 gap-3">
                            <div className="bg-[var(--background)] rounded-lg p-3 border border-[var(--border)]">
                              <p className="text-[10px] text-[var(--muted)]">{prov === 'google' ? 'Google' : 'M365'} Groups</p>
                              <p className="text-[18px] font-bold text-[#3b6ef6] mt-0.5">{(c.groups_count ?? 0).toLocaleString()}</p>
                            </div>
                            <div className="bg-[var(--background)] rounded-lg p-3 border border-[var(--border)]">
                              <p className="text-[10px] text-[var(--muted)]">{prov === 'google' ? 'Google' : 'M365'} Aliases</p>
                              <p className="text-[18px] font-bold text-[#8b5cf6] mt-0.5">{(c.aliases_count ?? 0).toLocaleString()}</p>
                            </div>
                            <div className="bg-[var(--background)] rounded-lg p-3 border border-[var(--border)]">
                              <p className="text-[10px] text-[var(--muted)]">{prov === 'google' ? 'Delegated' : 'Shared'} Mailboxes</p>
                              <p className="text-[18px] font-bold text-[#f97316] mt-0.5">{(c.shared_count ?? 0).toLocaleString()}</p>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* ── Tab: Sync & Audit ─────────────────────────────────────── */}
        {intTab === 'sync' && syncHistory && (
          <div className="p-5 space-y-5">
            {/* Live delta sync summary */}
            <div>
              <p className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-3">Live Delta Sync</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {(['google', 'm365'] as const).filter(p => connections?.[p]?.connected).map(prov => {
                  const ts = syncHistory.last_sync?.[prov]
                  const diff = ts ? Math.floor((Date.now() - ts * 1000) / 1000) : null
                  const lastSyncStr = diff == null ? 'Never' : diff < 60 ? `${diff}s ago` : `${Math.floor(diff / 60)}m ago`
                  return (
                    <div key={prov} className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-3">
                      <p className="text-[10px] text-[var(--muted)]">{prov === 'google' ? 'Google Workspace' : 'Microsoft 365'} Last Sync</p>
                      <p className="text-[18px] font-bold text-emerald-400 mt-0.5">{lastSyncStr}</p>
                      <p className="text-[10px] text-[var(--muted)] mt-0.5">Every 1 min</p>
                    </div>
                  )
                })}
                <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-3">
                  <p className="text-[10px] text-[var(--muted)]">Mailboxes Monitored</p>
                  <p className="text-[18px] font-bold text-[#3b6ef6] mt-0.5">{(syncHistory.monitored_mailboxes ?? 0).toLocaleString()}</p>
                  <p className="text-[10px] text-[var(--muted)] mt-0.5">Auto-enrolled</p>
                </div>
                <div className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-3">
                  <p className="text-[10px] text-[var(--muted)]">Total Emails Scanned</p>
                  <p className="text-[18px] font-bold text-[#8b5cf6] mt-0.5">{(syncHistory.baseline?.emails_processed ?? 0).toLocaleString()}</p>
                  <p className="text-[10px] text-[var(--muted)] mt-0.5">Baseline + live</p>
                </div>
              </div>
            </div>

            {/* Per-provider baseline audit */}
            <div>
              <p className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-3">Baseline Audit</p>
              <div className="space-y-3">
                {(['google', 'm365'] as const).filter(p => connections?.[p]?.connected).map(prov => {
                  const pd = syncHistory.providers?.[prov]
                  const connInfo = connections?.[prov] as any
                  const pct = pd?.progress ?? connInfo?.baseline_progress ?? 0
                  const isComplete = pct >= 100
                  const lastAt = pd?.last_baseline_at || connInfo?.last_baseline_at
                  const provLabel = prov === 'google' ? 'Google Workspace' : 'Microsoft 365'
                  return (
                    <div key={prov} className="bg-[var(--background)] border border-[var(--border)] rounded-xl p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <p className="text-[13px] font-semibold text-[var(--foreground)]">{provLabel} Baseline</p>
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                          isComplete ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                        }`}>
                          {isComplete ? '✓ Complete' : `${pct}% in progress`}
                        </span>
                      </div>
                      <div className="h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
                        <div className="h-full bg-[#3b6ef6] rounded-full transition-all" style={{ width: `${Math.min(pct, 100)}%` }} />
                      </div>
                      <div className="flex items-center gap-4 text-[11px] text-[var(--muted)]">
                        <span><strong className="text-[var(--foreground)]">{(pd?.emails_processed ?? 0).toLocaleString()}</strong> emails processed</span>
                        <span><strong className="text-[var(--foreground)]">{(pd?.mailboxes ?? connInfo?.mailbox_count ?? 0).toLocaleString()}</strong> mailboxes</span>
                        {lastAt && (
                          <span>Last run: <strong className="text-[var(--foreground)]">{new Date(lastAt).toLocaleString()}</strong></span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Recent delta sync log */}
            <div>
              <p className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-3">Recent Delta Sync Log</p>
              {syncHistory.history?.length > 0 ? (
                <div className="space-y-1.5">
                  {syncHistory.history.slice(0, 12).map((run: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 text-[12px] py-1.5 border-b border-[var(--border)] last:border-0">
                      <span className="text-[var(--muted)] w-14 flex-shrink-0 tabular-nums">
                        {new Date(run.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                      <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        run.provider === 'google' ? 'bg-blue-900/40 text-blue-300' : 'bg-purple-900/40 text-purple-300'
                      }`}>
                        {run.provider === 'google' ? 'Google' : 'M365'}
                      </span>
                      <span className="text-[var(--muted)] flex-1">
                        {run.new_emails > 0
                          ? <><span className="text-emerald-400 font-semibold">+{run.new_emails}</span> new emails</>
                          : <span className="text-[var(--muted)]">No new emails</span>}
                      </span>
                      <span className={`text-[11px] font-semibold ${run.status === 'ok' ? 'text-emerald-500' : 'text-red-400'}`}>
                        {run.status === 'ok' ? '✓ OK' : '✗ Error'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[12px] text-[var(--muted)] py-2">No delta syncs yet — first sync runs within 1 minute of connection.</p>
              )}
            </div>
          </div>
        )}

        {/* ── Tab: Phish Reports ────────────────────────────────────── */}
        {intTab === 'phish' && (
          <PhishReportTab />
        )}
      </div>

      {/* Data handling footer */}
      <div className="flex items-start gap-3 px-4 py-3.5 bg-white/[0.02] border border-white/[0.05] rounded-xl">
        <ShieldCheck size={14} className="text-slate-500 mt-0.5 flex-shrink-0" />
        <p className="text-[12px] text-slate-500 leading-relaxed">
          <span className="text-slate-400 font-medium">Data handling:</span>{' '}
          Email content is analysed in-memory and never stored. Only metadata (sender, recipient, subject hash, classification) is retained.
          OAuth tokens are encrypted at rest using AES-256. TLS 1.3 in transit.
        </p>
      </div>
    </div>
  )
}
