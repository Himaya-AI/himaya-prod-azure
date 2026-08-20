import { ActionChip } from './DlpChrome'
import type { PolicyChange } from '@/lib/dlp/policy-diff'

export default function DlpPolicyDiff({
  publishedVersion,
  changes,
  hasDraft,
  includesUnsaved = false,
}: {
  publishedVersion: number
  changes: PolicyChange[]
  hasDraft: boolean
  includesUnsaved?: boolean
}) {
  const added = changes.filter((change) => change.kind === 'added').length
  const removed = changes.filter((change) => change.kind === 'removed').length
  const changed = changes.filter((change) => change.kind === 'changed').length
  const defaultChanged = changes.some((change) => change.kind === 'default_action')

  return (
    <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-[13px] font-semibold text-white">
            Draft vs active v{publishedVersion}
          </h3>
          <p className="mt-1 text-[11px] text-[#71717a]">
            {includesUnsaved
              ? 'Includes unsaved editor changes. Save draft before Publish; the server publishes the last saved draft.'
              : 'This is what Publish will make live. The gateway enforces the active version, not this editor.'}
          </p>
        </div>
        {changes.length === 0 ? (
          <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-400">
            No differences
          </span>
        ) : (
          <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-400">
            {[
              added ? `${added} added` : null,
              changed ? `${changed} changed` : null,
              removed ? `${removed} removed` : null,
              defaultChanged ? 'default action' : null,
            ].filter(Boolean).join(' · ')}
          </span>
        )}
      </div>

      {changes.length === 0 ? (
        <p className="text-[12px] text-[#71717a]">
          The editor matches active v{publishedVersion}.
          {hasDraft ? ' Publishing would create a new identical version.' : ''}
        </p>
      ) : (
        <ul className="space-y-2">
          {changes.map((change) => {
            if (change.kind === 'default_action') {
              return (
                <li
                  key="default-action"
                  className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-[12px] text-[#a1a1aa]"
                >
                  Default action{' '}
                  <span className="text-white">{change.from}</span>
                  {' → '}
                  <span className="text-white">{change.to}</span>
                </li>
              )
            }
            if (change.kind === 'added') {
              return (
                <li
                  key={`added-${change.rule.rule_id}`}
                  className="rounded-lg border border-emerald-500/15 bg-emerald-500/[0.04] px-3 py-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wide text-emerald-400">
                      Added
                    </span>
                    <span className="text-[12px] text-white">{change.rule.name}</span>
                    <ActionChip action={change.rule.action} />
                  </div>
                </li>
              )
            }
            if (change.kind === 'removed') {
              return (
                <li
                  key={`removed-${change.rule.rule_id}`}
                  className="rounded-lg border border-red-500/15 bg-red-500/[0.04] px-3 py-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wide text-red-400">
                      Removed
                    </span>
                    <span className="text-[12px] text-white">{change.rule.name}</span>
                    <ActionChip action={change.rule.action} />
                  </div>
                </li>
              )
            }
            return (
              <li
                key={`changed-${change.ruleId}`}
                className="rounded-lg border border-amber-500/15 bg-amber-500/[0.04] px-3 py-2"
              >
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-amber-400">
                    Changed
                  </span>
                  <span className="text-[12px] text-white">{change.name}</span>
                </div>
                <ul className="space-y-1 text-[11px] text-[#a1a1aa]">
                  {change.fields.map((field) => (
                    <li key={`${change.ruleId}-${field.label}`}>
                      {field.label}: {field.from} → {field.to}
                    </li>
                  ))}
                </ul>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
