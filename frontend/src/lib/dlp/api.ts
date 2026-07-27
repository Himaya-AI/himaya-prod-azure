import { AxiosError } from 'axios'

import api from '@/lib/api'
import type {
  DlpMessageDetail,
  DlpMessageList,
  DlpMessageListParams,
  DlpReviewActionRequest,
  DlpReviewActionResponse,
  DlpStatus,
  DlpTenantSettings,
  DlpTenantSettingsUpdate,
  PolicyDocument,
  PolicyVersion,
} from '@/lib/dlp/types'

const BASE = '/api/dlp/v2'

export async function getDlpStatus(): Promise<DlpStatus> {
  return (await api.get<DlpStatus>(`${BASE}/status`)).data
}

export async function getDlpSettings(): Promise<DlpTenantSettings> {
  return (await api.get<DlpTenantSettings>(`${BASE}/settings`)).data
}

export async function updateDlpSettings(
  payload: DlpTenantSettingsUpdate,
): Promise<DlpTenantSettings> {
  return (await api.put<DlpTenantSettings>(`${BASE}/settings`, payload)).data
}

export async function getActiveDlpPolicy(): Promise<PolicyVersion> {
  return (await api.get<PolicyVersion>(`${BASE}/policy`)).data
}

export async function getDlpPolicyDraft(): Promise<PolicyVersion | null> {
  return (await api.get<PolicyVersion | null>(`${BASE}/policy/draft`)).data
}

export async function saveDlpPolicyDraft(
  document: PolicyDocument,
): Promise<PolicyVersion> {
  return (await api.put<PolicyVersion>(`${BASE}/policy/draft`, { document })).data
}

export async function publishDlpPolicy(): Promise<PolicyVersion> {
  return (await api.post<PolicyVersion>(`${BASE}/policy/publish`)).data
}

export async function listDlpMessages(
  params: DlpMessageListParams = {},
): Promise<DlpMessageList> {
  const query: Record<string, string | number | boolean> = {}
  if (params.state) query.state = params.state
  if (params.reviewable === true) query.reviewable = true
  if (params.before) query.before = params.before
  if (params.limit != null) query.limit = params.limit
  return (await api.get<DlpMessageList>(`${BASE}/messages`, { params: query })).data
}

export async function getDlpMessage(
  messageId: string,
): Promise<DlpMessageDetail> {
  return (await api.get<DlpMessageDetail>(`${BASE}/messages/${messageId}`)).data
}

export async function releaseDlpMessage(
  messageId: string,
  payload: DlpReviewActionRequest,
): Promise<DlpReviewActionResponse> {
  return (
    await api.post<DlpReviewActionResponse>(
      `${BASE}/messages/${messageId}/release`,
      payload,
    )
  ).data
}

export async function stopDlpMessage(
  messageId: string,
  payload: DlpReviewActionRequest,
): Promise<DlpReviewActionResponse> {
  return (
    await api.post<DlpReviewActionResponse>(
      `${BASE}/messages/${messageId}/stop`,
      payload,
    )
  ).data
}

export function getDlpErrorMessage(
  error: unknown,
  fallback = 'The DLP request failed.',
): string {
  if (!(error instanceof AxiosError)) return fallback
  const data = error.response?.data as
    | { detail?: string | Array<{ msg?: string }> }
    | undefined
  if (typeof data?.detail === 'string') return data.detail
  if (Array.isArray(data?.detail)) {
    const details = data.detail
      .map((item) => item.msg)
      .filter((item): item is string => Boolean(item))
    if (details.length) return details.join(', ')
  }
  return error.message || fallback
}
