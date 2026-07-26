export const DLP_DETECTORS = [
  { value: 'credential', label: 'Credentials' },
  { value: 'pii', label: 'PII' },
  { value: 'lexicon', label: 'Confidential terms' },
] as const

export const DLP_ENTITY_TYPES = [
  'CREDIT_CARD',
  'IBAN_CODE',
  'US_BANK_NUMBER',
  'US_SSN',
  'US_PASSPORT',
  'US_DRIVER_LICENSE',
  'UK_NHS',
  'UK_NINO',
  'IN_AADHAAR',
  'IN_PAN',
] as const

export const DLP_LLM_CLASSIFICATIONS = [
  'SENSITIVE',
  'UNCERTAIN',
] as const
