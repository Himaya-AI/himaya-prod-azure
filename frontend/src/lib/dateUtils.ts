import { format as dateFnsFormat } from 'date-fns'

/**
 * Safely format a date string or Date object.
 * Returns fallback if the date is invalid or null.
 */
export function safeFormat(
  dateInput: string | Date | null | undefined,
  formatStr: string,
  fallback: string = '—'
): string {
  if (!dateInput) return fallback
  
  try {
    const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput
    
    // Check for invalid date
    if (isNaN(date.getTime())) {
      return fallback
    }
    
    return dateFnsFormat(date, formatStr)
  } catch (e) {
    console.warn('Date formatting error:', e, dateInput)
    return fallback
  }
}

/**
 * Safely parse a date and return the Date object or null if invalid.
 */
export function safeParseDate(dateInput: string | Date | null | undefined): Date | null {
  if (!dateInput) return null
  
  try {
    const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput
    return isNaN(date.getTime()) ? null : date
  } catch {
    return null
  }
}
