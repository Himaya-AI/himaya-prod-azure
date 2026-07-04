'use client'
import { ButtonHTMLAttributes, forwardRef } from 'react'
import { clsx } from 'clsx'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline'
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, disabled, ...props }, ref) => {
    const base = 'inline-flex items-center justify-center font-medium rounded-[var(--radius-md)] transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--background)] disabled:opacity-50 disabled:cursor-not-allowed'
    const variants = {
      primary: 'bg-gradient-to-b from-[#4a7eff] to-[var(--accent)] hover:from-[#5a8aff] hover:to-[var(--accent-hover)] text-white shadow-sm hover:shadow-md focus:ring-[var(--accent)]',
      secondary: 'bg-[var(--card)] hover:bg-[var(--card-hover)] text-[var(--foreground)] border border-[var(--border)] hover:border-[var(--border-strong)] focus:ring-[var(--accent)]',
      danger: 'bg-[var(--danger)] hover:bg-red-600 text-white focus:ring-[var(--danger)]',
      ghost: 'bg-transparent hover:bg-[var(--accent-subtle)] text-[var(--muted)] hover:text-[var(--foreground)]',
      outline: 'border border-[var(--border)] bg-transparent hover:bg-[var(--accent-subtle)] text-[var(--foreground)] hover:border-[var(--accent)]',
    }
    const sizes = {
      sm: 'text-[12px] px-3 py-1.5 gap-1.5',
      md: 'text-[13px] px-4 py-2 gap-2',
      lg: 'text-[14px] px-5 py-2.5 gap-2',
    }
    return (
      <button
        ref={ref}
        className={clsx(base, variants[variant], sizes[size], className)}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        )}
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'
export default Button
