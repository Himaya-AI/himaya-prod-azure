import { InputHTMLAttributes, forwardRef } from 'react'
import { clsx } from 'clsx'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, id, ...props }, ref) => {
    return (
      <div className="space-y-1.5">
        {label && (
          <label
            htmlFor={id}
            className="block text-sm font-medium text-[var(--foreground)] opacity-80"
          >
            {label}
          </label>
        )}
        <input
          ref={ref}
          id={id}
          className={clsx(
            'w-full px-3 py-2 rounded-lg text-sm transition-colors duration-200',
            'bg-[var(--input-bg,#1a1a2e)] border text-[var(--foreground)]',
            'placeholder-[var(--muted)]',
            'focus:outline-none focus:ring-2 focus:ring-[#3b6ef6] focus:border-transparent',
            error
              ? 'border-red-500'
              : 'border-[var(--border)]',
            className
          )}
          {...props}
        />
        {error && <p className="text-xs text-red-400">{error}</p>}
      </div>
    )
  }
)
Input.displayName = 'Input'
export default Input
