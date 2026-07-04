import { HTMLAttributes } from 'react'
import { clsx } from 'clsx'

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'neutral'
}

export function Badge({ className, variant = 'default', children, ...props }: BadgeProps) {
  const variants = {
    default:  'bg-white/[0.06] text-[#a1a1aa]',
    success:  'bg-white/[0.05] text-[#71717a] ring-1 ring-white/10',
    warning:  'bg-white/[0.05] text-[#a1a1aa] ring-1 ring-white/10',
    danger:   'bg-white/[0.05] text-[#f87171] ring-1 ring-white/[0.08]',
    info:     'bg-[#3b6ef6]/10 text-[#93b4fd] ring-1 ring-[#3b6ef6]/20',
    neutral:  'bg-white/[0.04] text-[#71717a]',
  }
  return (
    <span
      className={clsx('inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium tracking-wide', variants[variant], className)}
      {...props}
    >
      {children}
    </span>
  )
}
