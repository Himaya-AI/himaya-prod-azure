import { HTMLAttributes } from 'react'
import { clsx } from 'clsx'

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  noPadding?: boolean
  elevated?: boolean
}

export function Card({ className, noPadding, elevated, children, ...props }: CardProps) {
  return (
    <div
      className={clsx(
        'bg-[var(--card)] border border-[var(--border)] rounded-[var(--radius-lg)] transition-all duration-150',
        elevated && 'shadow-[var(--shadow-card)] hover:shadow-[var(--shadow-elevated)] hover:border-[var(--border-strong)]',
        !noPadding && 'p-5',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export function CardHeader({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={clsx('flex items-center justify-between mb-4', className)} {...props}>
      {children}
    </div>
  )
}

export function CardTitle({ className, children, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3 className={clsx('text-[14px] font-semibold text-[var(--foreground)]', className)} {...props}>
      {children}
    </h3>
  )
}
