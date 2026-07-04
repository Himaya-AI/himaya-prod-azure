import { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from 'react'
import { clsx } from 'clsx'

export function Table({ className, children, ...props }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={clsx('w-full text-sm', className)} {...props}>
        {children}
      </table>
    </div>
  )
}

export function Thead({ className, children, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead className={clsx('border-b border-[#0f3460]/50', className)} {...props}>
      {children}
    </thead>
  )
}

export function Tbody({ className, children, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tbody className={clsx('divide-y divide-[#0f3460]/30', className)} {...props}>
      {children}
    </tbody>
  )
}

export function Tr({ className, children, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr className={clsx('hover:bg-[#0f3460]/20 transition-colors', className)} {...props}>
      {children}
    </tr>
  )
}

export function Th({ className, children, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={clsx('px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider', className)} {...props}>
      {children}
    </th>
  )
}

export function Td({ className, children, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={clsx('px-4 py-3 text-slate-300', className)} {...props}>
      {children}
    </td>
  )
}
