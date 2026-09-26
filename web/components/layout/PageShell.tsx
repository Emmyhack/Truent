import clsx from 'clsx'

interface PageShellProps {
  children: React.ReactNode
  /** 404 fills the viewport so its footer sits at the bottom. */
  fullHeight?: boolean
  className?: string
}

/**
 * The inset, rounded panel every marketing screen sits inside: a 10px gutter of
 * page background around a hairline-bordered card.
 */
export function PageShell({ children, fullHeight = false, className }: PageShellProps) {
  return (
    <div className="min-h-screen bg-bg p-2.5">
      <div
        className={clsx(
          'relative overflow-clip rounded-[22px] border border-hair bg-bg',
          fullHeight && 'flex min-h-[calc(100vh-20px)] flex-col',
          className,
        )}
      >
        {children}
      </div>
    </div>
  )
}
