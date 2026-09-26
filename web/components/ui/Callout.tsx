import { AlertCircle, CheckCircle, AlertTriangle, Info } from 'lucide-react'
import clsx from 'clsx'

type CalloutType = 'info' | 'success' | 'warning' | 'error'

interface CalloutProps {
  type: CalloutType
  title?: string
  children: React.ReactNode
  className?: string
}

const calloutConfig: Record<CalloutType, { icon: React.ReactNode; borderColor: string; bgColor: string; titleColor: string }> = {
  info: {
    icon: <Info size={18} />,
    borderColor: 'border-medium',
    bgColor: 'bg-medium-bg',
    titleColor: 'text-medium',
  },
  success: {
    icon: <CheckCircle size={18} />,
    borderColor: 'border-low',
    bgColor: 'bg-low-bg',
    titleColor: 'text-low',
  },
  warning: {
    icon: <AlertTriangle size={18} />,
    borderColor: 'border-high',
    bgColor: 'bg-high-bg',
    titleColor: 'text-high',
  },
  error: {
    icon: <AlertCircle size={18} />,
    borderColor: 'border-critical',
    bgColor: 'bg-critical-bg',
    titleColor: 'text-critical',
  },
}

export function Callout({ type, title, children, className }: CalloutProps) {
  const config = calloutConfig[type]

  return (
    <div
      className={clsx(
        'border-l-2 rounded-r px-5 py-3.5',
        config.borderColor,
        config.bgColor,
        className,
      )}
    >
      {title && (
        <div className="flex items-center gap-2 mb-2">
          <div className={config.titleColor}>{config.icon}</div>
          <span className={clsx('text-label-sm', config.titleColor)}>{title}</span>
        </div>
      )}
      <div className="text-body-md text-sec">{children}</div>
    </div>
  )
}
