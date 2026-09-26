import { ReactNode } from 'react'
import clsx from 'clsx'

type ButtonVariant = 'primary' | 'secondary' | 'ghost'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md' | 'lg'
  children: ReactNode
  icon?: ReactNode
  iconPosition?: 'left' | 'right'
  fullWidth?: boolean
}

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    'bg-acc text-on-acc border border-acc hover:bg-acc-text active:bg-acc-text',
  secondary:
    'bg-transparent border border-hair text-sec hover:border-brand hover:text-text',
  ghost: 'bg-transparent border-0 text-sec hover:text-text',
}

const sizeStyles: Record<string, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
}

export function Button({
  variant = 'primary',
  size = 'md',
  children,
  icon,
  iconPosition = 'left',
  fullWidth = false,
  className,
  ...props
}: ButtonProps) {
  return (
    <button
      className={clsx(
        'font-[600] rounded transition-colors duration-150 cursor-pointer',
        'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
        'disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none',
        variantStyles[variant],
        sizeStyles[size],
        fullWidth && 'w-full',
        'flex items-center justify-center gap-2',
        className,
      )}
      {...props}
    >
      {icon && iconPosition === 'left' && <span className="flex items-center">{icon}</span>}
      {children}
      {icon && iconPosition === 'right' && <span className="flex items-center">{icon}</span>}
    </button>
  )
}
