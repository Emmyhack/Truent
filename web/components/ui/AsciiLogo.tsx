interface AsciiLogoProps {
  className?: string
  glow?: boolean
}

const LOGO = `████████╗██████╗ ██╗   ██╗███████╗███╗   ██╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝████╗  ██║╚══██╔══╝
   ██║   ██████╔╝██║   ██║█████╗  ██╔██╗ ██║   ██║   
   ██║   ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   `

/** Shared so the particle hero rasterises exactly what the footer renders. */
export const TRUENT_ASCII = LOGO

export function AsciiLogo({ className, glow = false }: AsciiLogoProps) {
  const baseClasses = 'font-mono leading-[1.05] whitespace-pre select-none'
  const colorClasses = glow ? 'text-acc-text drop-shadow-[0_0_24px_var(--acc-soft)]' : 'text-acc-text'
  const finalClassName = `${baseClasses} ${colorClasses} ${className || ''}`

  return (
    <pre
      className={finalClassName}
      aria-label="Truent"
      role="img"
    >
      {LOGO}
    </pre>
  )
}
