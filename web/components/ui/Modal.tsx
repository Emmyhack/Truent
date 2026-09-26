'use client'

import { X } from 'lucide-react'
import clsx from 'clsx'
import { useEscapeKey } from '@/components/hooks/useEscapeKey'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  size?: 'sm' | 'md' | 'lg'
}

const sizeStyles: Record<string, string> = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-2xl',
}

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  size = 'md',
}: ModalProps) {
  useEscapeKey(isOpen, onClose)

  if (!isOpen) return null

  return (
    <div
      className="fixed inset-0 bg-overlay backdrop-blur-sm z-50 flex items-center justify-center p-6"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        className={clsx(
          'bg-panel border border-hair rounded-lg w-full',
          sizeStyles[size],
          'max-h-[90vh] overflow-y-auto',
          'flex flex-col',
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-6 border-b border-hair">
          <h2 id="modal-title" className="text-headline-md text-text">{title}</h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-sec hover:text-text transition-colors p-2 -m-1"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {children}
        </div>
      </div>
    </div>
  )
}
