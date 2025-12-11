/**
 * EMET Guardian Warning Modal
 *
 * Clean, professional security modal for high-risk transaction detection.
 * Designed with Linear/Stripe/1Password aesthetic principles.
 */

import React from 'react';

export interface WarningModalProps {
  reasons: string[];
  onCancel: () => void;
  onProceed: () => void;
}

// Helper to parse threat info from reason string
function parseThreatInfo(reason: string): { title: string; description: string } {
  const colonIndex = reason.indexOf(':');
  if (colonIndex > 0 && colonIndex < 40) {
    return {
      title: reason.substring(0, colonIndex).trim(),
      description: reason.substring(colonIndex + 1).trim(),
    };
  }
  return { title: 'SECURITY THREAT', description: reason };
}

// Clean, minimal inline styles
const styles = {
  overlay: {
    position: 'fixed' as const,
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    zIndex: 2147483647,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '20px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  modal: {
    maxWidth: '420px',
    width: '100%',
    backgroundColor: '#0a0a0a',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: '12px',
    boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4)',
    overflow: 'hidden',
  },
  header: {
    padding: '24px 24px 0',
    display: 'flex',
    alignItems: 'flex-start',
    gap: '16px',
  },
  iconContainer: {
    width: '40px',
    height: '40px',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '10px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  headerText: {
    flex: 1,
  },
  title: {
    fontSize: '16px',
    fontWeight: 600,
    color: '#fafafa',
    margin: '0 0 4px',
    letterSpacing: '-0.01em',
  },
  subtitle: {
    fontSize: '13px',
    color: '#ef4444',
    margin: 0,
    fontWeight: 500,
  },
  threatsList: {
    padding: '16px 24px',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
    maxHeight: '240px',
    overflowY: 'auto' as const,
  },
  threatItem: {
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    border: '1px solid rgba(255, 255, 255, 0.06)',
    borderRadius: '8px',
    padding: '12px',
  },
  threatTitle: {
    fontSize: '11px',
    fontWeight: 600,
    color: '#ef4444',
    letterSpacing: '0.5px',
    textTransform: 'uppercase' as const,
    marginBottom: '4px',
  },
  threatDesc: {
    fontSize: '13px',
    color: 'rgba(255, 255, 255, 0.7)',
    lineHeight: 1.4,
    margin: 0,
  },
  divider: {
    height: '1px',
    backgroundColor: 'rgba(255, 255, 255, 0.06)',
    margin: '0 24px',
  },
  actions: {
    padding: '16px 24px 24px',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  },
  cancelButton: {
    width: '100%',
    padding: '12px 16px',
    backgroundColor: '#fafafa',
    color: '#0a0a0a',
    border: 'none',
    borderRadius: '8px',
    fontSize: '14px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s ease',
  },
  proceedButton: {
    width: '100%',
    padding: '12px 16px',
    backgroundColor: 'transparent',
    color: 'rgba(255, 255, 255, 0.4)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: '8px',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s ease',
  },
  footer: {
    padding: '12px 24px',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    borderTop: '1px solid rgba(255, 255, 255, 0.06)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
  },
  footerText: {
    fontSize: '11px',
    color: 'rgba(255, 255, 255, 0.3)',
    letterSpacing: '0.02em',
  },
};

export const WarningModal: React.FC<WarningModalProps> = ({
  reasons,
  onCancel,
  onProceed,
}) => {
  const [cancelHovered, setCancelHovered] = React.useState(false);
  const [proceedHovered, setProceedHovered] = React.useState(false);

  // Prevent scrolling
  React.useEffect(() => {
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, []);

  // Block escape key
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener('keydown', handleKeyDown, true);
    return () => window.removeEventListener('keydown', handleKeyDown, true);
  }, []);

  return (
    <div style={styles.overlay} onClick={(e) => e.stopPropagation()}>
      <div style={styles.modal}>
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.iconContainer}>
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#ef4444"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="15" y1="9" x2="9" y2="15" />
              <line x1="9" y1="9" x2="15" y2="15" />
            </svg>
          </div>
          <div style={styles.headerText}>
            <h2 style={styles.title}>Transaction Blocked</h2>
            <p style={styles.subtitle}>
              {reasons.length} security {reasons.length === 1 ? 'threat' : 'threats'} detected
            </p>
          </div>
        </div>

        {/* Threats List */}
        <div style={styles.threatsList}>
          {reasons.map((reason, index) => {
            const { title, description } = parseThreatInfo(reason);
            return (
              <div key={index} style={styles.threatItem}>
                <div style={styles.threatTitle}>{title}</div>
                <p style={styles.threatDesc}>{description}</p>
              </div>
            );
          })}
        </div>

        {/* Divider */}
        <div style={styles.divider} />

        {/* Actions */}
        <div style={styles.actions}>
          <button
            style={{
              ...styles.cancelButton,
              backgroundColor: cancelHovered ? '#ffffff' : '#fafafa',
              transform: cancelHovered ? 'translateY(-1px)' : 'none',
            }}
            onClick={onCancel}
            onMouseEnter={() => setCancelHovered(true)}
            onMouseLeave={() => setCancelHovered(false)}
          >
            Reject Transaction
          </button>
          <button
            style={{
              ...styles.proceedButton,
              borderColor: proceedHovered ? 'rgba(255, 255, 255, 0.2)' : 'rgba(255, 255, 255, 0.1)',
              color: proceedHovered ? 'rgba(255, 255, 255, 0.6)' : 'rgba(255, 255, 255, 0.4)',
              backgroundColor: proceedHovered ? 'rgba(255, 255, 255, 0.03)' : 'transparent',
            }}
            onClick={onProceed}
            onMouseEnter={() => setProceedHovered(true)}
            onMouseLeave={() => setProceedHovered(false)}
          >
            Proceed anyway
          </button>
        </div>

        {/* Footer */}
        <div style={styles.footer}>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="rgba(255, 255, 255, 0.3)"
            strokeWidth="2"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span style={styles.footerText}>EMET Guardian</span>
        </div>
      </div>
    </div>
  );
};

/**
 * Render the warning modal to a container element
 */
export function renderWarningModal(
  container: HTMLElement,
  reasons: string[],
  onCancel: () => void,
  onProceed: () => void
): () => void {
  const React = require('react');
  const ReactDOM = require('react-dom/client');

  const root = ReactDOM.createRoot(container);
  root.render(
    React.createElement(WarningModal, {
      reasons,
      onCancel: () => {
        root.unmount();
        onCancel();
      },
      onProceed: () => {
        root.unmount();
        onProceed();
      },
    })
  );

  return () => root.unmount();
}

export default WarningModal;
