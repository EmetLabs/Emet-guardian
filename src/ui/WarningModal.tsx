/**
 * EMET Guardian Warning Modal
 *
 * Full-screen blocking modal that displays when high-risk transactions are detected.
 * User MUST make a choice (Cancel or Proceed) - there is no dismiss/close option.
 *
 * SECURITY NOTE: This modal is the last line of defense before a potential drain.
 * The UI is intentionally alarming to ensure user attention.
 */

import React from 'react';

export interface WarningModalProps {
  reasons: string[];
  onCancel: () => void;
  onProceed: () => void;
}

// Inline styles to avoid CSS injection issues and ensure isolation
const styles = {
  overlay: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(139, 0, 0, 0.97)',
    zIndex: 2147483647, // Maximum z-index
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    justifyContent: 'center',
    padding: '20px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
    color: '#ffffff',
    overflow: 'auto',
  },
  container: {
    maxWidth: '600px',
    width: '100%',
    textAlign: 'center' as const,
  },
  iconContainer: {
    marginBottom: '20px',
  },
  icon: {
    width: '80px',
    height: '80px',
    margin: '0 auto',
    animation: 'pulse 1.5s ease-in-out infinite',
  },
  title: {
    fontSize: '36px',
    fontWeight: 'bold' as const,
    marginBottom: '16px',
    textShadow: '2px 2px 4px rgba(0, 0, 0, 0.5)',
    letterSpacing: '2px',
  },
  subtitle: {
    fontSize: '18px',
    marginBottom: '30px',
    opacity: 0.95,
    lineHeight: '1.5',
  },
  warningBox: {
    backgroundColor: 'rgba(0, 0, 0, 0.4)',
    borderRadius: '12px',
    padding: '24px',
    marginBottom: '30px',
    textAlign: 'left' as const,
    border: '2px solid rgba(255, 255, 255, 0.3)',
  },
  warningTitle: {
    fontSize: '16px',
    fontWeight: 'bold' as const,
    marginBottom: '16px',
    color: '#ffcccc',
    textTransform: 'uppercase' as const,
    letterSpacing: '1px',
  },
  reasonsList: {
    listStyle: 'none',
    padding: 0,
    margin: 0,
  },
  reasonItem: {
    padding: '12px 16px',
    marginBottom: '12px',
    backgroundColor: 'rgba(255, 0, 0, 0.2)',
    borderRadius: '8px',
    borderLeft: '4px solid #ff4444',
    fontSize: '14px',
    lineHeight: '1.6',
  },
  drainWarning: {
    backgroundColor: 'rgba(255, 200, 0, 0.15)',
    border: '1px solid rgba(255, 200, 0, 0.5)',
    borderRadius: '8px',
    padding: '16px',
    marginBottom: '30px',
    fontSize: '15px',
    lineHeight: '1.6',
  },
  drainWarningIcon: {
    display: 'inline-block',
    marginRight: '8px',
  },
  buttonContainer: {
    display: 'flex',
    gap: '16px',
    justifyContent: 'center',
    flexWrap: 'wrap' as const,
  },
  cancelButton: {
    backgroundColor: '#ffffff',
    color: '#8B0000',
    border: 'none',
    borderRadius: '8px',
    padding: '16px 48px',
    fontSize: '18px',
    fontWeight: 'bold' as const,
    cursor: 'pointer',
    transition: 'transform 0.2s, box-shadow 0.2s',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
  },
  proceedButton: {
    backgroundColor: 'transparent',
    color: 'rgba(255, 255, 255, 0.7)',
    border: '1px solid rgba(255, 255, 255, 0.3)',
    borderRadius: '8px',
    padding: '16px 32px',
    fontSize: '14px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  footer: {
    marginTop: '30px',
    fontSize: '12px',
    opacity: 0.6,
  },
};

// CSS keyframes for the pulse animation
const keyframesStyle = `
  @keyframes emet-pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
  }
  @keyframes emet-shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
    20%, 40%, 60%, 80% { transform: translateX(5px); }
  }
`;

export const WarningModal: React.FC<WarningModalProps> = ({
  reasons,
  onCancel,
  onProceed,
}) => {
  const [proceedHovered, setProceedHovered] = React.useState(false);
  const [cancelHovered, setCancelHovered] = React.useState(false);

  // Inject keyframes into document
  React.useEffect(() => {
    const styleEl = document.createElement('style');
    styleEl.textContent = keyframesStyle;
    document.head.appendChild(styleEl);
    return () => {
      document.head.removeChild(styleEl);
    };
  }, []);

  // Prevent scrolling on the body while modal is open
  React.useEffect(() => {
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, []);

  // Block keyboard shortcuts that might dismiss the modal
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Block Escape key
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener('keydown', handleKeyDown, true);
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true);
    };
  }, []);

  return (
    <div style={styles.overlay} onClick={(e) => e.stopPropagation()}>
      <div style={styles.container}>
        {/* Warning Icon */}
        <div style={styles.iconContainer}>
          <svg
            style={{
              ...styles.icon,
              animation: 'emet-pulse 1.5s ease-in-out infinite',
            }}
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M12 2L1 21h22L12 2z"
              fill="#ff4444"
              stroke="#ffffff"
              strokeWidth="1"
            />
            <path
              d="M12 9v5M12 16v2"
              stroke="#ffffff"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </div>

        {/* Title */}
        <h1 style={styles.title}>HIGH-RISK TRANSACTION</h1>

        {/* Subtitle */}
        <p style={styles.subtitle}>
          EMET Guardian has detected potentially dangerous patterns in this transaction.
          <br />
          <strong>Your wallet may be drained if you proceed.</strong>
        </p>

        {/* Reasons Box */}
        <div style={styles.warningBox}>
          <div style={styles.warningTitle}>Detected Threats:</div>
          <ul style={styles.reasonsList}>
            {reasons.map((reason, index) => (
              <li key={index} style={styles.reasonItem}>
                {reason}
              </li>
            ))}
          </ul>
        </div>

        {/* Drain Warning */}
        <div style={styles.drainWarning}>
          <span style={styles.drainWarningIcon}>&#9888;</span>
          <strong>WARNING:</strong> Signing this transaction could result in the permanent loss
          of all tokens in the affected accounts. Wallet drains are irreversible.
          If you did not explicitly request this action, this is likely a scam.
        </div>

        {/* Buttons */}
        <div style={styles.buttonContainer}>
          <button
            style={{
              ...styles.cancelButton,
              transform: cancelHovered ? 'scale(1.05)' : 'scale(1)',
              boxShadow: cancelHovered
                ? '0 6px 20px rgba(0, 0, 0, 0.4)'
                : '0 4px 12px rgba(0, 0, 0, 0.3)',
            }}
            onClick={onCancel}
            onMouseEnter={() => setCancelHovered(true)}
            onMouseLeave={() => setCancelHovered(false)}
          >
            &#10005; Cancel Transaction
          </button>

          <button
            style={{
              ...styles.proceedButton,
              backgroundColor: proceedHovered ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
              color: proceedHovered ? 'rgba(255, 255, 255, 0.9)' : 'rgba(255, 255, 255, 0.7)',
            }}
            onClick={onProceed}
            onMouseEnter={() => setProceedHovered(true)}
            onMouseLeave={() => setProceedHovered(false)}
          >
            I understand the risks, proceed anyway
          </button>
        </div>

        {/* Footer */}
        <div style={styles.footer}>
          EMET Guardian v1.0 | This is a security warning, not financial advice.
          <br />
          Always verify transactions independently.
        </div>
      </div>
    </div>
  );
};

/**
 * Render the warning modal to a container element
 * Used by the injection script to display the modal
 */
export function renderWarningModal(
  container: HTMLElement,
  reasons: string[],
  onCancel: () => void,
  onProceed: () => void
): () => void {
  // Dynamic import of ReactDOM to avoid bundling issues
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

  // Return cleanup function
  return () => {
    root.unmount();
  };
}

export default WarningModal;
