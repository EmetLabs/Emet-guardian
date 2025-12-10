/**
 * Content Script - EMET Guardian
 *
 * This script runs in the content script context (isolated from page).
 * Its sole responsibility is to inject the phantomHook.ts script into
 * the page context where it can access window.solana.
 *
 * SECURITY NOTES:
 * - Content scripts run in an isolated world
 * - To intercept Phantom, we must inject into the main world
 * - Injection must happen BEFORE any dApp JavaScript runs
 * - We use document_start to ensure early injection
 */

(function injectEmetGuardian() {
  'use strict';

  // Prevent double-injection in this content script context
  if ((window as any).__EMET_CONTENT_INJECTED__) {
    return;
  }
  (window as any).__EMET_CONTENT_INJECTED__ = true;

  /**
   * Inject the hook script into the page's main world
   * This is necessary because content scripts cannot access window.solana
   */
  function injectScript() {
    try {
      // Get the URL of our compiled hook script
      const scriptUrl = chrome.runtime.getURL('phantomHook.js');

      // Create a script element that loads our hook
      const script = document.createElement('script');
      script.src = scriptUrl;
      script.type = 'text/javascript';

      // Use async=false to ensure synchronous loading
      // This is critical - the hook must be in place before any dApp code runs
      script.async = false;

      // Inject at the earliest possible point
      const target = document.head || document.documentElement;

      // Insert as the first child to run before other scripts
      if (target.firstChild) {
        target.insertBefore(script, target.firstChild);
      } else {
        target.appendChild(script);
      }

      // Clean up the script tag after it loads (optional, for cleanliness)
      script.onload = () => {
        // Keep the script for debugging purposes
        // script.remove();
        console.log('[EMET Content] Hook script loaded successfully');
      };

      script.onerror = (error) => {
        console.error('[EMET Content] Failed to load hook script:', error);
      };

    } catch (error) {
      console.error('[EMET Content] Script injection failed:', error);
    }
  }

  // Inject immediately - we're running at document_start
  injectScript();

  /**
   * Alternative injection method using inline script
   * Fallback in case external script loading fails
   */
  function injectInlineScript() {
    try {
      const script = document.createElement('script');
      script.textContent = `
        // Minimal inline hook for fallback
        (function() {
          if (window.__EMET_GUARDIAN_INSTALLED__) return;
          console.log('[EMET] Inline fallback active - waiting for main hook');
        })();
      `;
      const target = document.head || document.documentElement;
      if (target.firstChild) {
        target.insertBefore(script, target.firstChild);
      } else {
        target.appendChild(script);
      }
      script.remove();
    } catch (e) {
      // Silent fail for CSP-restricted pages
    }
  }

  // Try inline injection as well for redundancy
  injectInlineScript();

  /**
   * Listen for messages from the injected script
   * This allows the hook to communicate with the extension if needed
   */
  window.addEventListener('message', (event) => {
    // Only accept messages from our own window
    if (event.source !== window) return;

    // Check for EMET Guardian messages
    if (event.data?.type === 'EMET_GUARDIAN_LOG') {
      console.log('[EMET Extension]', event.data.message);
    }

    if (event.data?.type === 'EMET_GUARDIAN_ALERT') {
      // Could forward to background script for logging/telemetry
      // Currently just log locally
      console.warn('[EMET Extension] Alert:', event.data.message);
    }
  });

  /**
   * Expose a method for the page script to check if extension is active
   * This is done via a custom event
   */
  document.addEventListener('EMET_GUARDIAN_PING', () => {
    document.dispatchEvent(new CustomEvent('EMET_GUARDIAN_PONG', {
      detail: { version: '1.0.0', active: true }
    }));
  });

  console.log('[EMET Content] Content script initialized');
})();
