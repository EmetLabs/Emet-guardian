/**
 * Background Service Worker - EMET Guardian
 *
 * Minimal background script for the extension.
 * Currently handles extension lifecycle events.
 *
 * Future enhancements could include:
 * - Analytics/telemetry (opt-in)
 * - Blocklist updates
 * - Cross-tab coordination
 */

// Log extension startup
console.log('[EMET Guardian] Background service worker started');

/**
 * Handle extension installation
 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[EMET Guardian] Extension installed');

    // Could open a welcome page here
    // chrome.tabs.create({ url: 'welcome.html' });
  } else if (details.reason === 'update') {
    console.log('[EMET Guardian] Extension updated to version', chrome.runtime.getManifest().version);
  }
});

/**
 * Handle messages from content scripts or popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[EMET Guardian] Message received:', message, 'from:', sender.tab?.url);

  if (message.type === 'EMET_LOG') {
    // Log events from content scripts
    console.log('[EMET Log]', message.data);
    sendResponse({ success: true });
  }

  if (message.type === 'EMET_BLOCKED_TX') {
    // Record blocked transaction event
    console.warn('[EMET Guardian] Blocked transaction:', message.data);
    sendResponse({ success: true });
  }

  if (message.type === 'EMET_ALLOWED_RISKY_TX') {
    // Record when user proceeds despite warning
    console.warn('[EMET Guardian] User proceeded with risky tx:', message.data);
    sendResponse({ success: true });
  }

  // Return true to indicate async response
  return true;
});

/**
 * Handle extension icon click
 */
chrome.action.onClicked.addListener((tab) => {
  console.log('[EMET Guardian] Extension icon clicked');

  // Show a simple notification that the extension is active
  if (tab.id) {
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // Check if our hook is installed
        const isActive = (window as any).__EMET_GUARDIAN_INSTALLED__;
        const message = isActive
          ? 'EMET Guardian is active and protecting this page.'
          : 'EMET Guardian is installed but Phantom was not detected on this page.';

        alert(message);
      },
    }).catch(err => {
      console.error('[EMET Guardian] Failed to check status:', err);
    });
  }
});

/**
 * Keep service worker alive (optional, for persistent logging)
 * Note: Chrome MV3 service workers are ephemeral by design
 */
chrome.alarms?.create('keepalive', { periodInMinutes: 1 });
chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepalive') {
    console.log('[EMET Guardian] Service worker heartbeat');
  }
});

// Export empty object for module compliance
export {};
