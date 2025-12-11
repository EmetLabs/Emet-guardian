/**
 * Phantom Wallet Hook - EMET Guardian
 *
 * This script is injected into the page context to intercept Phantom wallet
 * signing methods BEFORE they execute. It monkey-patches the Phantom provider
 * to add security analysis.
 *
 * SECURITY NOTES:
 * - This runs in the page context, not the extension context
 * - We cannot trust any page-provided data
 * - The hook must be installed before any dApp code runs
 * - Malicious pages may attempt to bypass or disable this hook
 */

// Self-executing function to avoid polluting global namespace
(function EMET_GUARDIAN_HOOK() {
  'use strict';

  // Prevent double-injection
  if ((window as any).__EMET_GUARDIAN_INSTALLED__) {
    return;
  }
  (window as any).__EMET_GUARDIAN_INSTALLED__ = true;

  console.log('[EMET Guardian] Initializing wallet security hook...');

  // ============================================================
  // DECODER AND RISK RULES (INLINED FOR PAGE CONTEXT)
  // ============================================================

  const SPL_TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

  const SPL_TOKEN_INSTRUCTIONS = {
    TRANSFER: 3,
    APPROVE: 4,
    SET_AUTHORITY: 6,
    CLOSE_ACCOUNT: 9,
    TRANSFER_CHECKED: 12,
    APPROVE_CHECKED: 13,
  } as const;

  const AUTHORITY_TYPES: Record<number, string> = {
    0: 'MintTokens',
    1: 'FreezeAccount',
    2: 'AccountOwner',
    3: 'CloseAccount',
  };

  const MAX_U64 = BigInt('18446744073709551615');
  const UNLIMITED_THRESHOLD = MAX_U64 * BigInt(999) / BigInt(1000);

  const SAFE_PROGRAM_IDS = new Set([
    SPL_TOKEN_PROGRAM_ID,
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
    '11111111111111111111111111111111',
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
    'ComputeBudget111111111111111111111111111111',
    'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',
    'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
    'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',
    'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK',
    'srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX',
    'LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo',
  ]);

  interface DecodedInstruction {
    program: string;
    type: string;
    source?: string;
    destination?: string;
    authority?: string;
    newAuthority?: string;
    authorityType?: string;
    amount?: bigint;
    accounts?: string[];
    programId?: string;
  }

  // Base58 encoding/decoding
  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function encodeBase58(bytes: Uint8Array): string {
    if (bytes.length === 0) return '';
    let zeros = 0;
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) zeros++;
    const result: number[] = [];
    let num = BigInt(0);
    for (const byte of bytes) num = num * BigInt(256) + BigInt(byte);
    while (num > 0) {
      result.unshift(Number(num % BigInt(58)));
      num = num / BigInt(58);
    }
    for (let i = 0; i < zeros; i++) result.unshift(0);
    return result.map(i => BASE58_ALPHABET[i]).join('');
  }

  function readUint64LE(data: Uint8Array, offset: number): bigint {
    let result = BigInt(0);
    for (let i = 0; i < 8; i++) {
      result |= BigInt(data[offset + i] ?? 0) << BigInt(i * 8);
    }
    return result;
  }

  function readCompactU16(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
    let value = 0;
    let bytesRead = 0;
    for (let i = 0; i < 3; i++) {
      const byte = data[offset + i];
      value |= (byte & 0x7f) << (i * 7);
      bytesRead++;
      if ((byte & 0x80) === 0) break;
    }
    return { value, bytesRead };
  }

  function decodeInstruction(programId: string, data: Uint8Array, accounts: string[]): DecodedInstruction {
    if (programId !== SPL_TOKEN_PROGRAM_ID) {
      return { program: 'unknown', type: 'unknown', programId, accounts };
    }
    if (data.length === 0) {
      return { program: 'spl-token', type: 'unknown' };
    }

    const instructionType = data[0];

    switch (instructionType) {
      case SPL_TOKEN_INSTRUCTIONS.TRANSFER:
      case SPL_TOKEN_INSTRUCTIONS.TRANSFER_CHECKED: {
        const isChecked = instructionType === SPL_TOKEN_INSTRUCTIONS.TRANSFER_CHECKED;
        if (data.length < (isChecked ? 10 : 9)) {
          return { program: 'spl-token', type: 'transfer' };
        }
        return {
          program: 'spl-token',
          type: 'transfer',
          source: accounts[0],
          destination: isChecked ? accounts[2] : accounts[1],
          authority: isChecked ? accounts[3] : accounts[2],
          amount: readUint64LE(data, 1),
        };
      }

      case SPL_TOKEN_INSTRUCTIONS.APPROVE:
      case SPL_TOKEN_INSTRUCTIONS.APPROVE_CHECKED: {
        const isChecked = instructionType === SPL_TOKEN_INSTRUCTIONS.APPROVE_CHECKED;
        if (data.length < (isChecked ? 10 : 9)) {
          return { program: 'spl-token', type: 'approve' };
        }
        return {
          program: 'spl-token',
          type: 'approve',
          source: accounts[0],
          destination: isChecked ? accounts[2] : accounts[1],
          authority: isChecked ? accounts[3] : accounts[2],
          amount: readUint64LE(data, 1),
        };
      }

      case SPL_TOKEN_INSTRUCTIONS.SET_AUTHORITY: {
        if (data.length < 3 || accounts.length < 2) {
          return { program: 'spl-token', type: 'setAuthority' };
        }
        const authorityTypeNum = data[1];
        const hasNewAuthority = data[2] === 1;
        let newAuthority: string | undefined;
        if (hasNewAuthority && data.length >= 35) {
          newAuthority = encodeBase58(data.slice(3, 35));
        }
        return {
          program: 'spl-token',
          type: 'setAuthority',
          source: accounts[0],
          authority: accounts[1],
          authorityType: AUTHORITY_TYPES[authorityTypeNum] || `Unknown(${authorityTypeNum})`,
          newAuthority,
        };
      }

      case SPL_TOKEN_INSTRUCTIONS.CLOSE_ACCOUNT: {
        if (accounts.length < 3) {
          return { program: 'spl-token', type: 'close' };
        }
        return {
          program: 'spl-token',
          type: 'close',
          source: accounts[0],
          destination: accounts[1],
          authority: accounts[2],
        };
      }

      default:
        return { program: 'spl-token', type: 'unknown' };
    }
  }

  function analyzeSerializedTransaction(serializedTx: Uint8Array): {
    instructions: DecodedInstruction[];
    affectedAccounts: Set<string>;
  } {
    const instructions: DecodedInstruction[] = [];
    const affectedAccounts = new Set<string>();

    try {
      let offset = 0;

      // Handle both signed and unsigned transactions
      const firstByte = serializedTx[0];
      // Check if this looks like a signature count (0-127 signatures)
      if (firstByte <= 127 && serializedTx.length > 1 + firstByte * 64) {
        offset = 1 + firstByte * 64;
      }

      // If offset went past the buffer or seems wrong, try from start
      if (offset >= serializedTx.length - 10) {
        offset = 0;
      }

      // Message header
      offset += 3; // Skip header bytes

      // Read account keys
      const { value: numAccounts, bytesRead: ab } = readCompactU16(serializedTx, offset);
      offset += ab;

      const accountKeys: string[] = [];
      for (let i = 0; i < numAccounts; i++) {
        if (offset + 32 > serializedTx.length) break;
        accountKeys.push(encodeBase58(serializedTx.slice(offset, offset + 32)));
        offset += 32;
      }

      // Skip recent blockhash
      offset += 32;

      // Read instructions
      const { value: numInstructions, bytesRead: ib } = readCompactU16(serializedTx, offset);
      offset += ib;

      for (let i = 0; i < numInstructions; i++) {
        if (offset >= serializedTx.length) break;

        const programIdIndex = serializedTx[offset++];
        const { value: numAccts, bytesRead: nab } = readCompactU16(serializedTx, offset);
        offset += nab;

        const accountIndices: number[] = [];
        for (let j = 0; j < numAccts; j++) {
          if (offset < serializedTx.length) {
            accountIndices.push(serializedTx[offset++]);
          }
        }

        const { value: dataLen, bytesRead: dlb } = readCompactU16(serializedTx, offset);
        offset += dlb;

        const data = serializedTx.slice(offset, offset + dataLen);
        offset += dataLen;

        const accounts = accountIndices.map(idx => accountKeys[idx] || `unknown_${idx}`);
        const programId = accountKeys[programIdIndex] || `unknown_${programIdIndex}`;

        accounts.forEach(acc => affectedAccounts.add(acc));
        instructions.push(decodeInstruction(programId, data, accounts));
      }
    } catch (e) {
      console.error('[EMET] Transaction parse error:', e);
    }

    return { instructions, affectedAccounts };
  }

  function assessRisk(
    instructions: DecodedInstruction[],
    affectedAccounts: Set<string>,
    userWallet: string
  ): { isHighRisk: boolean; reasons: string[] } {
    const reasons: string[] = [];
    const splInstructions = instructions.filter(ix => ix.program === 'spl-token');

    // Rule 1: Unlimited approval
    for (const ix of splInstructions) {
      if (ix.type === 'approve' && ix.amount !== undefined) {
        if (ix.amount >= UNLIMITED_THRESHOLD) {
          reasons.push(
            `UNLIMITED TOKEN APPROVAL: Granting unlimited spending to ${truncateAddr(ix.destination)}. ` +
            `This allows draining ALL tokens from this account at any time.`
          );
        }
      }
    }

    // Rule 2: Authority transfer
    for (const ix of splInstructions) {
      if (ix.type === 'setAuthority') {
        if (ix.authority === userWallet && ix.newAuthority && ix.newAuthority !== userWallet) {
          reasons.push(
            `AUTHORITY TRANSFER: Transferring ${ix.authorityType || 'account'} control ` +
            `to ${truncateAddr(ix.newAuthority)}. You will lose control.`
          );
        }
        if (ix.authority === userWallet && !ix.newAuthority) {
          reasons.push(
            `AUTHORITY REVOCATION: Permanently removing ${ix.authorityType || 'account'} control. ` +
            `This is irreversible.`
          );
        }
      }
    }

    // Rule 3: Multi-account operations
    const tokenAccounts = new Set<string>();
    splInstructions.forEach(ix => { if (ix.source) tokenAccounts.add(ix.source); });
    if (tokenAccounts.size >= 3) {
      reasons.push(
        `MULTI-ACCOUNT ATTACK: Transaction affects ${tokenAccounts.size} token accounts. ` +
        `Drain attacks often batch multiple accounts.`
      );
    }

    // Rule 4: Unknown program with user wallet
    for (const ix of instructions) {
      if (ix.program === 'unknown' && ix.programId && !SAFE_PROGRAM_IDS.has(ix.programId)) {
        if (ix.accounts?.includes(userWallet)) {
          reasons.push(
            `UNKNOWN PROGRAM: Unverified program ${truncateAddr(ix.programId)} ` +
            `interacting with your wallet.`
          );
        }
      }
    }

    // Rule 5: Drain pattern (approve/setAuthority + transfer/close)
    const hasApprove = splInstructions.some(ix => ix.type === 'approve');
    const hasSetAuth = splInstructions.some(ix => ix.type === 'setAuthority');
    const hasTransferOrClose = splInstructions.some(ix => ix.type === 'transfer' || ix.type === 'close');

    if ((hasApprove || hasSetAuth) && hasTransferOrClose) {
      const suspicious = splInstructions.some(ix =>
        (ix.type === 'transfer' || ix.type === 'close') &&
        ix.destination && ix.destination !== userWallet
      );
      if (suspicious) {
        reasons.push(
          `DRAIN PATTERN: Combines permission grants with transfers to external addresses. ` +
          `This is a common wallet drain technique.`
        );
      }
    }

    // Rule 6: Suspicious close
    for (const ix of splInstructions) {
      if (ix.type === 'close' && ix.destination && ix.destination !== userWallet) {
        reasons.push(
          `SUSPICIOUS CLOSURE: Closing account and sending rent to ${truncateAddr(ix.destination)} ` +
          `instead of your wallet.`
        );
      }
    }

    return { isHighRisk: reasons.length > 0, reasons };
  }

  function truncateAddr(addr?: string): string {
    if (!addr) return 'unknown';
    if (addr.length <= 12) return addr;
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
  }

  // ============================================================
  // WARNING MODAL (PURE DOM, NO REACT IN PAGE CONTEXT)
  // Premium UX based on MetaMask, Ledger, and fintech best practices
  // ============================================================

  // Helper to parse threat info from reason string
  function parseThreatInfo(reason: string): { title: string; description: string } {
    const colonIndex = reason.indexOf(':');

    if (colonIndex > 0 && colonIndex < 40) {
      const title = reason.substring(0, colonIndex).trim();
      const description = reason.substring(colonIndex + 1).trim();
      return { title, description };
    }
    return { title: 'SECURITY THREAT', description: reason };
  }

  function showWarningModal(reasons: string[]): Promise<'cancel' | 'proceed'> {
    return new Promise((resolve) => {
      // Create overlay - clean, minimal backdrop
      const container = document.createElement('div');
      container.id = 'emet-guardian-modal';
      container.style.cssText = `
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.85);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        opacity: 0;
        transition: opacity 0.2s ease;
      `;

      // Modal Card - clean, solid, professional
      const modal = document.createElement('div');
      modal.style.cssText = `
        position: relative;
        max-width: 420px;
        width: 100%;
        background: #0a0a0a;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        box-shadow: 0 24px 48px rgba(0, 0, 0, 0.4);
        transform: translateY(8px);
        transition: transform 0.2s ease;
        overflow: hidden;
      `;

      // Header section with icon
      const header = document.createElement('div');
      header.style.cssText = `
        padding: 24px 24px 0;
        display: flex;
        align-items: flex-start;
        gap: 16px;
      `;

      // Shield icon with X
      const iconContainer = document.createElement('div');
      iconContainer.style.cssText = `
        width: 40px;
        height: 40px;
        background: rgba(239, 68, 68, 0.1);
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      `;
      iconContainer.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
      `;

      const headerText = document.createElement('div');
      headerText.style.cssText = `flex: 1;`;

      const title = document.createElement('h2');
      title.textContent = 'Transaction Blocked';
      title.style.cssText = `
        font-size: 16px;
        font-weight: 600;
        color: #fafafa;
        margin: 0 0 4px;
        letter-spacing: -0.01em;
      `;

      const subtitle = document.createElement('p');
      subtitle.textContent = `${reasons.length} security ${reasons.length === 1 ? 'threat' : 'threats'} detected`;
      subtitle.style.cssText = `
        font-size: 13px;
        color: #ef4444;
        margin: 0;
        font-weight: 500;
      `;

      headerText.appendChild(title);
      headerText.appendChild(subtitle);
      header.appendChild(iconContainer);
      header.appendChild(headerText);

      // Threat list - compact, scannable
      const threatsList = document.createElement('div');
      threatsList.style.cssText = `
        padding: 16px 24px;
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 240px;
        overflow-y: auto;
      `;

      reasons.forEach((reason) => {
        const { title: threatTitle, description: threatDesc } = parseThreatInfo(reason);

        const item = document.createElement('div');
        item.style.cssText = `
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 8px;
          padding: 12px;
        `;

        const itemTitle = document.createElement('div');
        itemTitle.textContent = threatTitle;
        itemTitle.style.cssText = `
          font-size: 11px;
          font-weight: 600;
          color: #ef4444;
          letter-spacing: 0.5px;
          text-transform: uppercase;
          margin-bottom: 4px;
        `;

        const itemDesc = document.createElement('div');
        itemDesc.textContent = threatDesc;
        itemDesc.style.cssText = `
          font-size: 13px;
          color: rgba(255, 255, 255, 0.7);
          line-height: 1.4;
        `;

        item.appendChild(itemTitle);
        item.appendChild(itemDesc);
        threatsList.appendChild(item);
      });

      // Divider
      const divider = document.createElement('div');
      divider.style.cssText = `
        height: 1px;
        background: rgba(255, 255, 255, 0.06);
        margin: 0 24px;
      `;

      // Actions section
      const actions = document.createElement('div');
      actions.style.cssText = `
        padding: 16px 24px 24px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      `;

      const cancelButton = document.createElement('button');
      cancelButton.textContent = 'Reject Transaction';
      cancelButton.style.cssText = `
        width: 100%;
        padding: 12px 16px;
        background: #fafafa;
        color: #0a0a0a;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s ease;
      `;
      cancelButton.onmouseenter = () => {
        cancelButton.style.background = '#ffffff';
        cancelButton.style.transform = 'translateY(-1px)';
      };
      cancelButton.onmouseleave = () => {
        cancelButton.style.background = '#fafafa';
        cancelButton.style.transform = 'none';
      };
      cancelButton.onmousedown = () => { cancelButton.style.transform = 'scale(0.98)'; };
      cancelButton.onmouseup = () => { cancelButton.style.transform = 'translateY(-1px)'; };

      const proceedButton = document.createElement('button');
      proceedButton.textContent = 'Proceed anyway';
      proceedButton.style.cssText = `
        width: 100%;
        padding: 12px 16px;
        background: transparent;
        color: rgba(255, 255, 255, 0.4);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s ease;
      `;
      proceedButton.onmouseenter = () => {
        proceedButton.style.borderColor = 'rgba(255, 255, 255, 0.2)';
        proceedButton.style.color = 'rgba(255, 255, 255, 0.6)';
        proceedButton.style.background = 'rgba(255, 255, 255, 0.03)';
      };
      proceedButton.onmouseleave = () => {
        proceedButton.style.borderColor = 'rgba(255, 255, 255, 0.1)';
        proceedButton.style.color = 'rgba(255, 255, 255, 0.4)';
        proceedButton.style.background = 'transparent';
      };

      actions.appendChild(cancelButton);
      actions.appendChild(proceedButton);

      // Footer
      const footer = document.createElement('div');
      footer.style.cssText = `
        padding: 12px 24px;
        background: rgba(255, 255, 255, 0.02);
        border-top: 1px solid rgba(255, 255, 255, 0.06);
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
      `;
      footer.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span style="font-size: 11px; color: rgba(255, 255, 255, 0.3); letter-spacing: 0.02em;">EMET Guardian</span>
      `;

      // Assemble modal
      modal.appendChild(header);
      modal.appendChild(threatsList);
      modal.appendChild(divider);
      modal.appendChild(actions);
      modal.appendChild(footer);
      container.appendChild(modal);
      document.body.appendChild(container);

      // Event handlers
      const cleanup = () => {
        container.style.opacity = '0';
        modal.style.transform = 'translateY(8px)';
        setTimeout(() => {
          container.remove();
          document.body.style.overflow = '';
          window.removeEventListener('keydown', handleKeydown, true);
        }, 200);
      };

      const handleCancel = () => { cleanup(); resolve('cancel'); };
      const handleProceed = () => { cleanup(); resolve('proceed'); };

      cancelButton.onclick = handleCancel;
      proceedButton.onclick = handleProceed;

      const handleKeydown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          e.stopPropagation();
        }
      };
      window.addEventListener('keydown', handleKeydown, true);

      document.body.style.overflow = 'hidden';

      // Animate in
      requestAnimationFrame(() => {
        container.style.opacity = '1';
        modal.style.transform = 'translateY(0)';
      });
    });
  }

  // ============================================================
  // PHANTOM PROVIDER HOOK
  // ============================================================

  let hookedProvider: any = null;
  let userPublicKey: string | null = null;

  function getSerializedTransaction(tx: any): Uint8Array | null {
    try {
      // Handle different transaction formats
      if (tx instanceof Uint8Array) {
        return tx;
      }
      if (tx.serialize && typeof tx.serialize === 'function') {
        // web3.js Transaction object
        return tx.serialize({ requireAllSignatures: false, verifySignatures: false });
      }
      if (tx.serializeMessage && typeof tx.serializeMessage === 'function') {
        // Legacy Transaction
        return tx.serializeMessage();
      }
      if (ArrayBuffer.isView(tx)) {
        return new Uint8Array(tx.buffer, tx.byteOffset, tx.byteLength);
      }
      // VersionedTransaction
      if (tx.message && tx.message.serialize) {
        return tx.message.serialize();
      }
      console.warn('[EMET] Unknown transaction format:', tx);
      return null;
    } catch (e) {
      console.error('[EMET] Error serializing transaction:', e);
      return null;
    }
  }

  async function analyzeAndIntercept(tx: any): Promise<boolean> {
    const serialized = getSerializedTransaction(tx);
    if (!serialized) {
      console.warn('[EMET] Could not serialize transaction, allowing by default');
      return true; // Allow if we can't analyze
    }

    const { instructions, affectedAccounts } = analyzeSerializedTransaction(serialized);
    const wallet = userPublicKey || '';

    console.log('[EMET] Analyzing transaction:', {
      instructions: instructions.length,
      affectedAccounts: affectedAccounts.size,
      wallet: truncateAddr(wallet),
    });

    const { isHighRisk, reasons } = assessRisk(instructions, affectedAccounts, wallet);

    if (!isHighRisk) {
      console.log('[EMET] Transaction appears safe');
      return true;
    }

    console.warn('[EMET] HIGH RISK DETECTED:', reasons);

    const decision = await showWarningModal(reasons);

    if (decision === 'cancel') {
      console.log('[EMET] User cancelled high-risk transaction');
      return false;
    }

    console.warn('[EMET] User proceeded despite warnings');
    return true;
  }

  function hookPhantomProvider(provider: any) {
    if (hookedProvider === provider) {
      return; // Already hooked
    }

    console.log('[EMET Guardian] Hooking Phantom provider...');

    // Track user's public key
    if (provider.publicKey) {
      userPublicKey = provider.publicKey.toString();
    }

    // Listen for connection changes
    provider.on?.('connect', (publicKey: any) => {
      userPublicKey = publicKey?.toString() || null;
      console.log('[EMET] Wallet connected:', truncateAddr(userPublicKey || ''));
    });

    provider.on?.('disconnect', () => {
      userPublicKey = null;
      console.log('[EMET] Wallet disconnected');
    });

    // Hook signTransaction
    const originalSignTransaction = provider.signTransaction;
    if (originalSignTransaction) {
      provider.signTransaction = async function (tx: any) {
        console.log('[EMET] Intercepted signTransaction');
        const shouldProceed = await analyzeAndIntercept(tx);
        if (!shouldProceed) {
          throw new Error('Transaction rejected by EMET Guardian');
        }
        return originalSignTransaction.call(this, tx);
      };
    }

    // Hook signAllTransactions
    const originalSignAllTransactions = provider.signAllTransactions;
    if (originalSignAllTransactions) {
      provider.signAllTransactions = async function (txs: any[]) {
        console.log('[EMET] Intercepted signAllTransactions:', txs.length, 'transactions');
        for (const tx of txs) {
          const shouldProceed = await analyzeAndIntercept(tx);
          if (!shouldProceed) {
            throw new Error('Transaction rejected by EMET Guardian');
          }
        }
        return originalSignAllTransactions.call(this, txs);
      };
    }

    // Hook signAndSendTransaction
    const originalSignAndSendTransaction = provider.signAndSendTransaction;
    if (originalSignAndSendTransaction) {
      provider.signAndSendTransaction = async function (tx: any, options?: any) {
        console.log('[EMET] Intercepted signAndSendTransaction');
        const shouldProceed = await analyzeAndIntercept(tx);
        if (!shouldProceed) {
          throw new Error('Transaction rejected by EMET Guardian');
        }
        return originalSignAndSendTransaction.call(this, tx, options);
      };
    }

    hookedProvider = provider;
    console.log('[EMET Guardian] Provider successfully hooked');
  }

  // ============================================================
  // PROVIDER DETECTION
  // ============================================================

  function checkForPhantom() {
    const phantom = (window as any).phantom?.solana || (window as any).solana;

    if (phantom?.isPhantom) {
      hookPhantomProvider(phantom);
      return true;
    }
    return false;
  }

  // Try immediately
  if (!checkForPhantom()) {
    // Set up observer for dynamic injection
    let attempts = 0;
    const maxAttempts = 50;
    const interval = setInterval(() => {
      attempts++;
      if (checkForPhantom() || attempts >= maxAttempts) {
        clearInterval(interval);
        if (attempts >= maxAttempts) {
          console.log('[EMET Guardian] Phantom not detected after', maxAttempts, 'attempts');
        }
      }
    }, 100);

    // Also use MutationObserver as backup
    const observer = new MutationObserver(() => {
      if (checkForPhantom()) {
        observer.disconnect();
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    // Cleanup observer after timeout
    setTimeout(() => observer.disconnect(), 10000);
  }

  // Watch for window.solana changes (Phantom may inject later)
  let phantomChecked = false;
  Object.defineProperty(window, '__EMET_CHECK_PHANTOM__', {
    get() {
      if (!phantomChecked) {
        phantomChecked = checkForPhantom();
      }
      return phantomChecked;
    },
    configurable: true,
  });

  console.log('[EMET Guardian] Hook installation complete');
})();
