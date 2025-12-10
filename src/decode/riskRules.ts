/**
 * Risk Rules Engine
 *
 * Deterministic, hard-coded rules to detect wallet drain patterns.
 * NO ML, NO soft scoring - binary high-risk detection only.
 *
 * SECURITY NOTE: These rules are based on known attack patterns.
 * Attackers may attempt to evade detection. This is defense-in-depth,
 * not a guarantee of safety.
 */

import { DecodedInstruction, TransactionAnalysis, SPL_TOKEN_PROGRAM_ID } from './splTokenDecoder';

export interface RiskAssessment {
  isHighRisk: boolean;
  reasons: string[];
}

// Maximum value for SPL token amounts (u64 max)
// Approvals at or near this value are considered "unlimited"
const MAX_U64 = BigInt('18446744073709551615');

// Threshold for "effectively unlimited" - 99.9% of max
const UNLIMITED_THRESHOLD = MAX_U64 * BigInt(999) / BigInt(1000);

// Known safe program IDs (allowlist)
// These are well-audited, widely-used programs
const SAFE_PROGRAM_IDS = new Set([
  SPL_TOKEN_PROGRAM_ID,                                    // SPL Token
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',          // Token-2022
  '11111111111111111111111111111111',                      // System Program
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',         // Associated Token Account
  'ComputeBudget111111111111111111111111111111',           // Compute Budget
  'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',          // Metaplex Token Metadata
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',          // Jupiter v6
  'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',          // Orca Whirlpool
  'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK',         // Raydium CLMM
  'srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX',          // Serum DEX v3
  'LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo',          // Meteora
]);

// Minimum number of affected token accounts to trigger multi-account warning
const MULTI_ACCOUNT_THRESHOLD = 3;

/**
 * Assess risk of a transaction based on decoded instructions
 *
 * @param analysis - The decoded transaction analysis
 * @param userWallet - The user's wallet public key (base58)
 * @returns Risk assessment with boolean flag and reason strings
 */
export function assessRisk(
  analysis: TransactionAnalysis,
  userWallet: string
): RiskAssessment {
  const reasons: string[] = [];

  // Rule 1: Unlimited or near-unlimited token approval
  for (const ix of analysis.splTokenInstructions) {
    if (ix.type === 'approve' && ix.amount !== undefined) {
      if (ix.amount >= UNLIMITED_THRESHOLD) {
        reasons.push(
          `UNLIMITED TOKEN APPROVAL detected: Granting unlimited spending permission to ${truncateAddress(ix.destination)}. ` +
          `This allows the delegate to drain ALL tokens from this account at any time.`
        );
      }
    }
  }

  // Rule 2: SetAuthority transferring ownership away from user
  for (const ix of analysis.splTokenInstructions) {
    if (ix.type === 'setAuthority') {
      // Check if authority is being transferred away from user
      const currentAuthority = ix.authority;
      const newAuthority = ix.newAuthority;

      // If current authority is user and new authority is different
      if (currentAuthority === userWallet && newAuthority && newAuthority !== userWallet) {
        reasons.push(
          `AUTHORITY TRANSFER detected: Transferring ${ix.authorityType || 'account'} authority ` +
          `from your wallet to ${truncateAddress(newAuthority)}. ` +
          `You will lose control over this account.`
        );
      }

      // If new authority is undefined/null, ownership is being revoked entirely
      if (currentAuthority === userWallet && !newAuthority) {
        reasons.push(
          `AUTHORITY REVOCATION detected: Removing ${ix.authorityType || 'account'} authority entirely. ` +
          `This action is irreversible and you will permanently lose control.`
        );
      }
    }
  }

  // Rule 3: Multiple token accounts affected
  const affectedTokenAccounts = new Set<string>();
  for (const ix of analysis.splTokenInstructions) {
    if (ix.source) affectedTokenAccounts.add(ix.source);
  }

  if (affectedTokenAccounts.size >= MULTI_ACCOUNT_THRESHOLD) {
    reasons.push(
      `MULTI-ACCOUNT OPERATION: This transaction affects ${affectedTokenAccounts.size} different token accounts. ` +
      `Drain attacks often target multiple accounts in a single transaction to maximize theft.`
    );
  }

  // Rule 4: Unknown program requesting authority
  for (const ix of analysis.instructions) {
    if (ix.program === 'unknown' && ix.raw) {
      const programId = ix.raw.programId;

      // Check if this unknown program is in our safe list
      if (!SAFE_PROGRAM_IDS.has(programId)) {
        // Check if the instruction involves authority/owner accounts
        // by looking at account patterns (heuristic)
        const accounts = ix.raw.accounts;

        // If user's wallet is one of the accounts, it might be requesting authority
        if (accounts.includes(userWallet)) {
          reasons.push(
            `UNKNOWN PROGRAM: Unverified program ${truncateAddress(programId)} ` +
            `is requesting interaction with your wallet. This program is not in the known-safe list.`
          );
        }
      }
    }
  }

  // Rule 5: Pattern detection for common drain flows
  // Drain pattern: Approve + Transfer/Close in same tx, or SetAuthority + operations
  const hasApprove = analysis.splTokenInstructions.some(ix => ix.type === 'approve');
  const hasSetAuthority = analysis.splTokenInstructions.some(ix => ix.type === 'setAuthority');
  const hasTransferOrClose = analysis.splTokenInstructions.some(
    ix => ix.type === 'transfer' || ix.type === 'close'
  );

  // Suspicious: Approve/SetAuthority combined with immediate transfer/close
  if ((hasApprove || hasSetAuthority) && hasTransferOrClose) {
    // Check if transfers are going to a different address than the authority
    const suspiciousPattern = analysis.splTokenInstructions.some(ix => {
      if (ix.type === 'transfer' && ix.destination && ix.destination !== userWallet) {
        return true;
      }
      if (ix.type === 'close' && ix.destination && ix.destination !== userWallet) {
        return true;
      }
      return false;
    });

    if (suspiciousPattern) {
      reasons.push(
        `DRAIN PATTERN DETECTED: This transaction combines permission grants with immediate ` +
        `transfers to external addresses. This is a common wallet drain technique.`
      );
    }
  }

  // Rule 6: Close account sending rent to different address
  for (const ix of analysis.splTokenInstructions) {
    if (ix.type === 'close') {
      if (ix.destination && ix.destination !== userWallet) {
        reasons.push(
          `SUSPICIOUS ACCOUNT CLOSURE: Closing token account and sending rent refund ` +
          `to ${truncateAddress(ix.destination)} instead of your wallet.`
        );
      }
    }
  }

  // Rule 7: Large transfer amounts (not unlimited, but significant)
  // This is informational but can indicate drain attempts
  for (const ix of analysis.splTokenInstructions) {
    if (ix.type === 'transfer' && ix.amount !== undefined) {
      // Check if destination is not the user
      if (ix.destination && ix.destination !== userWallet) {
        // We don't know token decimals, so we can't determine exact value
        // Flag very large raw amounts as suspicious
        const LARGE_AMOUNT_THRESHOLD = BigInt('1000000000000'); // 1 trillion smallest units

        if (ix.amount >= LARGE_AMOUNT_THRESHOLD) {
          reasons.push(
            `LARGE TRANSFER: Transferring ${formatLargeNumber(ix.amount)} tokens ` +
            `to ${truncateAddress(ix.destination)}.`
          );
        }
      }
    }
  }

  return {
    isHighRisk: reasons.length > 0,
    reasons,
  };
}

/**
 * Truncate a Solana address for display
 */
function truncateAddress(address: string | undefined): string {
  if (!address) return 'unknown';
  if (address.length <= 12) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

/**
 * Format large numbers for display
 */
function formatLargeNumber(num: bigint): string {
  const str = num.toString();
  if (str.length > 15) {
    return `${str.slice(0, 3)}...${str.slice(-3)} (${str.length} digits)`;
  }
  return str.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Quick check if a transaction likely needs analysis
 * Used for early filtering before full decode
 */
export function mightBeRisky(programIds: string[]): boolean {
  // Always analyze if SPL Token program is involved
  if (programIds.includes(SPL_TOKEN_PROGRAM_ID)) {
    return true;
  }

  // Always analyze if there are unknown programs
  const hasUnknownProgram = programIds.some(id => !SAFE_PROGRAM_IDS.has(id));
  if (hasUnknownProgram) {
    return true;
  }

  return false;
}
