/**
 * SPL Token Instruction Decoder
 *
 * Decodes SPL Token program instructions from raw transaction data.
 * Supports: Approve, SetAuthority, Transfer, CloseAccount
 *
 * SECURITY NOTE: This decoder operates on unsigned transactions.
 * All decoded data should be treated as potentially malicious.
 */

// SPL Token Program ID (mainnet)
export const SPL_TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

// SPL Token instruction discriminators (first byte)
export const SPL_TOKEN_INSTRUCTIONS = {
  TRANSFER: 3,
  APPROVE: 4,
  SET_AUTHORITY: 6,
  CLOSE_ACCOUNT: 9,
  TRANSFER_CHECKED: 12,
  APPROVE_CHECKED: 13,
} as const;

// Authority types for SetAuthority instruction
export const AUTHORITY_TYPES = {
  0: 'MintTokens',
  1: 'FreezeAccount',
  2: 'AccountOwner',
  3: 'CloseAccount',
} as const;

export interface DecodedInstruction {
  program: 'spl-token' | 'unknown';
  type: 'approve' | 'setAuthority' | 'transfer' | 'close' | 'unknown';
  source?: string;
  destination?: string;
  authority?: string;
  newAuthority?: string;
  authorityType?: string;
  amount?: bigint;
  mint?: string;
  owner?: string;
  raw?: {
    programId: string;
    data: Uint8Array;
    accounts: string[];
  };
}

/**
 * Read a 64-bit unsigned integer from buffer (little-endian)
 * Used for token amounts
 */
function readUint64LE(data: Uint8Array, offset: number): bigint {
  let result = BigInt(0);
  for (let i = 0; i < 8; i++) {
    result |= BigInt(data[offset + i] ?? 0) << BigInt(i * 8);
  }
  return result;
}

/**
 * Decode a single SPL Token instruction
 */
export function decodeInstruction(
  programId: string,
  data: Uint8Array,
  accounts: string[]
): DecodedInstruction {
  // Not an SPL Token instruction
  if (programId !== SPL_TOKEN_PROGRAM_ID) {
    return {
      program: 'unknown',
      type: 'unknown',
      raw: { programId, data, accounts },
    };
  }

  if (data.length === 0) {
    return {
      program: 'spl-token',
      type: 'unknown',
      raw: { programId, data, accounts },
    };
  }

  const instructionType = data[0];

  switch (instructionType) {
    case SPL_TOKEN_INSTRUCTIONS.TRANSFER: {
      // Transfer: source(0), destination(1), owner(2)
      // Data: [type(1), amount(8)]
      if (data.length < 9 || accounts.length < 3) {
        return {
          program: 'spl-token',
          type: 'transfer',
          raw: { programId, data, accounts },
        };
      }
      return {
        program: 'spl-token',
        type: 'transfer',
        source: accounts[0],
        destination: accounts[1],
        authority: accounts[2],
        amount: readUint64LE(data, 1),
      };
    }

    case SPL_TOKEN_INSTRUCTIONS.TRANSFER_CHECKED: {
      // TransferChecked: source(0), mint(1), destination(2), owner(3)
      // Data: [type(1), amount(8), decimals(1)]
      if (data.length < 10 || accounts.length < 4) {
        return {
          program: 'spl-token',
          type: 'transfer',
          raw: { programId, data, accounts },
        };
      }
      return {
        program: 'spl-token',
        type: 'transfer',
        source: accounts[0],
        mint: accounts[1],
        destination: accounts[2],
        authority: accounts[3],
        amount: readUint64LE(data, 1),
      };
    }

    case SPL_TOKEN_INSTRUCTIONS.APPROVE: {
      // Approve: source(0), delegate(1), owner(2)
      // Data: [type(1), amount(8)]
      if (data.length < 9 || accounts.length < 3) {
        return {
          program: 'spl-token',
          type: 'approve',
          raw: { programId, data, accounts },
        };
      }
      return {
        program: 'spl-token',
        type: 'approve',
        source: accounts[0],
        destination: accounts[1], // delegate
        authority: accounts[2],   // owner
        amount: readUint64LE(data, 1),
      };
    }

    case SPL_TOKEN_INSTRUCTIONS.APPROVE_CHECKED: {
      // ApproveChecked: source(0), mint(1), delegate(2), owner(3)
      // Data: [type(1), amount(8), decimals(1)]
      if (data.length < 10 || accounts.length < 4) {
        return {
          program: 'spl-token',
          type: 'approve',
          raw: { programId, data, accounts },
        };
      }
      return {
        program: 'spl-token',
        type: 'approve',
        source: accounts[0],
        mint: accounts[1],
        destination: accounts[2], // delegate
        authority: accounts[3],   // owner
        amount: readUint64LE(data, 1),
      };
    }

    case SPL_TOKEN_INSTRUCTIONS.SET_AUTHORITY: {
      // SetAuthority: account(0), currentAuthority(1)
      // Data: [type(1), authorityType(1), hasNewAuthority(1), newAuthority?(32)]
      if (data.length < 3 || accounts.length < 2) {
        return {
          program: 'spl-token',
          type: 'setAuthority',
          raw: { programId, data, accounts },
        };
      }

      const authorityTypeNum = data[1];
      const hasNewAuthority = data[2] === 1;
      let newAuthority: string | undefined;

      if (hasNewAuthority && data.length >= 35) {
        // Extract 32-byte public key
        const pubkeyBytes = data.slice(3, 35);
        newAuthority = encodeBase58(pubkeyBytes);
      }

      return {
        program: 'spl-token',
        type: 'setAuthority',
        source: accounts[0],
        authority: accounts[1],
        authorityType: AUTHORITY_TYPES[authorityTypeNum as keyof typeof AUTHORITY_TYPES] || `Unknown(${authorityTypeNum})`,
        newAuthority: newAuthority,
      };
    }

    case SPL_TOKEN_INSTRUCTIONS.CLOSE_ACCOUNT: {
      // CloseAccount: account(0), destination(1), owner(2)
      // Data: [type(1)]
      if (accounts.length < 3) {
        return {
          program: 'spl-token',
          type: 'close',
          raw: { programId, data, accounts },
        };
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
      return {
        program: 'spl-token',
        type: 'unknown',
        raw: { programId, data, accounts },
      };
  }
}

/**
 * Base58 encoding for public keys
 * Minimal implementation for display purposes
 */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    zeros++;
  }

  // Convert to base58
  const result: number[] = [];
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * BigInt(256) + BigInt(byte);
  }

  while (num > 0) {
    result.unshift(Number(num % BigInt(58)));
    num = num / BigInt(58);
  }

  // Add leading '1's for leading zeros
  for (let i = 0; i < zeros; i++) {
    result.unshift(0);
  }

  return result.map(i => BASE58_ALPHABET[i]).join('');
}

/**
 * Decode base58 string to bytes
 */
export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  let num = BigInt(0);
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * BigInt(58) + BigInt(index);
  }

  // Count leading '1's
  let zeros = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    zeros++;
  }

  // Convert to bytes
  const bytes: number[] = [];
  while (num > 0) {
    bytes.unshift(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }

  // Add leading zeros
  for (let i = 0; i < zeros; i++) {
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

export interface TransactionAnalysis {
  instructions: DecodedInstruction[];
  affectedAccounts: Set<string>;
  splTokenInstructions: DecodedInstruction[];
}

/**
 * Analyze a serialized transaction
 * Extracts and decodes all instructions
 */
export function analyzeTransaction(serializedTx: Uint8Array): TransactionAnalysis {
  const instructions: DecodedInstruction[] = [];
  const affectedAccounts = new Set<string>();

  try {
    // Parse the transaction message
    // Solana transaction format:
    // [numSignatures(1), signatures(64*n), message...]
    // Message format (legacy):
    // [numRequiredSignatures(1), numReadonlySignedAccounts(1), numReadonlyUnsignedAccounts(1),
    //  numAccounts(compact), accounts(32*n), recentBlockhash(32), numInstructions(compact), instructions...]

    let offset = 0;

    // Skip signature count and signatures for unsigned transactions
    const numSignatures = serializedTx[offset];
    offset += 1 + (numSignatures * 64);

    // If this is just a message (no signature prefix), reset
    if (offset >= serializedTx.length) {
      offset = 0;
    }

    // Message header
    const numRequiredSignatures = serializedTx[offset];
    const numReadonlySignedAccounts = serializedTx[offset + 1];
    const numReadonlyUnsignedAccounts = serializedTx[offset + 2];
    offset += 3;

    // Read compact-u16 for number of accounts
    const { value: numAccounts, bytesRead: accountsBytesRead } = readCompactU16(serializedTx, offset);
    offset += accountsBytesRead;

    // Read account public keys
    const accountKeys: string[] = [];
    for (let i = 0; i < numAccounts; i++) {
      const pubkeyBytes = serializedTx.slice(offset, offset + 32);
      accountKeys.push(encodeBase58(pubkeyBytes));
      offset += 32;
    }

    // Skip recent blockhash (32 bytes)
    offset += 32;

    // Read compact-u16 for number of instructions
    const { value: numInstructions, bytesRead: instructionsBytesRead } = readCompactU16(serializedTx, offset);
    offset += instructionsBytesRead;

    // Parse each instruction
    for (let i = 0; i < numInstructions; i++) {
      // Program ID index
      const programIdIndex = serializedTx[offset];
      offset += 1;

      // Number of accounts (compact-u16)
      const { value: numAccountsInInstruction, bytesRead: numAccountsBytesRead } = readCompactU16(serializedTx, offset);
      offset += numAccountsBytesRead;

      // Account indices
      const accountIndices: number[] = [];
      for (let j = 0; j < numAccountsInInstruction; j++) {
        accountIndices.push(serializedTx[offset]);
        offset += 1;
      }

      // Data length (compact-u16)
      const { value: dataLength, bytesRead: dataLengthBytesRead } = readCompactU16(serializedTx, offset);
      offset += dataLengthBytesRead;

      // Instruction data
      const data = serializedTx.slice(offset, offset + dataLength);
      offset += dataLength;

      // Resolve account addresses
      const accounts = accountIndices.map(idx => accountKeys[idx] || `unknown_${idx}`);
      const programId = accountKeys[programIdIndex] || `unknown_program_${programIdIndex}`;

      // Track affected accounts
      accounts.forEach(acc => affectedAccounts.add(acc));

      // Decode the instruction
      const decoded = decodeInstruction(programId, data, accounts);
      instructions.push(decoded);
    }
  } catch (error) {
    // If parsing fails, return empty analysis
    // This is defensive - malformed transactions should be treated as suspicious
    console.error('[EMET] Transaction parsing error:', error);
  }

  const splTokenInstructions = instructions.filter(ix => ix.program === 'spl-token');

  return {
    instructions,
    affectedAccounts,
    splTokenInstructions,
  };
}

/**
 * Read a compact-u16 from the buffer
 * Solana uses variable-length encoding for lengths
 */
function readCompactU16(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let value = 0;
  let bytesRead = 0;

  for (let i = 0; i < 3; i++) {
    const byte = data[offset + i];
    value |= (byte & 0x7f) << (i * 7);
    bytesRead++;
    if ((byte & 0x80) === 0) {
      break;
    }
  }

  return { value, bytesRead };
}
