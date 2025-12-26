# EMET Guardian - Solana Wallet Security Extension

**A Chrome extension that protects Solana wallets from transaction-based drain attacks.**

Built by [EMET Labs](https://github.com/EmetLabs) - Solana Wallet Security Research

---

## What is EMET Labs?

EMET Labs is a Solana wallet security research organization focused on protecting users from wallet drain attacks, malicious dApps, and transaction-based exploits. Our mission is to make the Solana ecosystem safer through open-source security tools and research.

## What Does This Extension Do?

EMET Guardian intercepts Solana wallet signing requests **before** they reach Phantom wallet. It:

1. **Intercepts** all `signTransaction`, `signAllTransactions`, and `signAndSendTransaction` calls
2. **Decodes** the unsigned transaction to extract SPL Token instructions
3. **Analyzes** the transaction against known drain patterns
4. **Blocks** high-risk transactions with a full-screen warning
5. **Requires** explicit user decision before any signing can proceed

### The Warning Screen

When a high-risk transaction is detected, you'll see a **full-screen red warning** that:
- Explains the detected threat in plain English
- Lists all risk factors found
- Requires you to either **Cancel** or explicitly **Proceed**
- Cannot be dismissed without making a choice

## What Threats Does It Block?

EMET Guardian detects these high-risk patterns:

| Threat | Description |
|--------|-------------|
| **Unlimited Token Approval** | Detects `Approve` instructions with MAX_U64 amount (unlimited spending permission) |
| **Authority Transfer** | Detects `SetAuthority` transferring account control away from your wallet |
| **Authority Revocation** | Detects permanent removal of authority (irreversible) |
| **Multi-Account Attacks** | Flags transactions affecting 3+ token accounts (common in batch drains) |
| **Unknown Programs** | Warns about unverified programs interacting with your wallet |
| **Drain Patterns** | Detects permission grants combined with immediate transfers to external addresses |
| **Suspicious Closures** | Catches account closures sending rent to addresses other than your wallet |

## What It Does NOT Block

This is a first-line defense, not a complete security solution. It does **NOT**:

- Protect against phishing or social engineering
- Analyze program logic or smart contract vulnerabilities
- Detect attacks using allowlisted programs (Jupiter, Raydium, etc.)
- Block legitimate transactions that happen to match patterns
- Protect other wallets (Solflare, Backpack, etc.) - Phantom only for MVP
- Verify the legitimacy of NFT mints or airdrops
- Protect against attacks that don't use SPL Token instructions

**Always verify transactions independently. This tool is defense-in-depth, not a guarantee.**

## Installation

### Prerequisites

- Node.js 18+ and npm
- Chrome browser
- Phantom wallet extension

### Build from Source

```bash
# Clone the repository
git clone https://github.com/EmetLabs/Emet-guardian.git

cd Emet-guardian

# Install dependencies
npm install

# Build the extension
npm run build
```

### Load in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `dist/` folder from this project
5. The EMET Guardian icon should appear in your toolbar

## Testing the Extension

### Quick Test

1. Ensure Phantom wallet is installed and connected
2. Visit any Solana dApp (e.g., [Jupiter](https://jup.ag), [Raydium](https://raydium.io))
3. Initiate a token swap or transfer
4. If the transaction is safe, it proceeds normally to Phantom
5. If high-risk patterns are detected, the warning screen appears

### Testing High-Risk Detection

To verify the extension catches dangerous transactions:

1. **Create a test transaction** with an unlimited approval:
   ```javascript
   // In browser console on a Solana dApp
   const { Token, TOKEN_PROGRAM_ID } = solanaWeb3;

   // Create an Approve instruction with MAX amount
   const ix = Token.createApproveInstruction(
     TOKEN_PROGRAM_ID,
     sourceAccount,      // Your token account
     delegateAccount,    // Attacker's address
     ownerAccount,       // Your wallet
     [],
     BigInt('18446744073709551615')  // MAX_U64 = unlimited
   );
   ```

2. **Attempt to sign** the transaction
3. **Verify** the red warning screen appears
4. **Test Cancel** - Phantom should NOT open
5. **Test Proceed** - Phantom should open normally

### Expected Behavior

| Scenario | Expected Result |
|----------|-----------------|
| Normal swap | Transaction proceeds to Phantom |
| Unlimited approval | Red warning screen blocks signing |
| User cancels | Promise rejects, Phantom never opens |
| User proceeds | Transaction continues to Phantom |
| No Phantom | Extension waits, eventually times out |

## Development

### Project Structure

```
emet-guardian-extension/
├── manifest.json           # Extension manifest (MV3)
├── package.json           # Dependencies and scripts
├── webpack.config.js      # Build configuration
├── tsconfig.json          # TypeScript configuration
├── src/
│   ├── inject/
│   │   └── phantomHook.ts  # Core interception logic (page context)
│   ├── decode/
│   │   ├── splTokenDecoder.ts  # SPL instruction decoder
│   │   └── riskRules.ts        # Threat detection rules
│   ├── ui/
│   │   └── WarningModal.tsx    # React warning component
│   ├── background.ts       # Service worker
│   └── content.ts          # Content script (injection)
├── public/
│   └── icon.png           # Extension icon
└── README.md
```

### Key Files

- **`phantomHook.ts`**: Injected into page context, monkey-patches Phantom's provider methods
- **`splTokenDecoder.ts`**: Decodes raw SPL Token instructions from serialized transactions
- **`riskRules.ts`**: Deterministic rules that flag high-risk patterns
- **`WarningModal.tsx`**: Full-screen blocking UI (also has inline DOM version in hook)

### Build Commands

```bash
npm run build    # Production build
npm run dev      # Development build with watch mode
npm run clean    # Remove dist/
```

### Adding New Risk Rules

Edit `src/decode/riskRules.ts`:

```typescript
// Example: Add rule for suspicious memo instructions
if (someCondition) {
  reasons.push(
    `THREAT_NAME: Description of the threat ` +
    `and what could happen if user proceeds.`
  );
}
```

Rules must be:
- **Deterministic** - Same input always produces same output
- **Explainable** - Clear English description for users
- **Conservative** - Better to warn than to miss an attack

## Architecture Decisions

### Why Inject into Page Context?

Phantom's provider (`window.solana`) lives in the page's JavaScript context. Content scripts run in an isolated world and cannot access it. We must inject a script that runs in the main world.

### Why Decode Transactions Ourselves?

We intercept **before** Phantom sees the transaction. The dApp provides an unsigned `Transaction` object. We serialize and decode it ourselves to analyze the instructions without any external dependencies at runtime.

### Why No Backend?

- Privacy: No transaction data leaves your browser
- Security: No server to compromise
- Reliability: Works offline, no API dependencies
- Speed: Instant local analysis

### Why Deterministic Rules?

- Predictable: Users can understand why something was flagged
- Auditable: Rules can be publicly verified
- No false sense of security: We don't claim ML can catch everything

## Security Considerations

### Threat Model

This extension assumes:
- The page may be hostile
- Phantom itself is trusted
- The user may not understand transaction details
- Attackers know about this extension

### Limitations

- **Bypass possible**: Sophisticated attackers may craft transactions that evade detection
- **False positives**: Legitimate transactions may trigger warnings
- **Timing window**: If injection fails, protection is lost
- **Single wallet**: Only Phantom is protected in this MVP

### Recommendations

1. Always verify transactions independently
2. Don't blindly trust "Proceed" - read the warnings
3. Use hardware wallets for large holdings
4. Report bypasses to EMET Labs responsibly

## Security Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

EMET Guardian is a security tool that attempts to detect malicious transactions, but:

- It cannot catch all attacks
- It may produce false positives
- It is not a substitute for careful transaction review
- Attackers actively work to bypass security tools

**You are solely responsible for your own security. Never sign transactions you don't understand. When in doubt, reject the transaction.**

## Contributing

We welcome contributions! Please:

1. Open an issue describing the change
2. Fork and create a feature branch
3. Write tests for new detection rules
4. Submit a PR with clear description

### Priority Areas

- Additional drain pattern detection
- Solflare wallet support
- Improved transaction decoding
- Better UX for the warning modal

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contact

- GitHub: [@EmetLabs](https://github.com/EmetLabs)
- Twitter: [@EmetLabs](https://twitter.com/EmetLabs)
- Security issues: security@emetlabs.io

---

**Built with caution by EMET Labs. Stay safe out there.**
