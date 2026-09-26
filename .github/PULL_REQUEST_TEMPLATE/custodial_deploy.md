# Pre-deploy checklist — custodial + NWC deploy

Run this end-to-end before promoting `sattest` + `sattest-backend` to production
**with the custodial path enabled** (both funding modes available). Anything that
fails blocks the deploy. Use **signet/testnet** wallets where it says "real" —
never mainnet.

> **This checklist covers BOTH flows.** It applies only when the custodial path is
> turned on: `ALLOW_CUSTODIAL_BOUNTIES=true` on the backend **and**
> `CUSTODIAL_BOUNTIES_ENABLED = true` in the extension (`src/bounty/bounty.util.ts`).
> Both must agree — a mismatch lets the extension offer a mode the backend rejects.
>
> For the default **non-custodial-only** deploy, use **`PRE_DEPLOY_CHECKLIST_NWC.md`**.
>
> With custodial enabled and a wallet connected, `Add Bounty` shows a funding-mode
> quick-pick. Custodial bounties hold sats in the LNbits Treasury/Payout wallets
> until approval; NWC bounties move sats wallet-to-wallet and never touch our host.

## 0. Environment prep

- [ ] `cd sattest && npm test` — all green (≥ 424 tests)
- [ ] `cd sattest && npx tsc --noEmit` — no output
- [ ] `cd sattest-backend && npm test` — all green (≥ 238 tests)
- [ ] `cd sattest-backend && npx tsc -p tsconfig.build.json --noEmit` — no output
- [ ] `cd sattest-backend && npm run generate` — no pending migrations missing from `drizzle/`
- [ ] Backend `.env` has: `DATABASE_URL`, `WALLET_ENCRYPTION_KEY`, `PAYOUTS_ENABLED=true`
- [ ] **`ALLOW_CUSTODIAL_BOUNTIES=true`** on the backend
- [ ] Extension build has **`CUSTODIAL_BOUNTIES_ENABLED = true`** in `src/bounty/bounty.util.ts` (matches the backend flag)
- [ ] LNbits configured: `LNBITS_URL`, `LNBITS_INVOICE_KEY`, `LNBITS_API_KEY`
- [ ] LNbits **Payout** wallet holds ≥ 500 sats float (covers the 100-sat fee reserve + buffer)
- [ ] Circuit-breaker caps sane: `PAYOUT_CAP_HOURLY_SATS`, `PAYOUT_CAP_DAILY_SATS`, `PAYOUT_ALERT_SATS`, `PAYOUT_BALANCE_MULTIPLIER`
- [ ] Two test wallets on hand:
  - **Wallet A (creator)** — Alby Hub / Coinos / Phoenix / Mutiny with NWC support, funded
  - **Wallet B (claimer)** — any LNURL-pay-capable wallet (LN address fine)
- [ ] Two Nostr identities on hand (creator npub + claimer npub) — separate signers or VS Code windows

---

## 1. Extension activation

- [ ] Install the `.vsix` into a clean VS Code profile
- [ ] Open a workspace with at least one supported test file
- [ ] No error toasts on activation
- [ ] Test Controller populates within ~5 s
- [ ] Code-lens appears above test functions for any pre-existing bounties
- [ ] Command palette lists: Add Bounty, Check Bounty Paid, Remove Bounty, Claim Bounty, Approve Claim, Connect Lightning Wallet (NWC), Disconnect Lightning Wallet (NWC), Connect Nostr

## 2. Nostr connection

- [ ] `Connect Nostr` (Ctrl/Cmd+Alt+N) opens the bunker QR webview
- [ ] When already connected, the panel shows a green "Connected as @handle" banner
- [ ] The banner shows the **real profile name** (`@handle`), not a hex pubkey; a failed lookup
      never downgrades a previously-correct handle, and a different npub never inherits the
      previous identity's handle
- [ ] Approving in Primal (or your NIP-46 remote signer) resolves the panel; on a fresh connect the QR is replaced by a "Connected as …" view that auto-closes after a few seconds
- [ ] Reload window — Nostr session persists (no re-pair required)

## 3. Connect a Lightning wallet (NWC)

- [ ] Run `Connect Lightning Wallet (NWC)` **before** connecting Nostr → toast: *"Connect to Nostr first…"* — no URI prompt
- [ ] Connect Nostr, retry the command
- [ ] Paste a malformed string (e.g. `https://example.com`) → validator rejects with *"Expected a nostr+walletconnect:// URI"*
- [ ] Paste a real `nostr+walletconnect://…` URI from Wallet A → success toast
- [ ] Backend DB: `users.encrypted_nwc_uri` is non-null and **not** plaintext
- [ ] `GET /users/me/nwc-status` → `{configured: true, …}` — **no `uri` field**

## 4. Funding-mode quick-pick

- [ ] With Wallet A connected, `Add Bounty`, enter an amount
- [ ] A quick-pick appears with **"Fund from connected Lightning wallet (non-custodial)"** and **"Fund via Lightning invoice (custodial)"**
- [ ] Esc the quick-pick → no bounty created, no toast

---

## CUSTODIAL FLOW

## 5. Custodial bounty — happy path

- [ ] `Add Bounty`, enter `5000` sats, pick **"Fund via Lightning invoice (custodial)"**
- [ ] On first use, choose your LNbits setup (default vs your own)
- [ ] QR webview opens; copy the invoice
- [ ] Pay the invoice from Wallet B
- [ ] Within ~10 s the lens flips to **"💰 Funded – Claimable (5000 sats)"** — **no** "Non-custodial" badge
- [ ] LNbits Treasury wallet shows +5000 sats; Payout wallet unchanged
- [ ] Backend bounty row: `funding_mode='custodial'`, `invoice` + `payment_hash` populated

## 6. Check payment status (custodial only)

- [ ] On an unpaid custodial bounty, `Check Bounty Paid` → reports not yet funded; QR panel reopens
- [ ] After paying, `Check Bounty Paid` → marks it funded

## 7. Claim + approve a custodial bounty

- [ ] Switch to the claimer profile
- [ ] Click the **Funded – Claimable** lens → enter Wallet B's LN address → a **"Payout address privacy"** quick-pick appears (**Share** default / **Hide my Lightning address from the creator**); Esc → claim cancelled, nothing sent
- [ ] Choose **Share** → lens flips to **"💰 Claim Pending"**
- [ ] Switch to the creator profile → **"✅ Approve Claim"** lens appears beneath the pending lens
- [ ] Click Approve → lens flips to **"💰 Claim Approved – Payout Sent"**
- [ ] **Exactly one** success toast — no accompanying *"Failed to approve claim: Claim is not pending"*
- [ ] Double-click Approve (or approve from a second window): the duplicate is benign — a neutral
      *"already being approved…"* / *"already approved — payout completed."*, **never** a red
      failure toast, and **no** second payout (backend returns **409** `CLAIM_ALREADY_APPROVED` /
      `CLAIM_IN_PROGRESS`)
- [ ] Wallet B receives 5000 sats within ~30 s
- [ ] LNbits Payout wallet decremented by 5000 + routing fee

### 7a. Private claim (hide payout address from creator)
- [ ] Claim another funded bounty and choose **"Hide my Lightning address from the creator"**
- [ ] Backend `claims` row: `lnurl_private = true`, `claimant_lnurl` still stored
- [ ] As creator, Approve → confirm modal reads *"…to: the claimant"* (no raw address); `GET /bounties/:id/pending-claim` returns `claimantLnurl: null`, `lnurlHidden: true`
- [ ] Approve still pays Wallet B and writes `payout_txid` / `status='approved'`

## 8. Custodial deactivate / refund

- [ ] Create a fresh 1000-sat custodial bounty, fund it
- [ ] As creator, `Remove Bounty` → choose **refund** → enter the creator's LN address
- [ ] Toast: "Refunded 1000 sats to …"; bounty `active=false`; creator wallet receives ~1000 sats (minus routing)
- [ ] Unfunded custodial bounty → `Remove Bounty` deactivates silently (no refund prompt)
- [ ] Bounty with an already-approved claim → no refund offered (sats already out the door)
- [ ] Bounty with a still-pending claim → warned that refunding abandons the claimant before the LNURL prompt

### 8a. Fee-reserve guard rail
- [ ] Drain the LNbits Payout wallet below the 100-sat reserve
- [ ] Attempt a refund → user-facing toast: *"the payout wallet needs a small fee reserve. Top up … by ~100 sats and retry, or deactivate without a refund."* (not a doubled "Failed to deactivate bounty")
- [ ] Top up the wallet, retry → succeeds

---

## NON-CUSTODIAL (NWC) FLOW

## 9. Non-custodial bounty — happy path

- [ ] `Add Bounty`, enter `2000` sats, pick **"Fund from connected Lightning wallet (non-custodial)"**
- [ ] **No QR panel.** Toast: *"✅ Bounty created … Sats will move from your connected wallet when you approve a claim."*
- [ ] Lens reads **"💰 Funded – Claimable (2000 sats) · Non-custodial"** (badge present)
- [ ] Backend bounty row: `funding_mode='nwc'`, `invoice=null`, `payment_hash=null`, `invoice_paid=true`
- [ ] LNbits Treasury wallet **unchanged**

## 10. Claim + approve a non-custodial bounty

- [ ] Switch to the claimer profile; lens still shows the "· Non-custodial" badge + tooltip
- [ ] Claim with Wallet B's LN address → "Claim Pending · Non-custodial"
- [ ] Switch to the creator profile, click **Approve** → within ~30–60 s (NWC reply timeout 180 s):
  - [ ] Wallet A balance drops by 2000 sats + routing
  - [ ] Wallet B receives 2000 sats
  - [ ] LNbits Treasury **and** Payout wallets unchanged
  - [ ] Backend `claims.payout_txid` (preimage) populated, `status='approved'`

### 10a. Wallet offline / budget exceeded
- [ ] Disable Wallet A's NWC relay (or exhaust the budget), create + claim another NWC bounty, hit Approve
- [ ] Backend returns 502; the toast surfaces the real cause; claim stays `pending`
- [ ] Re-enable / top up, retry Approve → succeeds

### 10b. LNURL pinning (Layer 4)
- [ ] Approve uses `claim.claimant_lnurl` from the DB, never a body field — verify in logs
- [ ] POST `/bounties/:id/approve` with a different `lnurl` in the body → ignored; original pinned LNURL is paid

## 11. Remove a non-custodial bounty

- [ ] Create a fresh NWC bounty (don't claim it), `Remove Bounty`
- [ ] **No LNURL refund prompt** (nothing was custodied); `active=false`; Wallet A unchanged

## 12. Disconnect wallet

- [ ] `Disconnect Lightning Wallet (NWC)` with none configured → info toast
- [ ] With a wallet configured → modal confirm → Cancel leaves it; Disconnect clears `encrypted_nwc_uri` + budget columns
- [ ] After disconnect, the funding-mode quick-pick still appears for custodial, but picking non-custodial triggers the auto-connect flow
- [ ] **End the remote session in your signer app, then Disconnect** → still **succeeds** with no
      signer round-trip / no "waiting on signer" notice / no 15 s stall (`DELETE /users/me/nwc`
      is `nostrAuth`, not `moneyAuth` — revoke must never need a live signer; connect still does)

### 12a. Stranded NWC bounties
- [ ] Disconnect while an NWC bounty is pending approval → Approve returns 400/502 "wallet not connected"
- [ ] Reconnect → retry Approve → succeeds

---

## 13. Circuit breakers (both paths)

- [ ] Set `PAYOUTS_ENABLED=false`, restart
  - [ ] Approving a **custodial** claim → blocked
  - [ ] Approving an **NWC** claim → also blocked (kill switch covers both)
  - [ ] Restore `PAYOUTS_ENABLED=true`
- [ ] Trigger `evaluatePayoutGuards` rate limit (> N approvals in the window for one creator) → 429 on **both** paths; nothing paid
- [ ] `payoutBalanceLooksSane` only gates custodial payouts (draws from the LNbits Payout wallet); NWC approvals skip it
- [ ] Large-payout anomaly alert fires for an oversized bounty of **either** mode (check Slack/log sink)

## 14. Multi-window / per-repo

- [ ] Open the same workspace in a second VS Code window
- [ ] Create a bounty in window 1 → within ~30 s the lens shows up in window 2
- [ ] Open a *different* repo workspace → bounties from repo A do **not** appear (repo-slug filter works)

## 15. Failure-toast rate limiting

- [ ] Stop the backend, open the workspace fresh → only **one** "Failed to load bounties from backend" toast
- [ ] Wait > 10 s, switch editors → toast may appear again (cooldown reset is fine)

## 16. Database & migration

- [ ] Apply the latest `drizzle/` migrations to the staging DB; no errors
- [ ] Pre-existing custodial bounties still work end-to-end after migration
- [ ] `users` has the NWC columns (`encrypted_nwc_uri`, `nwc_budget_sats`, `nwc_budget_window`, `nwc_updated_at`); old rows NULL
- [ ] `bounties.funding_mode` defaults to `'custodial'` for legacy rows; handler sets it explicitly on insert
- [ ] `bounties.invoice` / `payment_hash` are nullable (`\d bounties` in psql)
- [ ] `claims.lnurl_private` exists (boolean, `NOT NULL DEFAULT false`); legacy rows read `false` (migration `0006_faithful_gabe_jones.sql`)

## 17. Final sanity

- [ ] Backend logs free of unhandled rejections during the run-through
- [ ] No NWC URI plaintext in logs (grep for `nostr+walletconnect://` — empty)
- [ ] No LNbits admin keys in logs
- [ ] No unexpected `console.error` / toasts in the extension's Output channel
- [ ] Bump the extension `version` in `package.json` before repackaging
- [ ] Tag the release, deploy backend first, then publish the extension

---

## Rollback plan

If anything in §5–§13 fails in production:
1. Set `PAYOUTS_ENABLED=false` on the backend (stops all approvals immediately — custodial and NWC)
2. To drop back to the safe default without a full revert, set `ALLOW_CUSTODIAL_BOUNTIES=false` (and ship the extension with `CUSTODIAL_BOUNTIES_ENABLED = false`) — NWC bounties keep working; custodial creation is refused
3. Otherwise revert the backend to the previous tag and pin/withdraw the extension
4. Custodial in-flight float lives in the LNbits Payout wallet — reconcile any half-finished payouts there; NWC bounties never put funds on our host
5. The `funding_mode` column is additive, so older rows are unaffected by a rollback
