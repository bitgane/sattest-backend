# Pre-deploy checklist — NWC (non-custodial) deploy

Run this end-to-end before promoting `sattest` + `sattest-backend` to production
**in the default non-custodial configuration**. Anything that fails blocks the
deploy. Use **signet/testnet** wallets where it says "real" — never mainnet.

> **This is the NWC-only checklist** (production default). Every new bounty funds
> from the creator's own Lightning wallet on approval; the backend never custodies
> funds. The custodial (LNbits invoice/QR) path is disabled here:
> `ALLOW_CUSTODIAL_BOUNTIES` is unset/`false` and
> `CUSTODIAL_BOUNTIES_ENABLED = false` in the extension.
>
> If you're deploying with the custodial path **enabled** (both flows available),
> use **`PRE_DEPLOY_CHECKLIST_CUSTODIAL.md`** instead.

---

## How to read this checklist

Every item is tagged with **where you do it**:

| Tag | Where | How |
| --- | --- | --- |
| **[VS Code — creator]** | VS Code window signed in as the **creator** npub | `Cmd/Ctrl+Shift+P` → type the command name shown in bold |
| **[VS Code — claimer]** | A **second** VS Code window signed in as the **claimer** npub | same |
| **[Terminal]** | Your shell, with the helpers from §0.4 sourced | copy/paste the code block |
| **[DB]** | Postgres, via the `q` helper from §0.4 | copy/paste the query |
| **[Railway]** | Railway dashboard → your backend service | Variables / Deployments / Logs tabs |
| **[Wallet]** | Wallet A or Wallet B's own app | — |

Exact command-palette names (the palette shows them with their category prefix):

- `Bounty: Add Bounty`
- `Bounty: Remove Bounty`
- `Bounty: Connect Lightning Wallet (NWC)`
- `Bounty: Disconnect Lightning Wallet (NWC)`
- `Bounty: Check Bounty Paid`
- `Claim: Claim Bounty`
- `Claim: Approve Claim`
- `Nostr: Connect Nostr` (also `Cmd/Ctrl+Alt+N`)

"Esc out" / "dismiss" always means pressing **Esc** on the currently focused
input box, quick-pick, or modal.

---

## 0. Environment prep

### 0.1 Build gates — [Terminal]

```bash
cd sattest && npm test
```

```bash
cd sattest && npx tsc --noEmit
```

```bash
cd sattest-backend && npm test
```

```bash
cd sattest-backend && npx tsc -p tsconfig.build.json --noEmit
```

```bash
cd sattest-backend && npm run generate
```

- [ ] extension `npm test` — all green (≥ 424 tests)
- [ ] extension `tsc --noEmit` — no output
- [ ] backend `npm test` — all green (≥ 238 tests)
- [ ] backend `tsc -p tsconfig.build.json --noEmit` — no output
- [ ] backend `npm run generate` — reports **no** new migration files (anything
      generated here means `drizzle/` was missing a migration; commit it and re-run §0.1)
- [ ] `node -v` ≥ **22.12.0** and `npm -v` ≥ **10** on the build host (matches `engines`)

### 0.2 Backend production env — [Railway]

Railway → your backend service → **Variables**. Check each is really set there,
not just present in `.env.example`:

- [ ] `NODE_ENV=production` — **must not** be `development` (that disables auth-event expiry, opens CORS, relaxes the SSRF guard, and leaks error text)
- [ ] `DATABASE_URL` — a variable reference to the Railway Postgres plugin, not a pasted value
- [ ] `WALLET_ENCRYPTION_KEY` — base64 32-byte value, **unchanged from the last deploy** (it encrypts stored NWC URIs; rotating it makes every saved wallet grant undecryptable and breaks approvals)
- [ ] `AUTH_AUDIENCE` — this service's own public URL, and **identical** to the extension's `sattest.backendUrl` (a mismatch rejects every auth event)
- [ ] `NOSTR_RELAYS` set; `ALLOWED_ORIGINS` set for any browser clients
- [ ] `PAYOUTS_ENABLED=true`
- [ ] Circuit-breaker vars set: `PAYOUT_CAP_HOURLY_SATS`, `PAYOUT_CAP_DAILY_SATS`, `PAYOUT_ALERT_SATS`, and `ALERT_WEBHOOK_URL` pointing at a channel someone watches
- [ ] **`ALLOW_CUSTODIAL_BOUNTIES` is unset or `false`** (production default — custodial off)
- [ ] `LNBITS_*` and `PAYOUT_BALANCE_MULTIPLIER` are **not required** for this deploy (no custodial path)

Extension side — [VS Code — creator], `Cmd/Ctrl+,` → search `sattest`:

- [ ] `CUSTODIAL_BOUNTIES_ENABLED = false` in `sattest/src/bounty/bounty.util.ts` (matches the backend flag)
- [ ] `sattest.backendUrl` points at the deployed backend and **matches `AUTH_AUDIENCE`** exactly (scheme + host + port, no trailing path)

### 0.3 Test identities and wallets — do this before anything else

You need **two Nostr identities whose nsec you hold**. Holding the nsec is what
makes the `[Terminal]` checks in §3, §6c and §9 possible — those sign auth
events yourself with `nak`, and a key that lives only inside someone else's
signer app can't do that.

**Install the tools** — [Terminal]:

```bash
brew install jq
go install github.com/fiatjaf/nak@latest   # or grab a binary from github.com/fiatjaf/nak/releases
```

**Generate the two identities** — [Terminal]:

```bash
nak key generate   # run twice — first output = creator, second = claimer
```

Each run prints a hex private key. Save both. Convert to `nsec`/`npub` when you
need them in an app:

```bash
nak key encode nsec <hex-private-key>
nak key public <hex-private-key> | xargs nak key encode npub
```

> **This is the `<creator-key>` referenced throughout the checklist**: the
> creator identity's private key, in hex or `nsec` form, from the step above.
> Never use a key that holds real funds or a real social identity.

**Make each identity usable from VS Code.** The extension signs via NIP-46, so
each identity needs to live in a remote signer that can hand out a `bunker://`
pairing. [nsec.app](https://nsec.app) is the easiest for testing because it
accepts an imported nsec (Primal only signs for accounts created in Primal):

- [ ] Import the **creator** nsec into nsec.app in one browser profile
- [ ] Import the **claimer** nsec into nsec.app in a second browser profile (or a different browser) so the two sessions don't collide
- [ ] Publish a kind-0 profile (a display name) for each identity to one of the `sattest.nostrRelays` — §2 checks that the handle renders instead of a hex pubkey

> If you'd rather keep a key inside a remote signer only, `nak` also accepts a
> `bunker://` URI in place of the raw key: `--sec 'bunker://…'`. It's slower
> (each signature needs signer approval) — the raw nsec is the smoother path
> for a checklist run.

**Wallets:**

- [ ] **Wallet A (creator)** — Alby Hub / Coinos / Phoenix / Mutiny, with NWC support, funded. Generate a connection string in its app (Alby Hub: *Connections → Add Connection*), and keep it handy — you'll paste it several times
- [ ] **Wallet B (claimer)** — any LNURL-pay-capable wallet; a plain Lightning address (`you@wallet.com`) is fine

### 0.4 Terminal toolkit — set this up once — [Terminal]

Save as `~/sattest-check.sh` and `source ~/sattest-check.sh` in every terminal
you use for this run. Every `[Terminal]` and `[DB]` block below assumes it.

```bash
# --- fill these in -----------------------------------------------------------
export AUD="https://<your-backend-host>"  # == AUTH_AUDIENCE
export CREATOR_SEC="<creator-key>"    # hex or nsec1… from §0.3
export CLAIMER_SEC="<claimer-key>"
export PGURL="postgres://…"           # Railway → Postgres plugin → Connect → connection URL
# -----------------------------------------------------------------------------

# Read-scope Authorization header (GET endpoints, /auth/nonce).
readauth() {
  printf 'Nostr %s' \
    "$(nak event -k 22242 -c 'sattest-auth' -t relay="$AUD" --sec "${1:-$CREATOR_SEC}" \
       | jq -c . | base64 | tr -d '\n')"
}

# Write-scope ("money") Authorization header — required by POST /bounties,
# /claim, /approve, PATCH /nwc. Fetches a fresh single-use nonce first.
moneyauth() {
  local sec="${1:-$CREATOR_SEC}" nonce
  nonce=$(curl -s -X POST "$AUD/auth/nonce" -H "Authorization: $(readauth "$sec")" | jq -r .nonce)
  printf 'Nostr %s' \
    "$(nak event -k 22242 -c 'sattest-auth:write' -t relay="$AUD" -t nonce="$nonce" --sec "$sec" \
       | jq -c . | base64 | tr -d '\n')"
}

# Query the DB:  q "select 1"
q() { psql "$PGURL" -c "$1"; }
```

Smoke-test the toolkit before you rely on it:

```bash
curl -s "$AUD/health" -H "Authorization: $(readauth)" | jq .
```

- [ ] Returns `{"status":"ok","dbConnected":true}`. A 401 here means `AUD` ≠
      `AUTH_AUDIENCE`, a bad key, or a clock more than 5 min off — fix it now,
      or every later `[Terminal]` step will fail for the wrong reason
- [ ] `q "select 1"` returns a row

> Auth events are valid for **30 min** (reads) and **5 min** (writes) in
> production. The helpers mint a fresh one per call, so just re-run the command
> if you see *"Auth event expired"*. A write header is **single-use** — its
> nonce is burned on first use; call `moneyauth` again for each request.

---

## 1. Extension activation — [VS Code — creator]

- [ ] Package and install the `.vsix` into a clean VS Code profile:
      `Cmd/Ctrl+Shift+P` → **Extensions: Install from VSIX…** → pick the file
      (build it with `cd sattest && npx vsce package`)
- [ ] Open a workspace with at least one supported test file, and **trust** it
      when prompted (the extension refuses to activate in an untrusted workspace)
- [ ] No error toasts on activation
- [ ] Test Controller populates within ~5 s (open the **Testing** side-bar view)
- [ ] Code-lens appears above test functions for any pre-existing bounties
- [ ] `Cmd/Ctrl+Shift+P` → type `sattest` → the palette lists all eight commands
      from the table at the top of this file

## 2. Nostr connection — [VS Code — creator]

- [ ] `Cmd/Ctrl+Alt+N` (or **Nostr: Connect Nostr**) opens the bunker QR webview
- [ ] Pair it: open nsec.app on the creator profile and approve the connection
      (scan the QR, or copy the `bunker://` URI into nsec.app)
- [ ] On a fresh connect the QR is replaced by a "Connected as …" view that
      auto-closes after a few seconds
- [ ] Re-run **Nostr: Connect Nostr** while connected → the panel shows a green
      "Connected as @handle" banner
- [ ] The banner shows the **real profile name** (`@handle`), not a hex pubkey. A
      `abcd1234…wxyz` rendering means the kind-0 profile lookup missed — check the
      identity actually has a profile published to one of the `sattest.nostrRelays` (§0.3)
- [ ] Reconnect on a flaky network (turn Wi-Fi off, run the command, turn it back
      on) → a previously-correct handle is **not** downgraded to hex (a failed
      lookup keeps the last known-good name and is never persisted)
- [ ] Connect as a **different** npub whose profile can't be resolved (the claimer
      identity, before you publish its kind-0) → it shows *that* identity's
      pubkey, **not** the previous identity's handle. Reconnect as the creator afterwards
- [ ] `Cmd/Ctrl+Shift+P` → **Developer: Reload Window** → the Nostr session
      persists (no re-pair required)

## 3. Connect a Lightning wallet (NWC)

Run these in order — each item continues from the previous one.

- [ ] **[VS Code — creator]** With Nostr *not* yet connected (use a fresh profile,
      or reload after disconnecting), run **Bounty: Connect Lightning Wallet (NWC)**
      → toast *"Connect to Nostr first…"*, and **no** URI prompt appears
- [ ] Connect Nostr (§2), then run **Bounty: Connect Lightning Wallet (NWC)** again
- [ ] In the URI prompt, type `https://example.com` → the validator rejects inline
      with *"Expected a nostr+walletconnect:// URI"* and won't let you submit
- [ ] Clear it, paste Wallet A's real `nostr+walletconnect://…` URI, press Enter
- [ ] **Only if `sattest.backendUrl` is a non-default host** (a staging URL): a
      modal warns you're about to send a spending grant to `<host>` → choose
      **"Send to this server"**. On the shipped default backend or localhost this
      modal is correctly skipped, and it won't reappear for an origin you've accepted
- [ ] A quick-pick titled *"Budget window (optional, display only)"* appears →
      choose **"Daily budget window"**
- [ ] The sats prompt appears → type `0` → validator rejects (*"Enter a positive
      whole number"*)
- [ ] Clear the field and press Enter with it **empty** → validator still rejects
      (an amount is required once a window is chosen; the quick-pick's "Skip"
      option is the only budget-less path)
- [ ] Type `100000` and press Enter → saving mints a write-scope auth credential,
      so nsec.app may ask you to approve **one signature** → approve it → success
      toast *"✅ Lightning wallet connected…"*

Verify it landed — **[DB]**:

```bash
q "select left(encrypted_nwc_uri, 24) as uri_head, nwc_budget_sats, nwc_budget_window, nwc_updated_at from users where nostr_pubkey = '$(nak key public "$CREATOR_SEC")'"
```

- [ ] `uri_head` is non-null and looks like base64/hex — **not** `nostr+walletc…`
- [ ] `nwc_budget_sats = 100000`, `nwc_budget_window = daily`

Verify the API — **[Terminal]**:

```bash
curl -s -i "$AUD/users/me/nwc-status" | head -20
```

- [ ] **Unauthenticated** → **401** with
      `{"error": "Missing or invalid Authorization header. Expected: Nostr <base64-event>"}`
      (this endpoint requires Nostr read auth — a plain browser hit failing this way is correct)

```bash
curl -s "$AUD/users/me/nwc-status" -H "Authorization: $(readauth)" | jq .
```

- [ ] **Authenticated** → `{configured: true, relay: …, lud16: …, budgetSats: 100000, budgetWindow: "daily", updatedAt: …}`
- [ ] **No `uri` field anywhere in the response** — `lud16`/`relay` are the display summary only, never the secret

### 3a. Cancellation paths — [VS Code — creator]

Four independent runs of **Bounty: Connect Lightning Wallet (NWC)** from the
command palette. Nothing here is a terminal command — each bullet is one full
run of that command, bailing out at a different prompt.

After each of the first three, re-run the `[DB]` query above and confirm the row
still reads exactly as it did at the end of §3 (`nwc_budget_sats = 100000`,
`daily`, same `nwc_updated_at`).

- [ ] **Run 1 — bail at the URI prompt.** Palette → **Bounty: Connect Lightning
      Wallet (NWC)** → press **Esc** on the "Paste your NWC connection string"
      input → no toast, no DB change
- [ ] **Run 2 — bail at the budget window.** Palette → same command → paste
      Wallet A's URI → **Esc** on the *"Budget window"* quick-pick → no DB change
- [ ] **Run 3 — bail at the sats prompt.** Palette → same command → paste the URI
      → choose **"Daily budget window"** → **Esc** on the sats input → no DB change
- [ ] **Run 4 — the "Skip" path succeeds.** Palette → same command → paste the URI
      → choose **"Skip — set in my wallet app"** → success toast, and the DB now
      shows `encrypted_nwc_uri` non-null with `nwc_budget_sats` and
      `nwc_budget_window` **NULL**

Restore a budget before continuing (re-run the command, choose Daily / `100000`)
so §4 tests the normal configuration.

## 4. Add a non-custodial bounty — wallet already connected — [VS Code — creator]

- [ ] Open a test file, put the cursor in a test, run **Bounty: Add Bounty**, enter `2000` sats
- [ ] **No funding-mode quick-pick** appears (custodial disabled) and **no QR panel** opens
- [ ] The wallet picker (*"Which Lightning wallet should fund this bounty?"*) lists
      **"Use connected wallet — \<address\>"** first, with a detail line
      *"Address from your wallet's NWC connection string · connected \<date\>"*.
      That address is the `lud16` **embedded in Wallet A's NWC string by the wallet
      provider** — it identifies the funding wallet and may differ from the alias you
      use day-to-day; it is display-only and never a payout destination
- [ ] Choose it → toast *"✅ Bounty created: 2000 sats … Sats will move from your
      connected wallet when you approve a claim."*
- [ ] Lens above the test reads **"💰 Funded – Claimable (2000 sats) · Non-custodial"**
      (badge present)

**[DB]**

```bash
q "select id, amount_sats, funding_mode, invoice, payment_hash, invoice_paid, active from bounties order by created_at desc limit 1"
```

- [ ] `funding_mode='nwc'`, `invoice` NULL, `payment_hash` NULL, `invoice_paid=t`
- [ ] Note this `id` — later steps refer to it as `<bounty-id>`

### 4a. Cancel mid-create — [VS Code — creator]

- [ ] **Bounty: Add Bounty** → enter an amount → **Esc** on the wallet-picker step
      → re-run the `[DB]` query above: still the same bounty, no new row

## 5. Add a non-custodial bounty — no wallet connected (auto-connect)

This is the common first-run path.

- [ ] **[VS Code — creator]** Run **Bounty: Disconnect Lightning Wallet (NWC)** and
      confirm, so no NWC URI is stored (full disconnect coverage is §8)
- [ ] Run **Bounty: Add Bounty**, enter `1500` sats
- [ ] The **Connect Lightning Wallet (NWC)** flow launches **automatically** (the
      URI prompt appears without you running that command)
- [ ] Paste Wallet A's URI and complete the prompts as in §3
- [ ] After connecting, the bounty is created as NWC (badge present), no QR panel
- [ ] **Now the cancel variant:** disconnect the wallet again, run **Bounty: Add
      Bounty** → enter `1500` → **Esc** the auto-launched URI prompt → warning toast
      *"A connected Lightning wallet is required to create a bounty. Run 'Add Bounty'
      again after connecting your wallet."*
- [ ] **[DB]** `q "select count(*) from bounties where amount_sats = 1500"` — one row
      (from the successful run), not two
- [ ] Reconnect Wallet A before continuing

## 6. Claim + approve a non-custodial bounty

Uses the 2000-sat bounty from §4.

- [ ] **[VS Code — claimer]** Open the same workspace in a second VS Code window and
      connect Nostr as the **claimer** identity (§2, claimer nsec.app profile)
- [ ] Lens shows **"Funded – Claimable · Non-custodial"**; hover it → tooltip mentions
      *"non-custodial — funded from creator wallet on approval"*
- [ ] Run **Claim: Claim Bounty** (or click the lens) → enter Wallet B's LN address
- [ ] A **"Payout address privacy"** quick-pick appears with **"Share…"** (default)
      and **"Hide my Lightning address from the creator"** → press **Esc** first →
      the claim is cancelled, nothing sent
- [ ] Claim again, this time choose **Share** → lens flips to "Claim Pending · Non-custodial"
- [ ] **[VS Code — creator]** Switch to the creator window. If Nostr was connected
      after activation, confirm the **"✅ Approve Claim"** lens appears for the creator
      (it refreshes on connect); otherwise right-click the test → **Approve Claim** also works
- [ ] The confirmation modal *"Send 2000 sats to: \<Wallet B's address\>"* shows
      **"Yes, Approve Payout"** plus exactly **one** Cancel button (VS Code's native
      one — no duplicate)
- [ ] Click **Approve**, then within ~30–60 s (NWC reply timeout is 180 s):
  - [ ] **[Wallet]** Wallet A balance drops by 2000 sats + routing
  - [ ] **[Wallet]** Wallet B receives 2000 sats
  - [ ] **[VS Code — creator]** **Exactly one** toast — *"Claim approved – payout
        triggered!"*. **No** accompanying *"Failed to approve claim: Claim is not
        pending"* (the two must never appear together)

**[DB]**

```bash
q "select c.status, c.payout_txid, c.lnurl_private, b.active from claims c join bounties b on b.id = c.bounty_id order by c.claimed_at desc limit 1"
```

- [ ] `status='approved'`, `payout_txid` populated (the preimage), bounty `active=f`

### 6a-dup. Duplicate / concurrent approve is benign

Set up a fresh bounty + claim (repeat §4 then §6 through the claim), then:

- [ ] **[VS Code — creator]** While an approve is still processing (signer wait or
      payout in flight), click the **"✅ Approve Claim"** lens **again** → the second
      click is ignored with a neutral *"This claim is already being approved…"* — it
      does **not** fire a second `/approve`
- [ ] After the claim is fully approved, click Approve once more (or approve the same
      claim from a **second VS Code window** signed in as the creator) → you see a
      benign *"This claim was already approved — payout completed."*, **never** a red
      *"Failed to approve claim"* toast; no second payout
- [ ] Check the responses: VS Code **Help → Toggle Developer Tools → Network**, or
      re-issue the call yourself — **[Terminal]**:

      ```bash
      curl -s -i -X POST "$AUD/bounties/<bounty-id>/approve" \
        -H "Authorization: $(moneyauth)" \
        -H 'Content-Type: application/json' \
        -d '{"claimId":"<claim-id>"}'
      ```

      → **409** with `code: 'CLAIM_ALREADY_APPROVED'` (already paid) or
      `'CLAIM_IN_PROGRESS'` (mid-flight). Get `<claim-id>` from
      `q "select id, bounty_id, status from claims order by claimed_at desc limit 5"`

### 6a. Signer unresponsive (notice → re-pair, no silent stalls)

Every money-moving call (create / claim / approve / connect) mints a write-scope
credential needing a **live** signer. Timeout is **15 s** for these; the notice
carries a **per-operation** label (e.g. "payout approval", "bounty creation").

Set up another fresh bounty + pending claim first (§4 + §6 through the claim).

- [ ] **[VS Code — creator]** Close the nsec.app tab (or lock your signer app), then
      click **Approve** on the pending claim
- [ ] After ~5 s a **cancellable progress notification** appears — *"Waiting for your
      Nostr signer — payout approval…"* with *"Open your signer … and approve the
      request."* — so the user is never left staring at nothing
- [ ] Reopen the signer and approve a normal payout: on the **happy path** (signer
      open, auto-approving) the notice does **not** flash
- [ ] Repeat the signer-closed setup, click Approve, then click **Cancel** on the
      notice → the operation aborts immediately with **no error toast** and no sats
      moved (don't wait out the 15 s)
- [ ] Repeat again and let it run: at ~15 s the notice clears and the
      **Connect-Nostr QR webview opens** to re-pair (a stale/ended session is fixed
      by re-pairing, which mints a fresh auth event)
- [ ] Scan to re-pair in nsec.app → the approval **retries automatically** and the
      payout completes (no need to re-click Approve)
- [ ] Force a second timeout right after re-pairing (set nsec.app to ask per
      signature and ignore the request) → an error toast points at the signer's
      **permission settings** for Sattest, instead of looping the QR
- [ ] **[DB]** `q "select status from claims order by claimed_at desc limit 1"` — stays
      `pending` until a successful approve; no double-spend
- [ ] After a fresh **Nostr: Connect Nostr** pairing, approving does **not** require a
      separate per-signature tap (the connect URI requests `sign_event:22242` up front)
- [ ] The label matches the action: **Bounty: Add Bounty** with the signer closed shows
      "…— bounty creation…", **Claim: Claim Bounty** shows "…— claim…" (no blanket
      "payment authorization" on non-payout flows)

### 6b. Wallet offline / budget exceeded

- [ ] **[Wallet]** Break Wallet A's NWC: revoke/pause the connection in its app, or
      set the connection's budget to an amount smaller than the bounty
- [ ] **[VS Code]** Create a fresh NWC bounty (§4), claim it (§6), hit Approve
- [ ] **[VS Code — creator]** The toast surfaces the real cause (wallet unreachable /
      budget exceeded), and the backend returned **502** — confirm in
      **[Railway]** → **Logs**, or by replaying the approve curl from §6a-dup
- [ ] **[DB]** `q "select status from claims order by claimed_at desc limit 1"` — still `pending`
- [ ] **[Wallet]** Re-enable the connection / raise the budget → **[VS Code]** click
      Approve again → succeeds; `payout_txid` written

### 6c. LNURL pinning (Layer 4)

- [ ] **[Railway → Logs]** During the §6 approve, the log line shows the payout
      destination coming from `claim.claimant_lnurl` in the DB, **not** any value in
      the request body
- [ ] **[Terminal]** Create + claim a fresh bounty, then approve it yourself with a
      **different** `lnurl` injected into the body:

      ```bash
      curl -s -X POST "$AUD/bounties/<bounty-id>/approve" \
        -H "Authorization: $(moneyauth)" \
        -H 'Content-Type: application/json' \
        -d '{"claimId":"<claim-id>","lnurl":"attacker@example.com"}' | jq .
      ```

      → the extra field is ignored (it isn't in the schema) and **[Wallet]** Wallet B —
      the originally pinned address — receives the sats. Confirm with
      `q "select claimant_lnurl, payout_txid from claims where id = '<claim-id>'"`

### 6d. Private claim (hide payout address from creator)

- [ ] **[VS Code — creator]** Create a fresh NWC bounty (§4). Note its `<bounty-id>`
- [ ] **[VS Code — claimer]** **Claim: Claim Bounty** → enter Wallet B's address →
      choose **"Hide my Lightning address from the creator"**
- [ ] **[DB]**

      ```bash
      q "select lnurl_private, claimant_lnurl from claims order by claimed_at desc limit 1"
      ```

      → `lnurl_private = t`, and `claimant_lnurl` **is still stored** (privacy hides
      it, it doesn't drop it)
- [ ] **[VS Code — creator]** Hit Approve → the confirm modal reads *"Send N sats to:
      the claimant"* — the real LN address is **not** shown. Leave the modal open
- [ ] **[Terminal]** Check what the creator's client can actually see:

      ```bash
      curl -s "$AUD/bounties/<bounty-id>/pending-claim" -H "Authorization: $(readauth)" | jq .
      ```

      → `claimantLnurl: null`, `lnurlHidden: true` — the address never reaches the
      creator's client (check this response body, not just the UI)
- [ ] **[VS Code — creator]** Confirm the approval → **[Wallet]** Wallet B receives the
      sats; **[DB]** `payout_txid` written, `status='approved'` (the payout routes to
      the pinned address server-side even though the creator never saw it)

## 7. Remove a non-custodial bounty — [VS Code — creator]

- [ ] Create a fresh NWC bounty (§4) and **don't** claim it
- [ ] Run **Bounty: Remove Bounty** on that test
- [ ] **No LNURL refund prompt** appears (nothing was custodied)
- [ ] Confirm the modal → the lens disappears
- [ ] **[DB]** `q "select active from bounties where id = '<bounty-id>'"` → `f`
- [ ] **[Wallet]** Wallet A balance unchanged (no money was ever held)

## 8. Disconnect wallet — [VS Code — creator]

- [ ] With **no** wallet configured (run the disconnect once first if needed), run
      **Bounty: Disconnect Lightning Wallet (NWC)** → toast *"No Lightning wallet is
      currently connected."*
- [ ] Connect Wallet A again (§3), then run **Bounty: Disconnect Lightning Wallet
      (NWC)** → modal asks *"Disconnect your Lightning wallet?"*
- [ ] Press **Esc** / Cancel → **[DB]** the `users` row is unchanged (re-run the §3 query)
- [ ] Run it again, choose **Disconnect** → toast *"Lightning wallet disconnected."*
- [ ] **[DB]**

      ```bash
      q "select encrypted_nwc_uri, nwc_budget_sats, nwc_budget_window, nwc_updated_at from users where nostr_pubkey = '$(nak key public "$CREATOR_SEC")'"
      ```

      → all four columns NULL
- [ ] **Bounty: Add Bounty** now triggers the auto-connect flow again (§5)

### 8a. Disconnect without a live signer (revoke must always work)

- [ ] **[VS Code — creator]** Connect Nostr, connect a wallet, then **end the remote
      session in your signer app** (nsec.app → the Sattest connection → disconnect/revoke)
- [ ] Run **Bounty: Disconnect Lightning Wallet (NWC)** → it **succeeds** (toast
      *"Lightning wallet disconnected."*) with **no** signer round-trip, **no**
      "waiting on signer" notice, and **no** 15 s stall — disconnect uses the cached
      read credential (`DELETE /users/me/nwc` is `nostrAuth`, not `moneyAuth`)
- [ ] **[DB]** same query as §8 → all NWC columns NULL
- [ ] (Only if even the cached read credential has aged out — > 30 min idle) → the
      Connect-Nostr QR appears to re-pair, then disconnect completes. On any failure
      the toast also mentions revoking directly in your wallet app
- [ ] By contrast, **connecting** a wallet (§3) still requires the signer (it grants
      spending access — `PATCH /users/me/nwc` stays `moneyAuth`): with the signer
      session ended, **Bounty: Connect Lightning Wallet (NWC)** does *not* silently
      succeed — it prompts to re-pair

### 8b. Stranded NWC bounties

- [ ] **[VS Code]** Create an NWC bounty, claim it from the claimer window, and leave
      it pending
- [ ] **[VS Code — creator]** Run **Bounty: Disconnect Lightning Wallet (NWC)**
- [ ] Click **Approve** on the pending claim → backend returns 400/502 with a clear
      "wallet not connected" message, surfaced in the toast
- [ ] Reconnect Wallet A (§3) → click Approve again → succeeds

## 9. Backend rejects custodial while disabled — [Terminal]

With `ALLOW_CUSTODIAL_BOUNTIES` off (production default). Each call needs a fresh
`moneyauth` header (the nonce is single-use).

```bash
curl -s -X POST "$AUD/bounties" \
  -H "Authorization: $(moneyauth)" \
  -H 'Content-Type: application/json' \
  -d '{"testId":"checklist/custodial-probe","amountSats":1000,"fundingMode":"custodial"}' | jq .
```

- [ ] → **400** *"Custodial bounties are currently disabled. Connect a Lightning
      wallet (NWC) to create a bounty."*

Now the default-mode case, which must be run as a creator with **no** wallet
connected — disconnect first (§8), or use the claimer key
(`moneyauth "$CLAIMER_SEC"`), which has never connected one:

```bash
curl -s -X POST "$AUD/bounties" \
  -H "Authorization: $(moneyauth "$CLAIMER_SEC")" \
  -H 'Content-Type: application/json' \
  -d '{"testId":"checklist/no-wallet-probe","amountSats":1000}' | jq .
```

- [ ] → **400** *"Connect a Lightning wallet (NWC) before creating a non-custodial
      bounty"* (funding mode defaults to NWC, which requires a wallet)
- [ ] **[Railway → Logs]** No LNbits invoice is minted in either case, and
      **[DB]** `q "select count(*) from bounties where test_id like 'checklist/%'"` → `0`

## 10. Circuit breakers (security regressions) — [Railway] + [VS Code]

The caps are measured in **sats approved per window**, not claim count — so the
way to trip them is to set the cap below the bounty amount, not to approve many
claims.

- [ ] **Kill switch.** [Railway → Variables] set `PAYOUTS_ENABLED=false`, wait for the
      redeploy → [VS Code] approve a pending NWC claim → blocked with a
      "payouts temporarily disabled" error (**503**); the kill switch covers the NWC
      path too. **[DB]** claim stays `pending`
- [ ] Restore `PAYOUTS_ENABLED=true` and redeploy → the same approve now succeeds
- [ ] **Hourly cap.** [Railway] set `PAYOUT_CAP_HOURLY_SATS=1` → [VS Code] create,
      claim and approve a 2000-sat NWC bounty → **429**, toast surfaces the cap, and
      **[Railway → Logs]** shows *"Hourly payout cap exceeded"*. **[DB]** claim stays
      `pending`, nothing paid
- [ ] Restore the real `PAYOUT_CAP_HOURLY_SATS` (and check `PAYOUT_CAP_DAILY_SATS`
      wasn't consumed by the run) → approve again → succeeds
- [ ] **Anomaly alert.** [Railway] set `PAYOUT_ALERT_SATS=100` → approve a 2000-sat
      NWC bounty → the payout still completes **and** an alert lands in the
      `ALERT_WEBHOOK_URL` channel (check Slack/log sink) → restore the real threshold

## 11. Multi-window / per-repo — [VS Code]

- [ ] Open the same workspace in a second VS Code window
- [ ] Create a bounty in window 1
- [ ] Within ~30 s (after the activation refresh), the lens shows up in window 2
- [ ] Open a *different* repo workspace → bounties from repo A do **not** appear
      (repo-slug filter works)

## 12. Failure-toast rate limiting

- [ ] **[Railway]** Stop the backend service (or point `sattest.backendUrl` at a dead
      port such as `http://localhost:9` and reload)
- [ ] **[VS Code]** Open the workspace fresh — only **one** "Failed to load bounties
      from backend" toast (not several)
- [ ] Wait > 10 s, switch editors → the toast may appear again (cooldown reset is fine)
- [ ] Restore the backend / the real `backendUrl`

## 13. Database & migration — [Terminal] + [DB]

- [ ] Apply the latest migrations to the **staging** DB; no errors:

      ```bash
      cd sattest-backend && DATABASE_URL="$PGURL" npx drizzle-kit migrate
      ```

- [ ] `users` has the NWC columns and old rows have them NULL:

      ```bash
      q "select column_name, is_nullable from information_schema.columns where table_name='users' and column_name like 'nwc%' or column_name='encrypted_nwc_uri'"
      ```

- [ ] `bounties.funding_mode` exists; legacy rows read `'custodial'` but the handler
      always sets it explicitly on insert:

      ```bash
      q "select funding_mode, count(*) from bounties group by funding_mode"
      ```

- [ ] `bounties.invoice` and `bounties.payment_hash` are nullable in the actual schema:

      ```bash
      psql "$PGURL" -c '\d bounties'
      ```

- [ ] `claims.lnurl_private` exists (boolean, `NOT NULL DEFAULT false`); legacy claim
      rows read `false` (migration `0006_faithful_gabe_jones.sql`):

      ```bash
      psql "$PGURL" -c '\d claims'
      ```

## 14. Final sanity

- [ ] **[Railway → Logs]** Free of unhandled rejections across the whole run-through
- [ ] **[Railway → Logs]** No NWC URI plaintext — search the staging logs for
      `nostr+walletconnect://`; there must be zero hits
- [ ] **[VS Code]** No unexpected `console.error` / toasts in the extension's Output
      channel (**View → Output** → pick *Sattest* in the dropdown)
- [ ] **[Terminal]** Clean up the probe rows from §9 if any were created
- [ ] Bump the extension `version` in `sattest/package.json` before repackaging
- [ ] Tag the release, deploy the backend first, then publish the extension

---

## Rollback plan

If anything in §4–§10 fails in production:
1. [Railway] Set `PAYOUTS_ENABLED=false` on the backend (stops all approvals immediately)
2. Revert the backend to the previous tag
3. Withdraw the extension from the Marketplace (or pin users to the prior version)
4. NWC bounties never put funds on our host, so there's no float to reconcile; in-flight approvals simply fail closed and can be retried after rollback
5. Leaving `ALLOW_CUSTODIAL_BOUNTIES` unset keeps the safe non-custodial default; the `funding_mode` column is additive, so older rows are unaffected
