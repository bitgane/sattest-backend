# Security Policy

This service authenticates users with their Nostr identity and makes Lightning payouts on their behalf. Please report security problems privately so they can be fixed before anyone can use them to steal funds.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion.**

Report privately, using either of these:

- **GitHub private vulnerability reporting** (preferred): go to this repo's **Security** tab and choose **Report a vulnerability**.
- **Email:** bitgane@proton.me

Include:

- the affected endpoint, file, or commit
- steps to reproduce, or a proof of concept
- what an attacker could achieve (for example, "pay out another user's bounty" or "read a stored NWC connection")

Sattest is maintained by one person. You can expect an acknowledgement within 7 days, and updates as the fix progresses. Once the fix is deployed, the issue will be disclosed publicly and you will be credited, unless you ask not to be.

There is no paid bug bounty program.

## Supported versions

Only the latest commit on `master` is supported. The hosted instance is deployed from `master`, so fixes are not backported.

## In scope

Especially:

- **Unauthorized payouts:** approving, paying, or redirecting a bounty you don't own; paying a claim more than once; getting around the payout caps or the `PAYOUTS_ENABLED` kill switch.
- **Authentication:** forging or replaying the signed Nostr auth events (read or write scope), reusing nonces, or bypassing `AUTH_AUDIENCE` binding.
- **Stored wallet connections:** anything that exposes a user's NWC connection string, or the key that encrypts it.
- **Server-side request forgery (SSRF)** through the LNURL, Lightning address, or relay URLs the server fetches.
- **Leaking other users' data**, such as a claimant's hidden LNURL.

## Out of scope

- Vulnerabilities in a user's own Lightning wallet, NWC provider, or Nostr signer.
- Problems that need a misconfigured deployment. For example, running with `NODE_ENV=development` in production turns off several protections on purpose.
- Denial of service through sheer request volume.
- Findings from automated scanners that come without a working exploit.

## Testing

Test against your own local instance, not the hosted one. See the [README](README.md) for setup. Never test with wallets or funds that don't belong to you.
