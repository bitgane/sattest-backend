# sattest-backend

API server for **[Sattest](https://github.com/bitgane/sattest)**, the VS Code extension that attaches Lightning bounties to unit tests. The extension is the client. This service stores bounties and claims, authenticates users by their Nostr identity, and fires payouts over Nostr Wallet Connect (NIP-47) when a creator approves a claim.

Payouts are **non-custodial by default**: sats move from the bounty creator's own wallet to the claimant, and the backend never holds funds. An older custodial flow built on LNbits still exists, but it is off unless an operator enables it with `ALLOW_CUSTODIAL_BOUNTIES=true`.

## Stack

Node 22 · Express 5 · PostgreSQL with Drizzle ORM · nostr-tools · Alby SDK for NWC

## Running locally

```bash
git clone https://github.com/bitgane/sattest-backend.git
cd sattest-backend
npm install
cp .env.example .env   # then fill in the values, and set NODE_ENV=development
npm run migrate
npm run dev
```

You need a PostgreSQL database for `DATABASE_URL`. [`.env.example`](.env.example) documents every variable.

To point the extension at your local server, set `sattest.backendUrl` to `http://localhost:3000` in your VS Code **user** settings. The setting is machine-scoped, so a workspace `settings.json` cannot change it.

## Tests

```bash
npm test
```

The tests mock the database and supply their own environment defaults, so they run without Postgres or a `.env`.

## Authentication

Every request is authenticated with a signed Nostr event (NIP-42, kind `22242`), sent in the header `Authorization: Nostr <base64 event>`.

- **Read** endpoints accept an event whose content is `sattest-auth`.
- **Write** endpoints (anything that creates, claims, approves, or pays) require content `sattest-auth:write`. The event must also carry a single-use nonce from `POST /auth/nonce`.

The extension repo defines these values a second time. Contract tests in both repos pin them, so changing one side without the other fails CI.

## Deployment

The service is set up for Railway. [`railway.json`](railway.json) builds the app, runs migrations before each deploy, and then starts it. For a production deployment, set `NODE_ENV=production` and `AUTH_AUDIENCE` to the service's public URL; the server refuses to start in production without `AUTH_AUDIENCE`. The payout circuit breakers are also configured through environment variables, listed in `.env.example`.

## License

[MIT](LICENSE.md)
