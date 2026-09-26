import { z } from 'zod';
import { decode } from 'bolt11';
import { NOSTR_PUBKEY_RE, REPO_SLUG_RE } from './lib/http';

// Request-body validation schemas, extracted from index.ts so each route module
// can import just the schema it needs.

export const CreateBountySchema = z.object({
    testId: z.string().min(1, { message: 'testId is required' }),
    frontEndInvoice: z.string()
        .optional()
        .refine(
            (val) => {
                if (!val) return true;
                try {
                    decode(val);
                    return true;
                } catch {
                    return false;
                }
            },
            { message: 'Invalid BOLT11 Lightning invoice' }
        ),

    frontEndPaymentHash: z
        .string()
        .optional()
        .refine(
            (val) => {
                if (!val) return true; // allow undefined/empty
                return /^[0-9a-f]{64}$/i.test(val);
            },
            { message: 'Payment hash must be exactly 64 hexadecimal characters (0-9, a-f, A-F)' }
        )
        .refine(
            (val) => {
                if (!val) return true;
                return val.length === 64;
            },
            { message: 'Payment hash must be exactly 64 characters long' }
        ),
    amountSats: z
        .number()
        .int({ message: 'amountSats must be an integer' })
        .min(1, { message: 'amountSats must be at least 1 sat' })
        .max(50000, { message: 'amountSats cannot exceed 50,000 sats' }),
    memo: z.string().max(500, { message: 'memo too long (max 500 chars)' }).optional(),
    // Optional git repo slug ("owner/repo"). Provided by the extension when a
    // workspace has a configured git remote. Used as the primary scope for
    // unauthenticated listing via GET /bounties?repo=... and POST /bounties/filter.
    repo: z
        .string()
        .regex(REPO_SLUG_RE, { message: 'repo must look like "owner/repo"' })
        .optional(),
    // 'custodial' (default) funds via LNbits invoice like today. 'nwc' is the
    // non-custodial path: no up-front invoice, sats move from the creator's
    // own wallet on approval. Requires the user to have connected an NWC URI.
    fundingMode: z.enum(['custodial', 'nwc']).optional(),
});

// Body schema for PATCH /users/me/nwc. URI is the raw NIP-47 connection string;
// budget fields are informational (real enforcement lives in the user's wallet).
export const SetNwcSchema = z.object({
    uri: z.string().trim().min(1, { message: 'uri is required' }).max(4096),
    budgetSats: z.number().int().positive().max(50_000_000).optional(),
    budgetWindow: z.enum(['daily', 'weekly', 'monthly']).optional(),
});

export const DeactivateBountySchema = z.object({
    refundLnurl: z
        .string()
        .trim()
        .min(1, { message: 'refundLnurl cannot be empty' })
        .max(2048, { message: 'refundLnurl too long (max 2048 chars)' })
        .optional(),
});

export const FilterBountiesSchema = z.object({
    testIds: z
        .array(
            z.string()
                .min(1, { message: 'testId cannot be empty' })
                .max(500, { message: 'testId too long (max 500 chars)' })
        )
        .min(1, { message: 'testIds must contain at least one id' })
        .max(500, { message: 'testIds cannot exceed 500 entries per request' }),
});

export const ClaimBountySchema = z.object({
    lnurl: z
        .string()
        .trim()
        .min(1, { message: 'Valid lnurl is required' })
        .max(2048, { message: 'lnurl too long (max 2048 chars)' }),
    // Absent → false (share the destination with the creator, today's default).
    hideLnurl: z.boolean().optional(),
});

export const ApproveClaimSchema = z.object({
    claimId: z.string().uuid({ message: 'claimId must be a valid UUID' }),
    // The claimant identity the caller believes it is paying. Required whenever
    // more than one claim is open on the bounty (see the ambiguity guard in the
    // handler): claimId alone is not enough, because the client reads that id
    // from /pending-claim, which an attacker can influence by filing a claim.
    // Naming the pubkey moves the choice of recipient from the server's
    // ordering to the creator's explicit intent.
    claimantPubkey: z
        .string()
        .regex(NOSTR_PUBKEY_RE, { message: 'claimantPubkey must be a 64-char hex Nostr pubkey' })
        .optional(),
});
