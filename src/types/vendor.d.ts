// Ambient declarations for packages that ship no TypeScript types.
// These stubs are intentionally minimal — we only expose the shapes we use.

declare module 'bolt11' {
    interface PaymentRequestObject {
        satoshis?: number | null;
        millisatoshis?: string | null;
        payeeNodeKey?: string;
        tags?: Array<{ tagName: string; data: unknown }>;
    }
    export function decode(paymentRequest: string): PaymentRequestObject;
}

declare module 'bech32' {
    export function decode(str: string, limit?: number): { prefix: string; words: number[] };
    export function fromWords(words: number[]): number[];
    export function toWords(bytes: number[]): number[];
    export function encode(prefix: string, words: number[], limit?: number): string;
}
