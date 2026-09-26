import { assertPublicHttpUrl, isBlockedAddress, readJsonCapped, readTextCapped } from './ssrf';

// Mock DNS resolution so hostname cases are deterministic and offline.
jest.mock('node:dns/promises', () => ({
    lookup: jest.fn(),
}));
import { lookup } from 'node:dns/promises';
const mockLookup = lookup as jest.MockedFunction<typeof lookup>;

const realNodeEnv = process.env.NODE_ENV;

afterAll(() => {
    process.env.NODE_ENV = realNodeEnv;
});

describe('isBlockedAddress', () => {
    it('blocks IPv4 loopback / private / link-local / CGNAT / reserved', () => {
        for (const addr of [
            '127.0.0.1',
            '10.0.0.1',
            '172.16.5.5',
            '172.31.255.255',
            '192.168.1.1',
            '169.254.169.254', // cloud metadata
            '100.64.0.1', // CGNAT
            '0.0.0.0',
            '224.0.0.1', // multicast
            '255.255.255.255',
        ]) {
            expect(isBlockedAddress(addr)).toBe(true);
        }
    });

    it('allows public IPv4', () => {
        for (const addr of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1']) {
            expect(isBlockedAddress(addr)).toBe(false);
        }
    });

    it('blocks IPv6 loopback / link-local / unique-local / mapped-private', () => {
        for (const addr of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:10.0.0.1']) {
            expect(isBlockedAddress(addr)).toBe(true);
        }
    });

    it('allows public IPv6 and mapped-public', () => {
        expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
        expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
    });

    it('blocks anything that is not a parseable IP (fail closed)', () => {
        expect(isBlockedAddress('not-an-ip')).toBe(true);
        expect(isBlockedAddress('')).toBe(true);
    });
});

describe('assertPublicHttpUrl — development (permissive)', () => {
    beforeEach(() => {
        process.env.NODE_ENV = 'development';
    });

    it('allows http://localhost and never resolves DNS', async () => {
        await expect(assertPublicHttpUrl('http://localhost:5000/x')).resolves.toBeUndefined();
        expect(mockLookup).not.toHaveBeenCalled();
    });

    it('allows a private IP in development', async () => {
        await expect(assertPublicHttpUrl('http://10.0.0.1/cb')).resolves.toBeUndefined();
    });

    it('still rejects a non-http(s) scheme', async () => {
        await expect(assertPublicHttpUrl('file:///etc/passwd')).rejects.toThrow(/non-http/);
    });
});

describe('assertPublicHttpUrl — production', () => {
    beforeEach(() => {
        process.env.NODE_ENV = 'production';
        mockLookup.mockReset();
    });

    it('rejects plaintext http://', async () => {
        await expect(assertPublicHttpUrl('http://example.com/x')).rejects.toThrow(/plaintext http/);
        expect(mockLookup).not.toHaveBeenCalled();
    });

    it('rejects a non-http(s) scheme', async () => {
        await expect(assertPublicHttpUrl('ftp://example.com')).rejects.toThrow(/non-http/);
    });

    it('rejects an unparseable URL', async () => {
        await expect(assertPublicHttpUrl('::::not a url')).rejects.toThrow(/invalid URL/i);
    });

    it('rejects an https URL whose literal host is private (no DNS)', async () => {
        await expect(assertPublicHttpUrl('https://10.0.0.1/x')).rejects.toThrow(/non-public/);
        expect(mockLookup).not.toHaveBeenCalled();
    });

    it('rejects the cloud-metadata literal address', async () => {
        await expect(assertPublicHttpUrl('https://169.254.169.254/latest/')).rejects.toThrow(
            /non-public/
        );
    });

    it('rejects a hostname that resolves to a private IP', async () => {
        mockLookup.mockResolvedValue([{ address: '192.168.0.5', family: 4 }] as never);
        await expect(assertPublicHttpUrl('https://evil.example.com/x')).rejects.toThrow(/non-public/);
        expect(mockLookup).toHaveBeenCalledWith('evil.example.com', { all: true });
    });

    it('rejects when ANY resolved address is private (rebinding-style split answer)', async () => {
        mockLookup.mockResolvedValue([
            { address: '93.184.216.34', family: 4 },
            { address: '127.0.0.1', family: 4 },
        ] as never);
        await expect(assertPublicHttpUrl('https://mixed.example.com/x')).rejects.toThrow(
            /non-public/
        );
    });

    it('rejects when DNS resolution fails', async () => {
        mockLookup.mockRejectedValue(new Error('ENOTFOUND'));
        await expect(assertPublicHttpUrl('https://nope.example.com/x')).rejects.toThrow(
            /could not resolve/
        );
    });

    it('allows a hostname that resolves only to public addresses', async () => {
        mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
        await expect(assertPublicHttpUrl('https://good.example.com/x')).resolves.toBeUndefined();
    });

    it('strips IPv6 brackets before classifying a literal host', async () => {
        await expect(assertPublicHttpUrl('https://[::1]/x')).rejects.toThrow(/non-public/);
    });
});

// ---------------------------------------------------------------------------
describe('readJsonCapped', () => {
    function streamOf(chunks: Buffer[]) {
        return (async function* () {
            for (const c of chunks) yield c;
        })();
    }

    it('parses a normal JSON body', async () => {
        const payload = JSON.stringify({ tag: 'payRequest', minSendable: 1000 });
        await expect(readJsonCapped({ body: streamOf([Buffer.from(payload)]) }))
            .resolves.toEqual({ tag: 'payRequest', minSendable: 1000 });
    });

    it('parses a body delivered in multiple chunks', async () => {
        const payload = JSON.stringify({ a: 1, b: 'x'.repeat(100) });
        const half = Math.floor(payload.length / 2);
        await expect(
            readJsonCapped({
                body: streamOf([Buffer.from(payload.slice(0, half)), Buffer.from(payload.slice(half))]),
            })
        ).resolves.toEqual({ a: 1, b: 'x'.repeat(100) });
    });

    it('rejects a body over the cap instead of buffering it', async () => {
        await expect(
            readJsonCapped({ body: streamOf([Buffer.alloc(70_000, 65)]) })
        ).rejects.toThrow(/exceeds 65536 bytes/);
    });

    it('rejects when the cap is exceeded across chunk boundaries', async () => {
        await expect(
            readJsonCapped({ body: streamOf([Buffer.alloc(40_000, 65), Buffer.alloc(40_000, 65)]) })
        ).rejects.toThrow(/exceeds/);
    });

    it('honours a custom cap', async () => {
        await expect(
            readJsonCapped({ body: streamOf([Buffer.alloc(2048, 65)]) }, 1024)
        ).rejects.toThrow(/exceeds 1024 bytes/);
    });

    it('throws rather than parsing when no bounded stream exists', async () => {
        await expect(readJsonCapped({ body: null })).rejects.toThrow(/bounded stream/);
        await expect(readJsonCapped({ body: undefined })).rejects.toThrow(/bounded stream/);
    });

    it('throws on invalid JSON within the cap', async () => {
        await expect(readJsonCapped({ body: streamOf([Buffer.from('not json')]) }))
            .rejects.toThrow();
    });
});

// ---------------------------------------------------------------------------
// Error paths need their own cap. `readJsonCapped` only guards the success
// branch, so every `!resp.ok` handler calling `.text()` left the whole
// mitigation one status code away from being bypassed: an attacker-controlled
// LNURL server answers non-2xx with an enormous body and we buffer all of it
// while composing the error message.
describe('readTextCapped', () => {
    function streamOf(chunks: Buffer[]) {
        return (async function* () {
            for (const c of chunks) yield c;
        })();
    }

    it('returns a short body unchanged', async () => {
        await expect(readTextCapped({ body: streamOf([Buffer.from('not found')]) }))
            .resolves.toBe('not found');
    });

    it('truncates an oversized body instead of buffering it', async () => {
        const result = await readTextCapped({ body: streamOf([Buffer.alloc(500_000, 65)]) });

        expect(result.length).toBeLessThan(2200);
        expect(result).toMatch(/truncated/);
    });

    it('truncates across chunk boundaries', async () => {
        const result = await readTextCapped({
            body: streamOf([Buffer.alloc(1500, 65), Buffer.alloc(1500, 66)]),
        });

        expect(result.length).toBeLessThan(2200);
        expect(result).toMatch(/truncated/);
    });

    it('honours a custom cap', async () => {
        const result = await readTextCapped({ body: streamOf([Buffer.alloc(500, 65)]) }, 100);
        expect(result.length).toBeLessThan(140);
    });

    it('returns empty rather than throwing when there is no stream', async () => {
        // These run on an already-failing request. Replacing the caller's real
        // error (the status code) with a read error would hide the problem.
        await expect(readTextCapped({ body: null })).resolves.toBe('');
        await expect(readTextCapped({ body: undefined })).resolves.toBe('');
    });

    it('returns what it read when the stream fails mid-body', async () => {
        const failing = (async function* () {
            yield Buffer.from('partial');
            throw new Error('socket reset');
        })();

        await expect(readTextCapped({ body: failing })).resolves.toBe('partial');
    });

    it('tears down an oversized stream rather than abandoning its socket', async () => {
        let cancelled = false;
        const body: any = (async function* () {
            yield Buffer.alloc(5000, 65);
        })();
        body.destroy = () => {
            cancelled = true;
        };

        await readTextCapped({ body }, 1000);

        expect(cancelled).toBe(true);
    });
});
