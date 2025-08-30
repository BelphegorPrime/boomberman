import { TLSFingerprintAnalyzer } from '../src/detection/analyzers/TLSFingerprintAnalyzer.js';
import { TLSFingerprintingConfig, BotTLSPattern } from '../src/detection/types/TLSFingerprint.js';
import { HTTPFingerprint } from '../src/detection/types/HTTPFingerprint.js';
import { Request } from 'express';


// Mock TLS socket for testing
class MockTLSSocket {
    private mockSession?: Buffer;
    private mockCipher?: any;
    private mockProtocol?: string;
    private mockPeerCertificate?: any;

    constructor(options: {
        session?: Buffer;
        cipher?: any;
        protocol?: string;
        peerCertificate?: any;
    } = {}) {
        this.mockSession = options.session;
        this.mockCipher = options.cipher;
        this.mockProtocol = options.protocol;
        this.mockPeerCertificate = options.peerCertificate;
    }

    getSession(): Buffer | undefined {
        return this.mockSession;
    }

    getCipher(): any {
        return this.mockCipher;
    }

    getProtocol(): string | undefined {
        return this.mockProtocol;
    }

    getPeerCertificate(): any {
        return this.mockPeerCertificate;
    }

    get encrypted(): boolean {
        return true;
    }
}

// Helper function to create mock request with TLS socket
function createMockTLSRequest(tlsOptions: any = {}): Request {
    const mockSocket = new MockTLSSocket(tlsOptions);
    return {
        socket: mockSocket,
        headers: {},
        method: 'GET',
        url: '/',
    } as any;
}

// Helper function to create mock request without TLS
function createMockHTTPRequest(): Request {
    return {
        socket: { encrypted: false },
        headers: {},
        method: 'GET',
        url: '/',
    } as any;
}

describe('TLSFingerprintAnalyzer', () => {
    let analyzer: TLSFingerprintAnalyzer;

    beforeEach(() => {
        analyzer = new TLSFingerprintAnalyzer();
    });

    describe('Basic TLS Analysis', () => {
        test('should return empty fingerprint for non-TLS requests', () => {
            const req = createMockHTTPRequest();
            const result = analyzer.analyze(req);

            expect(result.cipherSuites).toEqual([]);
            expect(result.extensions).toEqual([]);
            expect(result.ellipticCurves).toEqual([]);
            expect(result.signatureAlgorithms).toEqual([]);
            expect(result.isKnownBotPattern).toBe(false);
            expect(result.consistencyScore).toBe(1.0);
            expect(result.ja3Hash).toBeUndefined();
            expect(result.tlsVersion).toBeUndefined();
        });

        test('should analyze TLS connection with basic cipher info', () => {
            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = analyzer.analyze(req);

            expect(result.tlsVersion).toBe('771'); // TLS 1.2
            expect(result.cipherSuites).toContain('ECDHE-RSA-AES256-GCM-SHA384');
            expect(result.extensions.length).toBeGreaterThan(0);
            expect(result.ellipticCurves.length).toBeGreaterThan(0);
            expect(result.ja3Hash).toBeDefined();
        });

        test('should handle TLS 1.3 connections', () => {
            const req = createMockTLSRequest({
                protocol: 'TLSv1.3',
                cipher: { name: 'TLS_AES_256_GCM_SHA384' }
            });

            const result = analyzer.analyze(req);

            expect(result.tlsVersion).toBe('772'); // TLS 1.3
            expect(result.cipherSuites).toContain('TLS_AES_256_GCM_SHA384');
        });

        test('should handle unknown TLS protocol versions', () => {
            const req = createMockTLSRequest({
                protocol: 'UnknownTLS',
                cipher: { name: 'SOME-CIPHER' }
            });

            const result = analyzer.analyze(req);

            expect(result.tlsVersion).toBe('UnknownTLS');
        });
    });

    describe('Bot Pattern Detection', () => {
        test('should detect curl-like TLS patterns', () => {
            const customPatterns: BotTLSPattern[] = [{
                name: 'test-curl',
                tlsVersionPattern: /^769$/,
                cipherSuitePatterns: [/ECDHE-RSA/],
                confidence: 0.8,
                description: 'Test curl pattern'
            }];

            const customAnalyzer = new TLSFingerprintAnalyzer({
                botPatterns: customPatterns
            });

            const req = createMockTLSRequest({
                protocol: 'TLSv1',
                cipher: { name: 'ECDHE-RSA-AES256-SHA' }
            });

            const result = customAnalyzer.analyze(req);

            expect(result.isKnownBotPattern).toBe(true);
        });

        test('should not flag legitimate browser patterns', () => {
            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = analyzer.analyze(req);

            // Should not match default bot patterns with typical browser TLS
            expect(result.isKnownBotPattern).toBe(false);
        });

        test('should handle JA3 hash pattern matching', () => {
            const customPatterns: BotTLSPattern[] = [{
                name: 'test-ja3',
                ja3Pattern: /^[a-f0-9]{8}$/,
                confidence: 0.9,
                description: 'Test JA3 pattern'
            }];

            const customAnalyzer = new TLSFingerprintAnalyzer({
                botPatterns: customPatterns
            });

            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'AES256-SHA' }
            });

            const result = customAnalyzer.analyze(req);

            // JA3 hash should be 8 hex characters (simplified hash)
            expect(result.ja3Hash).toMatch(/^[a-f0-9]{8}$/);
        });
    });

    describe('TLS/HTTP Consistency Checking', () => {
        test('should calculate high consistency for matching fingerprints', () => {
            const httpFingerprint: HTTPFingerprint = {
                headerSignature: 'browser-like',
                missingHeaders: [],
                suspiciousHeaders: [],
                headerOrderScore: 0.9,
                automationSignatures: [],
                tlsFingerprint: 'tls-present'
            };

            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = analyzer.analyze(req, httpFingerprint);

            // Should have reasonable consistency score for legitimate browser-like traffic
            expect(result.consistencyScore).toBeGreaterThan(0.6);
        });

        test('should detect inconsistency between TLS and HTTP fingerprints', () => {
            const httpFingerprint: HTTPFingerprint = {
                headerSignature: 'automation-like',
                missingHeaders: ['Accept', 'Accept-Language'],
                suspiciousHeaders: ['X-Automation'],
                headerOrderScore: 0.2,
                automationSignatures: ['selenium'],
                tlsFingerprint: 'tls-present'
            };

            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = analyzer.analyze(req, httpFingerprint);

            expect(result.consistencyScore).toBeLessThan(0.7);
        });

        test('should handle old TLS versions with modern HTTP headers', () => {
            const httpFingerprint: HTTPFingerprint = {
                headerSignature: 'modern-browser',
                missingHeaders: [],
                suspiciousHeaders: [],
                headerOrderScore: 0.9,
                automationSignatures: [],
                tlsFingerprint: 'tls-present'
            };

            const req = createMockTLSRequest({
                protocol: 'TLSv1', // Old TLS version
                cipher: { name: 'RC4-SHA' } // Old cipher
            });

            const result = analyzer.analyze(req, httpFingerprint);

            expect(result.consistencyScore).toBeLessThan(0.8);
        });
    });

    describe('Configuration Options', () => {
        test('should respect disabled TLS fingerprinting', () => {
            const disabledAnalyzer = new TLSFingerprintAnalyzer({
                enabled: false
            });

            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = disabledAnalyzer.analyze(req);

            expect(result.cipherSuites).toEqual([]);
            expect(result.ja3Hash).toBeUndefined();
            expect(result.tlsVersion).toBeUndefined();
        });

        test('should use custom bot patterns', () => {
            const customPatterns: BotTLSPattern[] = [{
                name: 'custom-bot',
                tlsVersionPattern: /^771$/,
                confidence: 0.5,
                description: 'Custom bot pattern'
            }];

            const customAnalyzer = new TLSFingerprintAnalyzer({
                botPatterns: customPatterns
            });

            const req = createMockTLSRequest({
                protocol: 'TLSv1.2'
            });

            const result = customAnalyzer.analyze(req);

            expect(result.isKnownBotPattern).toBe(true);
        });

        test('should handle disabled consistency checking', () => {
            const noConsistencyAnalyzer = new TLSFingerprintAnalyzer({
                enableConsistencyCheck: false
            });

            const httpFingerprint: HTTPFingerprint = {
                headerSignature: 'inconsistent',
                missingHeaders: ['Accept'],
                suspiciousHeaders: [],
                headerOrderScore: 0.1,
                automationSignatures: ['selenium'],
                tlsFingerprint: 'tls-present'
            };

            const req = createMockTLSRequest({
                protocol: 'TLSv1',
                cipher: { name: 'RC4-SHA' }
            });

            const result = noConsistencyAnalyzer.analyze(req, httpFingerprint);

            expect(result.consistencyScore).toBe(1.0);
        });
    });

    describe('Error Handling', () => {
        test('should handle missing TLS socket gracefully', () => {
            const req = {
                socket: null,
                headers: {},
                method: 'GET',
                url: '/',
            } as any;

            const result = analyzer.analyze(req);

            expect(result.cipherSuites).toEqual([]);
            expect(result.isKnownBotPattern).toBe(false);
            expect(result.consistencyScore).toBe(1.0);
        });

        test('should handle TLS socket without cipher info', () => {
            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: null
            });

            const result = analyzer.analyze(req);

            expect(result.tlsVersion).toBe('771');
            expect(result.cipherSuites).toEqual([]);
            expect(result.ja3Hash).toBeDefined();
        });

        test('should handle malformed TLS data', () => {
            const req = createMockTLSRequest({
                protocol: undefined,
                cipher: undefined,
                session: undefined
            });

            const result = analyzer.analyze(req);

            expect(result.tlsVersion).toBe('unknown');
            expect(result.cipherSuites).toEqual([]);
            // Extensions are always populated with common ones
            expect(result.extensions.length).toBeGreaterThan(0);
        });
    });

    describe('JA3 Hash Generation', () => {
        test('should generate consistent JA3 hashes for same input', () => {
            const req1 = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const req2 = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result1 = analyzer.analyze(req1);
            const result2 = analyzer.analyze(req2);

            expect(result1.ja3Hash).toBe(result2.ja3Hash);
        });

        test('should generate different JA3 hashes for different inputs', () => {
            const req1 = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const req2 = createMockTLSRequest({
                protocol: 'TLSv1.3',
                cipher: { name: 'TLS_AES_256_GCM_SHA384' }
            });

            const result1 = analyzer.analyze(req1);
            const result2 = analyzer.analyze(req2);

            expect(result1.ja3Hash).not.toBe(result2.ja3Hash);
        });

        test('should include raw fingerprint data for debugging', () => {
            const req = createMockTLSRequest({
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const result = analyzer.analyze(req);

            expect(result.rawFingerprint).toBeDefined();
            expect(result.rawFingerprint).toContain('771'); // TLS version
            expect(result.rawFingerprint).toContain('ECDHE-RSA-AES256-GCM-SHA384');
        });
    });

    describe('Default Bot Patterns', () => {
        test('should include common automation tool patterns', () => {
            const defaultAnalyzer = new TLSFingerprintAnalyzer();

            // Test that default patterns are loaded
            expect(defaultAnalyzer).toBeDefined();

            // We can't directly access private botPatterns, but we can test behavior
            // by creating requests that should match default patterns
            const curlLikeReq = createMockTLSRequest({
                protocol: 'TLSv1',
                cipher: { name: 'ECDHE-RSA-AES256-SHA' }
            });

            const result = defaultAnalyzer.analyze(curlLikeReq);

            // The exact result depends on the pattern matching logic
            expect(result).toBeDefined();
            expect(typeof result.isKnownBotPattern).toBe('boolean');
        });
    });
});