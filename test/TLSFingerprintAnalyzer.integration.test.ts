import { HTTPFingerprintAnalyzer } from '../src/detection/analyzers/HTTPFingerprintAnalyzer.js';
import { ThreatScoringEngine } from '../src/detection/ThreatScoringEngine.js';
import { BehaviorMetrics } from '../src/detection/types/BehaviorMetrics.js';
import { GeoLocation } from '../src/detection/types/GeoLocation.js';
import { Request } from 'express';


// Mock TLS socket for integration testing
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

// Helper functions
function createMockRequest(headers: Record<string, string>, tlsOptions?: any): Request {
    const mockSocket = tlsOptions ? new MockTLSSocket(tlsOptions) : { encrypted: false };

    return {
        headers,
        rawHeaders: Object.entries(headers).flat(),
        socket: mockSocket,
        method: 'GET',
        url: '/',
        ip: '192.168.1.1'
    } as any;
}

function createMockBehaviorMetrics(): BehaviorMetrics {
    return {
        requestInterval: 1000,
        navigationPattern: [],
        timingConsistency: 0.5,
        humanLikeScore: 0.8,
        sessionDuration: 60000
    };
}

function createMockGeoLocation(): GeoLocation {
    return {
        country: 'US',
        region: 'CA',
        city: 'San Francisco',
        isVPN: false,
        isProxy: false,
        isHosting: false,
        isTor: false,
        riskScore: 10,
        asn: 15169,
        organization: 'Google LLC'
    };
}

describe('TLS Fingerprinting Integration Tests', () => {
    let httpAnalyzer: HTTPFingerprintAnalyzer;
    let scoringEngine: ThreatScoringEngine;

    beforeEach(() => {
        httpAnalyzer = new HTTPFingerprintAnalyzer({
            tls: {
                enabled: true,
                analysisTimeout: 100,
                enableConsistencyCheck: true
            }
        });

        scoringEngine = new ThreatScoringEngine({
            fingerprint: 0.4,
            behavioral: 0.3,
            geographic: 0.2,
            reputation: 0.1
        });
    });

    describe('End-to-End TLS Detection', () => {
        test('should detect legitimate browser with modern TLS', () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0'
            }, {
                protocol: 'TLSv1.3',
                cipher: { name: 'TLS_AES_256_GCM_SHA384' }
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(result.suspicionScore).toBeLessThan(40);
            expect(result.isSuspicious).toBe(true); // 36 is above the 30 threshold
            expect(fingerprint.tlsFingerprintData?.consistencyScore).toBeGreaterThan(0.8);
            expect(fingerprint.tlsFingerprintData?.isKnownBotPattern).toBe(false);
        });

        test('should detect curl-like automation tool', () => {
            const req = createMockRequest({
                'User-Agent': 'curl/7.68.0',
                'Accept': '*/*',
                'Host': 'example.com'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-SHA' }
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(result.suspicionScore).toBeGreaterThan(40);
            expect(result.isSuspicious).toBe(true);
            expect(fingerprint.automationSignatures).toContain('curl');
            expect(fingerprint.tlsFingerprintData?.consistencyScore).toBeLessThan(1.0);
        });

        test('should detect Python requests library', () => {
            const req = createMockRequest({
                'User-Agent': 'python-requests/2.25.1',
                'Accept-Encoding': 'gzip, deflate',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(result.suspicionScore).toBeGreaterThan(40);
            expect(result.isSuspicious).toBe(true);
            expect(fingerprint.automationSignatures).toContain('python-requests');
        });

        test('should detect Selenium WebDriver', () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'webdriver': 'true' // Selenium-specific header
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(result.suspicionScore).toBeGreaterThan(40);
            expect(result.isSuspicious).toBe(true);
            expect(fingerprint.suspiciousHeaders).toContain('webdriver');
        });
    });

    describe('TLS/HTTP Consistency Detection', () => {
        test('should flag inconsistent TLS version with modern headers', () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none'
            }, {
                protocol: 'TLSv1', // Old TLS version
                cipher: { name: 'RC4-SHA' } // Weak cipher
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(fingerprint.tlsFingerprintData?.consistencyScore).toBeLessThan(0.7);
            expect(result.suspicionScore).toBeGreaterThan(20);

            const tlsReasons = result.reasons.filter(r =>
                r.description.includes('TLS') || r.description.includes('inconsistency')
            );
            expect(tlsReasons.length).toBeGreaterThan(0);
        });

        test('should handle missing TLS data gracefully', () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate'
            }); // No TLS options - HTTP request

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            expect(fingerprint.tlsFingerprintData?.cipherSuites).toEqual([]);
            expect(fingerprint.tlsFingerprintData?.consistencyScore).toBe(1.0);
            expect(result.suspicionScore).toBeLessThan(40); // Should still be reasonably low for legitimate headers
        });
    });

    describe('Performance and Error Handling', () => {
        test('should complete TLS analysis within timeout', async () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const startTime = process.hrtime.bigint();
            const fingerprint = httpAnalyzer.analyze(req);
            const endTime = process.hrtime.bigint();

            const duration = Number(endTime - startTime) / 1_000_000; // Convert to milliseconds

            expect(duration).toBeLessThan(200); // Should complete quickly
            expect(fingerprint.tlsFingerprintData).toBeDefined();
        });

        test('should handle malformed TLS socket data', () => {
            const req = createMockRequest({
                'User-Agent': 'test-agent'
            }, {
                protocol: null,
                cipher: null,
                session: null
            });

            const fingerprint = httpAnalyzer.analyze(req);

            expect(fingerprint.tlsFingerprintData?.tlsVersion).toBe('unknown');
            expect(fingerprint.tlsFingerprintData?.cipherSuites).toEqual([]);
            expect(fingerprint.tlsFingerprintData?.isKnownBotPattern).toBe(false);
        });
    });

    describe('Configuration Integration', () => {
        test('should respect disabled TLS fingerprinting in HTTP analyzer', () => {
            const disabledAnalyzer = new HTTPFingerprintAnalyzer({
                tls: {
                    enabled: false,
                    analysisTimeout: 100,
                    enableConsistencyCheck: false
                }
            });

            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const fingerprint = disabledAnalyzer.analyze(req);

            expect(fingerprint.tlsFingerprintData?.cipherSuites).toEqual([]);
            expect(fingerprint.tlsFingerprintData?.ja3Hash).toBeUndefined();
        });

        test('should use custom TLS configuration', () => {
            const customAnalyzer = new HTTPFingerprintAnalyzer({
                tls: {
                    enabled: true,
                    analysisTimeout: 50,
                    enableConsistencyCheck: false,
                    botPatterns: [{
                        name: 'custom-test-pattern',
                        tlsVersionPattern: /^771$/,
                        confidence: 0.5,
                        description: 'Custom test pattern'
                    }]
                }
            });

            const req = createMockRequest({
                'User-Agent': 'test-agent'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'AES256-SHA' }
            });

            const fingerprint = customAnalyzer.analyze(req);

            expect(fingerprint.tlsFingerprintData?.consistencyScore).toBe(1.0); // Consistency check disabled
            expect(fingerprint.tlsFingerprintData?.isKnownBotPattern).toBe(true); // Should match custom pattern
        });
    });

    describe('Scoring Engine Integration', () => {
        test('should incorporate TLS scores into final threat assessment', () => {
            // Create a request that should trigger TLS-based detection
            const req = createMockRequest({
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }, {
                protocol: 'TLSv1.2',
                cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            // Should have reasons related to both HTTP and TLS fingerprinting
            const fingerprintReasons = result.reasons.filter(r => r.category === 'fingerprint');
            expect(fingerprintReasons.length).toBeGreaterThan(1);

            // Should have high suspicion score due to automation detection
            expect(result.suspicionScore).toBeGreaterThan(40);
        });

        test('should provide detailed reasoning for TLS-based detections', () => {
            const req = createMockRequest({
                'User-Agent': 'Mozilla/5.0 (compatible; automation)',
                'Accept': '*/*'
            }, {
                protocol: 'TLSv1', // Old version
                cipher: { name: 'RC4-SHA' } // Weak cipher
            });

            const fingerprint = httpAnalyzer.analyze(req);
            const behavior = createMockBehaviorMetrics();
            const geo = createMockGeoLocation();

            const result = scoringEngine.calculateScore(fingerprint, behavior, geo);

            const tlsReasons = result.reasons.filter(r =>
                r.description.includes('TLS') ||
                r.description.includes('cipher') ||
                r.description.includes('version')
            );

            expect(tlsReasons.length).toBeGreaterThan(0);
            expect(result.metadata.geoData).toBeDefined();
            expect(result.metadata.behaviorData).toBeDefined();
        });
    });
});