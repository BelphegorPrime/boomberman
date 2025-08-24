import { ThreatScoringEngine } from '../src/detection/ThreatScoringEngine.js';
import type {
    HTTPFingerprint,
    BehaviorMetrics,
    GeoLocation,
    ScoringWeights,
} from '../src/detection/types/index.js';

describe('ThreatScoringEngine', () => {
    let engine: ThreatScoringEngine;
    let defaultWeights: ScoringWeights;

    beforeEach(() => {
        defaultWeights = {
            fingerprint: 0.3,
            behavioral: 0.3,
            geographic: 0.2,
            reputation: 0.2,
        };
        engine = new ThreatScoringEngine(defaultWeights);
    });

    describe('constructor', () => {
        it('should create engine with valid weights', () => {
            expect(engine).toBeInstanceOf(ThreatScoringEngine);
            expect(engine.getWeights()).toEqual(defaultWeights);
        });

        it('should throw error for negative weights', () => {
            const invalidWeights = { fingerprint: -0.1, behavioral: 0.3, geographic: 0.2, reputation: 0.2 };
            expect(() => new ThreatScoringEngine(invalidWeights)).toThrow('All scoring weights must be non-negative');
        });

        it('should throw error for all zero weights', () => {
            const zeroWeights = { fingerprint: 0, behavioral: 0, geographic: 0, reputation: 0 };
            expect(() => new ThreatScoringEngine(zeroWeights)).toThrow('At least one scoring weight must be positive');
        });
    });

    describe('calculateScore', () => {
        let mockFingerprint: HTTPFingerprint;
        let mockBehavior: BehaviorMetrics;
        let mockGeo: GeoLocation;

        beforeEach(() => {
            mockFingerprint = {
                headerSignature: 'test-signature',
                missingHeaders: [],
                suspiciousHeaders: [],
                headerOrderScore: 0.8,
                automationSignatures: [],
            };

            mockBehavior = {
                requestInterval: 1000,
                navigationPattern: [],
                timingConsistency: 0.5,
                humanLikeScore: 0.7,
                sessionDuration: 60000,
            };

            mockGeo = {
                country: 'US',
                region: 'California',
                city: 'San Francisco',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 10,
                asn: 12345,
                organization: 'Test ISP',
            };
        });

        it('should return low suspicion score for legitimate traffic', () => {
            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeLessThan(30);
            expect(result.isSuspicious).toBe(false);
            expect(result.confidence).toBeGreaterThan(0.5);
            expect(result.reasons).toHaveLength(0);
        });

        it('should detect missing browser headers', () => {
            mockFingerprint.missingHeaders = ['Accept', 'Accept-Language'];

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'fingerprint',
                    description: expect.stringContaining('Missing 2 common browser headers'),
                })
            );
        });

        it('should detect automation signatures', () => {
            mockFingerprint.automationSignatures = ['selenium'];

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(20); // Adjusted for weighted scoring
            expect(result.isSuspicious).toBe(false); // May not be suspicious due to other low scores
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'fingerprint',
                    severity: 'high',
                    description: expect.stringContaining('Automation framework detected'),
                })
            );
        });

        it('should detect sub-human request intervals', () => {
            mockBehavior.requestInterval = 100; // Very fast

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'behavioral',
                    description: expect.stringContaining('Sub-human request interval'),
                })
            );
        });

        it('should detect high timing consistency', () => {
            mockBehavior.timingConsistency = 0.95; // Very consistent

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'behavioral',
                    description: expect.stringContaining('Highly consistent timing pattern'),
                })
            );
        });

        it('should detect low human-like behavior', () => {
            mockBehavior.humanLikeScore = 0.1; // Very robotic

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'behavioral',
                    description: expect.stringContaining('Low human-like behavior score'),
                })
            );
        });

        it('should detect VPN usage', () => {
            mockGeo.isVPN = true;

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'geographic',
                    description: 'Request originates from VPN endpoint',
                })
            );
        });

        it('should detect Tor usage with high penalty', () => {
            mockGeo.isTor = true;

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(5); // Adjusted for weighted scoring (geographic weight is 0.2)
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'geographic',
                    severity: 'high',
                    description: 'Request originates from Tor exit node',
                })
            );
        });

        it('should include reputation score when provided', () => {
            const reputation = 40;

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo, reputation);

            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'reputation',
                    description: expect.stringContaining('IP has reputation score of 40'),
                })
            );
        });

        it('should generate consistent fingerprints for same input', () => {
            const result1 = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);
            const result2 = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result1.fingerprint).toBe(result2.fingerprint);
        });

        it('should generate different fingerprints for different inputs', () => {
            const result1 = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            mockGeo.country = 'CN';
            const result2 = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result1.fingerprint).not.toBe(result2.fingerprint);
        });

        it('should include processing time in metadata', () => {
            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.metadata.processingTime).toBeGreaterThan(0);
            expect(result.metadata.timestamp).toBeGreaterThan(0);
            expect(result.metadata.detectorVersions.threatScoringEngine).toBe('1.0.0');
        });

        it('should cap suspicion score at 100', () => {
            // Create extremely suspicious request
            mockFingerprint.missingHeaders = ['Accept', 'Accept-Language', 'Accept-Encoding'];
            mockFingerprint.suspiciousHeaders = ['X-Bot', 'X-Automated'];
            mockFingerprint.automationSignatures = ['selenium', 'puppeteer'];
            mockFingerprint.headerOrderScore = 0.1;

            mockBehavior.requestInterval = 50;
            mockBehavior.timingConsistency = 0.99;
            mockBehavior.humanLikeScore = 0.05;

            mockGeo.isVPN = true;
            mockGeo.isProxy = true;
            mockGeo.isHosting = true;
            mockGeo.isTor = true;
            mockGeo.riskScore = 90;

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo, 80);

            expect(result.suspicionScore).toBeLessThanOrEqual(100);
            expect(result.isSuspicious).toBe(true);
        });
    });

    describe('combineScores', () => {
        it('should handle empty scores array', () => {
            const result = engine.calculateScore(
                { headerSignature: '', missingHeaders: [], suspiciousHeaders: [], headerOrderScore: 1, automationSignatures: [] },
                { requestInterval: 1000, navigationPattern: [], timingConsistency: 0.5, humanLikeScore: 0.7, sessionDuration: 60000 },
                { country: 'US', region: '', city: '', isVPN: false, isProxy: false, isHosting: false, isTor: false, riskScore: 0, asn: 0, organization: '' }
            );

            expect(result.suspicionScore).toBe(0);
        });

        it('should weight scores according to configuration', () => {
            const highFingerprintWeights = { fingerprint: 0.8, behavioral: 0.1, geographic: 0.05, reputation: 0.05 };
            const fingerprintEngine = new ThreatScoringEngine(highFingerprintWeights);

            const mockFingerprint: HTTPFingerprint = {
                headerSignature: 'test',
                missingHeaders: ['Accept', 'Accept-Language'],
                suspiciousHeaders: [],
                headerOrderScore: 0.8,
                automationSignatures: [],
            };

            const mockBehavior: BehaviorMetrics = {
                requestInterval: 1000,
                navigationPattern: [],
                timingConsistency: 0.5,
                humanLikeScore: 0.7,
                sessionDuration: 60000,
            };

            const mockGeo: GeoLocation = {
                country: 'US',
                region: '',
                city: '',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 0,
                organization: '',
            };

            const result = fingerprintEngine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            // Should be heavily influenced by fingerprint score
            expect(result.suspicionScore).toBeGreaterThan(10);
        });
    });

    describe('confidence calculation', () => {
        it('should have high confidence when all data sources available', () => {
            const mockFingerprint: HTTPFingerprint = {
                headerSignature: 'test',
                missingHeaders: ['Accept'],
                suspiciousHeaders: [],
                headerOrderScore: 0.8,
                automationSignatures: [],
            };

            const mockBehavior: BehaviorMetrics = {
                requestInterval: 100,
                navigationPattern: [],
                timingConsistency: 0.9,
                humanLikeScore: 0.2,
                sessionDuration: 60000,
            };

            const mockGeo: GeoLocation = {
                country: 'CN',
                region: '',
                city: '',
                isVPN: true,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 30,
                asn: 0,
                organization: '',
            };

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo, 25);

            expect(result.confidence).toBeGreaterThan(0.8);
        });

        it('should have lower confidence with conflicting scores', () => {
            const mockFingerprint: HTTPFingerprint = {
                headerSignature: 'test',
                missingHeaders: [],
                suspiciousHeaders: [],
                headerOrderScore: 0.9,
                automationSignatures: [],
            };

            const mockBehavior: BehaviorMetrics = {
                requestInterval: 50, // Very suspicious
                navigationPattern: [],
                timingConsistency: 0.95,
                humanLikeScore: 0.1,
                sessionDuration: 60000,
            };

            const mockGeo: GeoLocation = {
                country: 'US',
                region: '',
                city: '',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 5, // Low risk
                asn: 0,
                organization: '',
            };

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.confidence).toBeLessThan(0.9);
        });
    });

    describe('updateWeights', () => {
        it('should update weights successfully', () => {
            const newWeights = { fingerprint: 0.5, behavioral: 0.3, geographic: 0.1, reputation: 0.1 };

            engine.updateWeights(newWeights);

            expect(engine.getWeights()).toEqual(newWeights);
        });

        it('should validate new weights', () => {
            const invalidWeights = { fingerprint: -0.1, behavioral: 0.3, geographic: 0.2, reputation: 0.2 };

            expect(() => engine.updateWeights(invalidWeights)).toThrow('All scoring weights must be non-negative');
        });
    });

    describe('suspicious navigation patterns', () => {
        it('should detect admin panel access attempts', () => {
            const mockFingerprint: HTTPFingerprint = {
                headerSignature: 'test',
                missingHeaders: [],
                suspiciousHeaders: [],
                headerOrderScore: 0.8,
                automationSignatures: [],
            };

            const mockBehavior: BehaviorMetrics = {
                requestInterval: 1000,
                navigationPattern: ['/admin', '/wp-admin', '/login.php'],
                timingConsistency: 0.5,
                humanLikeScore: 0.7,
                sessionDuration: 60000,
            };

            const mockGeo: GeoLocation = {
                country: 'US',
                region: '',
                city: '',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 0,
                organization: '',
            };

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo);

            expect(result.suspicionScore).toBeGreaterThan(0);
            expect(result.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'behavioral',
                    description: expect.stringContaining('Suspicious navigation pattern detected'),
                })
            );
        });
    });

    describe('non-linear scaling', () => {
        it('should apply non-linear scaling for high scores', () => {
            // Create a request that would score very high to trigger non-linear scaling
            const mockFingerprint: HTTPFingerprint = {
                headerSignature: 'test',
                missingHeaders: ['Accept', 'Accept-Language', 'Accept-Encoding', 'Connection'],
                suspiciousHeaders: ['X-Bot', 'X-Automated', 'X-Selenium'],
                headerOrderScore: 0.1,
                automationSignatures: ['selenium', 'puppeteer'],
            };

            const mockBehavior: BehaviorMetrics = {
                requestInterval: 50,
                navigationPattern: ['/admin', '/wp-admin', '/login.php'],
                timingConsistency: 0.99,
                humanLikeScore: 0.05,
                sessionDuration: 60000,
            };

            const mockGeo: GeoLocation = {
                country: 'CN',
                region: '',
                city: '',
                isVPN: true,
                isProxy: true,
                isHosting: true,
                isTor: true,
                riskScore: 80,
                asn: 0,
                organization: '',
            };

            const result = engine.calculateScore(mockFingerprint, mockBehavior, mockGeo, 90);

            // Should be high due to multiple extreme factors
            expect(result.suspicionScore).toBeGreaterThan(60);
            expect(result.isSuspicious).toBe(true);
        });
    });
});