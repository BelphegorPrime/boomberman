import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express, { Request, Response, NextFunction } from 'express';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { detectionErrorHandler } from '../src/detection/ErrorHandler.js';
import { healthMonitor } from '../src/detection/HealthMonitor.js';
import { DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration.js';

// Create test app
const createTestApp = (middleware: EnhancedBotDetectionMiddleware) => {
    const app = express();

    app.use(middleware.middleware);

    app.get('/test', (req: Request, res: Response) => {
        res.json({
            success: true,
            detectionResult: req.detectionResult,
            detectionMetrics: req.detectionMetrics,
            correlationId: req.correlationId,
            detectionError: req.detectionError,
        });
    });

    app.get('/health', async (req: Request, res: Response) => {
        const health = await healthMonitor.getHealth();
        res.json(health);
    });

    return app;
};

describe('Enhanced Bot Detection Error Handling Integration', () => {
    let middleware: EnhancedBotDetectionMiddleware;
    let app: express.Application;

    beforeEach(() => {
        // Reset error handler state
        detectionErrorHandler.resetErrorStats();
        healthMonitor.resetCache();

        // Create middleware with test configuration
        middleware = new EnhancedBotDetectionMiddleware({
            ...DEFAULT_DETECTION_CONFIG,
            enabled: true,
        });

        app = createTestApp(middleware);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should handle geo service failures gracefully', async () => {
        // Mock GeoAnalyzer to fail
        const mockGeoAnalyzer = {
            analyze: jest.fn().mockRejectedValue(new Error('Geo service unavailable')),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        // Replace the analyzer in middleware (this is a bit hacky but works for testing)
        (middleware as any).geoAnalyzer = mockGeoAnalyzer;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.detectionResult).toBeDefined();
        expect(response.body.detectionResult.metadata.geoData).toBeDefined();

        // Should have fallback geo data
        expect(response.body.detectionResult.metadata.geoData.country).toBe('unknown');
    });

    test('should handle HTTP fingerprinting failures gracefully', async () => {
        // Mock HTTPFingerprintAnalyzer to fail
        const mockFingerprintAnalyzer = {
            analyze: jest.fn().mockImplementation(() => {
                throw new Error('Fingerprinting failed');
            }),
        };

        (middleware as any).httpAnalyzer = mockFingerprintAnalyzer;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.detectionResult).toBeDefined();

        // Should have used fallback fingerprinting
        expect(response.body.detectionResult.fingerprint).toMatch(/^basic-/);
    });

    test('should handle behavior analysis failures gracefully', async () => {
        // Mock BehaviorAnalyzer to fail
        const mockBehaviorAnalyzer = {
            analyze: jest.fn().mockImplementation(() => {
                throw new Error('Behavior analysis failed');
            }),
        };

        (middleware as any).behaviorAnalyzer = mockBehaviorAnalyzer;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.detectionResult).toBeDefined();
        expect(response.body.detectionResult.metadata.behaviorData).toBeDefined();

        // Should have neutral behavior metrics
        expect(response.body.detectionResult.metadata.behaviorData.humanLikeScore).toBe(0.5);
    });

    test('should handle scoring engine failures gracefully', async () => {
        // Mock ThreatScoringEngine to fail
        const mockScoringEngine = {
            calculateScore: jest.fn().mockImplementation(() => {
                throw new Error('Scoring engine failed');
            }),
        };

        (middleware as any).scoringEngine = mockScoringEngine;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.detectionResult).toBeDefined();
        expect(response.body.detectionError).toBeDefined();

        // Should have fallback detection result
        expect(response.body.detectionResult.metadata.fallbackReason).toBe('Scoring engine failure');
    });

    test('should handle complete middleware failure gracefully', async () => {
        // Mock middleware to throw error in main execution
        const originalMiddleware = middleware.middleware;
        middleware.middleware = jest.fn().mockImplementation(async (req: Request, res: Response, next: NextFunction) => {
            // Simulate a critical error
            throw new Error('Critical middleware failure');
        });

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(500); // Should result in 500 error since we're not catching it in the test app

        // The error should be handled by Express error handling
    });

    test('should handle timeout scenarios', async () => {
        // Mock all analyzers to be slow
        const slowOperation = () => new Promise(resolve => setTimeout(resolve, 100));

        const mockGeoAnalyzer = {
            analyze: jest.fn().mockImplementation(slowOperation),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        const mockFingerprintAnalyzer = {
            analyze: jest.fn().mockImplementation(slowOperation),
        };

        const mockBehaviorAnalyzer = {
            analyze: jest.fn().mockImplementation(slowOperation),
        };

        (middleware as any).geoAnalyzer = mockGeoAnalyzer;
        (middleware as any).httpAnalyzer = mockFingerprintAnalyzer;
        (middleware as any).behaviorAnalyzer = mockBehaviorAnalyzer;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.detectionResult).toBeDefined();

        // Should have timeout fallback result
        expect(response.body.detectionResult.metadata.timeoutOccurred).toBe(true);
    });

    test('should maintain error statistics', async () => {
        // Generate some errors
        const mockGeoAnalyzer = {
            analyze: jest.fn().mockRejectedValue(new Error('Geo service unavailable')),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        (middleware as any).geoAnalyzer = mockGeoAnalyzer;

        // Make multiple requests to generate errors
        for (let i = 0; i < 3; i++) {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .expect(200);
        }

        const errorStats = detectionErrorHandler.getErrorStats();
        expect(errorStats.errorCounts).toBeDefined();
        expect(Object.keys(errorStats.errorCounts).length).toBeGreaterThan(0);
    });

    test('should provide health status endpoint', async () => {
        const response = await request(app)
            .get('/health')
            .expect(200);

        expect(response.body).toMatchObject({
            status: expect.any(String),
            timestamp: expect.any(Number),
            components: expect.objectContaining({
                errorHandler: expect.objectContaining({
                    status: expect.any(String),
                    message: expect.any(String),
                }),
                geoAnalyzer: expect.objectContaining({
                    status: expect.any(String),
                    message: expect.any(String),
                }),
                circuitBreakers: expect.objectContaining({
                    status: expect.any(String),
                    message: expect.any(String),
                }),
            }),
            metrics: expect.objectContaining({
                totalErrors: expect.any(Number),
                errorRate: expect.any(Number),
                averageResponseTime: expect.any(Number),
            }),
        });
    });

    test('should handle circuit breaker activation', async () => {
        // Mock GeoAnalyzer to consistently fail
        const mockGeoAnalyzer = {
            analyze: jest.fn().mockRejectedValue(new Error('Persistent geo service failure')),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        (middleware as any).geoAnalyzer = mockGeoAnalyzer;

        // Make enough requests to trigger circuit breaker
        for (let i = 0; i < 10; i++) {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .expect(200);
        }

        // Check circuit breaker state
        const geoCircuitBreaker = detectionErrorHandler.getGeoCircuitBreaker();
        const stats = geoCircuitBreaker.getStats();

        // Circuit breaker should be open or have recorded failures
        expect(stats.failureCount).toBeGreaterThan(0);
    });

    test('should handle mixed success and failure scenarios', async () => {
        let callCount = 0;

        // Mock GeoAnalyzer to fail intermittently
        const mockGeoAnalyzer = {
            analyze: jest.fn().mockImplementation(() => {
                callCount++;
                if (callCount % 2 === 0) {
                    throw new Error('Intermittent geo service failure');
                }
                return Promise.resolve({
                    country: 'US',
                    region: 'California',
                    city: 'Mountain View',
                    isVPN: false,
                    isProxy: false,
                    isHosting: false,
                    isTor: false,
                    riskScore: 0,
                    asn: 15169,
                    organization: 'Google LLC',
                });
            }),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        (middleware as any).geoAnalyzer = mockGeoAnalyzer;

        // Make multiple requests
        const responses = await Promise.all([
            request(app).get('/test').set('User-Agent', 'Mozilla/5.0'),
            request(app).get('/test').set('User-Agent', 'Mozilla/5.0'),
            request(app).get('/test').set('User-Agent', 'Mozilla/5.0'),
            request(app).get('/test').set('User-Agent', 'Mozilla/5.0'),
        ]);

        // All requests should succeed
        responses.forEach(response => {
            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.detectionResult).toBeDefined();
        });

        // Some should have real geo data, others should have fallback
        const geoResults = responses.map(r => r.body.detectionResult.metadata.geoData);
        const realGeoResults = geoResults.filter(geo => geo.country === 'US');
        const fallbackGeoResults = geoResults.filter(geo => geo.country === 'unknown');

        expect(realGeoResults.length).toBeGreaterThan(0);
        expect(fallbackGeoResults.length).toBeGreaterThan(0);
    });

    test('should preserve correlation IDs through error scenarios', async () => {
        // Mock analyzer to fail
        const mockGeoAnalyzer = {
            analyze: jest.fn().mockRejectedValue(new Error('Geo service failure')),
            isInitialized: jest.fn().mockReturnValue(true),
        };

        (middleware as any).geoAnalyzer = mockGeoAnalyzer;

        const response = await request(app)
            .get('/test')
            .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            .expect(200);

        expect(response.body.correlationId).toBeDefined();
        expect(typeof response.body.correlationId).toBe('string');
        expect(response.body.correlationId.length).toBeGreaterThan(0);
    });
});