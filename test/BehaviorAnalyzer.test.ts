import { Request } from 'express';
import { BehaviorAnalyzer } from '../src/detection/analyzers/BehaviorAnalyzer.js';
import { BehaviorMetrics, SessionData } from '../src/detection/types/index.js';

// Mock Express Request
const createMockRequest = (overrides: Partial<Request> = {}): Request => {
    return {
        path: '/test',
        method: 'GET',
        headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        get: (header: string) => {
            const headers = (overrides.headers || {}) as Record<string, string>;
            return headers[header.toLowerCase()] ||
                (overrides as any).headers?.[header.toLowerCase()] ||
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
        },
        ...overrides
    } as Request;
};

// Helper class to control time for testing
class TimeController {
    private originalDateNow: () => number;
    private mockTime: number;
    private timeSequence: number[] = [];
    private sequenceIndex: number = 0;

    constructor() {
        this.originalDateNow = Date.now;
        this.mockTime = 1000000; // Fixed base time
    }

    setTime(time: number): void {
        this.mockTime = time;
        Date.now = () => this.mockTime;
    }

    setTimeSequence(times: number[]): void {
        this.timeSequence = times;
        this.sequenceIndex = 0;
        Date.now = () => {
            if (this.sequenceIndex < this.timeSequence.length) {
                return this.timeSequence[this.sequenceIndex++];
            }
            return this.timeSequence[this.timeSequence.length - 1] || this.mockTime;
        };
    }

    advanceTime(ms: number): void {
        this.mockTime += ms;
        Date.now = () => this.mockTime;
    }

    restore(): void {
        Date.now = this.originalDateNow;
    }
}

describe('BehaviorAnalyzer', () => {
    let analyzer: BehaviorAnalyzer;
    let timeController: TimeController;
    const testIp = '192.168.88.100';

    beforeEach(() => {
        analyzer = new BehaviorAnalyzer();
        timeController = new TimeController();
    });

    afterEach(() => {
        analyzer.clearSessions();
        timeController.restore();
    });

    describe('Session Tracking', () => {
        it('should create new session for first request', () => {
            const req = createMockRequest();

            analyzer.analyze(testIp, req);

            const session = analyzer.getSession(testIp);
            expect(session).toBeDefined();
            expect(session!.ip).toBe(testIp);
            expect(session!.requestCount).toBe(1);
            expect(session!.requests).toHaveLength(1);
        });

        it('should update existing session for subsequent requests', () => {
            const req1 = createMockRequest({ path: '/page1' });
            const req2 = createMockRequest({ path: '/page2' });

            analyzer.analyze(testIp, req1);
            analyzer.analyze(testIp, req2);

            const session = analyzer.getSession(testIp);
            expect(session!.requestCount).toBe(2);
            expect(session!.requests).toHaveLength(2);
            expect(session!.requests[0].path).toBe('/page1');
            expect(session!.requests[1].path).toBe('/page2');
        });

        it('should track request timing correctly', () => {
            const req = createMockRequest();
            const startTime = Date.now();

            analyzer.analyze(testIp, req);

            const session = analyzer.getSession(testIp);
            expect(session!.firstSeen).toBeGreaterThanOrEqual(startTime);
            expect(session!.lastSeen).toBeGreaterThanOrEqual(startTime);
        });

        it('should limit request history to 100 entries', () => {
            // Create 150 requests
            for (let i = 0; i < 150; i++) {
                const req = createMockRequest({ path: `/page${i}` });
                analyzer.analyze(testIp, req);
            }

            const session = analyzer.getSession(testIp);
            expect(session!.requests).toHaveLength(100);
            expect(session!.requestCount).toBe(150);
            // Should keep the most recent requests
            expect(session!.requests[99].path).toBe('/page149');
        });
    });

    describe('Request Interval Analysis', () => {
        it('should calculate average interval correctly', () => {
            const baseTime = 1000000;
            timeController.setTimeSequence([baseTime, baseTime + 1000, baseTime + 3000]);

            const req = createMockRequest();

            analyzer.analyze(testIp, req);
            analyzer.analyze(testIp, req);
            const result = analyzer.analyze(testIp, req);

            // Average of 1000ms and 2000ms = 1500ms
            expect(result.requestInterval).toBe(1500);
        });

        it('should return 0 for single request', () => {
            const req = createMockRequest();

            const result = analyzer.analyze(testIp, req);

            expect(result.requestInterval).toBe(0);
        });
    });

    describe('Sub-human Speed Detection', () => {
        it('should detect sub-human request speeds', () => {
            const baseTime = 1000000;
            timeController.setTimeSequence([baseTime, baseTime + 100, baseTime + 200]);

            const req = createMockRequest();

            analyzer.analyze(testIp, req);
            analyzer.analyze(testIp, req);
            const result = analyzer.analyze(testIp, req);

            expect(result.requestInterval).toBe(100);
            expect(result.humanLikeScore).toBeLessThan(0.8); // Should be penalized
        });

        it('should not penalize normal human speeds', () => {
            const baseTime = 1000000;
            timeController.setTimeSequence([baseTime, baseTime + 2000, baseTime + 5000]);

            const req = createMockRequest();

            analyzer.analyze(testIp, req);
            analyzer.analyze(testIp, req);
            const result = analyzer.analyze(testIp, req);

            expect(result.requestInterval).toBe(2500);
            expect(result.humanLikeScore).toBeGreaterThan(0.6);
        });
    });

    describe('Timing Consistency Analysis', () => {
        it('should detect robotic timing patterns', () => {
            const baseTime = 1000000;
            const interval = 1000; // Exactly 1 second between each request

            timeController.setTimeSequence([
                baseTime,
                baseTime + interval,
                baseTime + interval * 2,
                baseTime + interval * 3,
                baseTime + interval * 4,
                baseTime + interval * 5
            ]);

            const req = createMockRequest();

            for (let i = 0; i < 6; i++) {
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, req);

            expect(result.timingConsistency).toBeGreaterThan(0.6); // Consistent = robotic
            expect(result.humanLikeScore).toBeLessThan(0.8); // Should be penalized
        });

        it('should recognize human-like timing variation', () => {
            const baseTime = 1000000;
            const intervals = [800, 1200, 2000, 500, 3000]; // Variable intervals

            let currentTime = baseTime;
            const mockTimes = [currentTime];

            for (const interval of intervals) {
                currentTime += interval;
                mockTimes.push(currentTime);
            }

            timeController.setTimeSequence(mockTimes);

            const req = createMockRequest();

            for (let i = 0; i < 6; i++) {
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, req);

            expect(result.timingConsistency).toBeLessThan(0.6); // Variable timing
            expect(result.humanLikeScore).toBeGreaterThan(0.7);
        });
    });

    describe('Navigation Pattern Detection', () => {
        it('should extract navigation patterns correctly', () => {
            const paths = ['/home', '/products', '/product/123', '/cart', '/checkout'];

            for (const path of paths) {
                const req = createMockRequest({ path, method: 'GET' });
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.navigationPattern).toContain('GET:/home');
            expect(result.navigationPattern).toContain('GET:/products');
            expect(result.navigationPattern).toContain('GET:/checkout');
        });

        it('should detect automated flow patterns', () => {
            // Simulate systematic scanning behavior
            for (let i = 1; i <= 10; i++) {
                const req = createMockRequest({ path: `/admin/page${i}` });
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.humanLikeScore).toBeLessThan(0.7); // Should detect scanning pattern
        });

        it('should detect rapid identical requests', () => {
            const baseTime = 1000000;
            timeController.setTime(baseTime);

            // Make 6 identical requests rapidly
            for (let i = 0; i < 6; i++) {
                const req = createMockRequest({ path: '/api/data' });
                analyzer.analyze(testIp, req);
                timeController.advanceTime(100); // 100ms intervals
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.humanLikeScore).toBeLessThan(0.6); // Should be heavily penalized
        });
    });

    describe('Request Diversity Analysis', () => {
        it('should calculate diversity correctly for varied requests', () => {
            const requests = [
                { path: '/home', method: 'GET' },
                { path: '/api/data', method: 'POST' },
                { path: '/profile', method: 'GET' },
                { path: '/settings', method: 'PUT' }
            ];

            for (const reqData of requests) {
                const req = createMockRequest(reqData);
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.humanLikeScore).toBeGreaterThan(0.5); // High diversity = human-like
        });

        it('should penalize low diversity requests', () => {
            // Make many requests to the same endpoint
            for (let i = 0; i < 20; i++) {
                const req = createMockRequest({ path: '/api/endpoint' });
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.humanLikeScore).toBeLessThan(0.7); // Low diversity = suspicious
        });
    });

    describe('Session Duration Tracking', () => {
        it('should calculate session duration correctly', () => {
            const baseTime = 1000000;
            timeController.setTimeSequence([baseTime, baseTime + 5000]);

            const req = createMockRequest();

            analyzer.analyze(testIp, req);
            const result = analyzer.analyze(testIp, req);

            expect(result.sessionDuration).toBe(5000);
        });
    });

    describe('Memory Management', () => {
        it('should track active session count', () => {
            analyzer.analyze('192.168.1.1', createMockRequest());
            analyzer.analyze('192.168.1.2', createMockRequest());
            analyzer.analyze('192.168.1.3', createMockRequest());

            expect(analyzer.getActiveSessionCount()).toBe(3);
        });

        it('should clear all sessions', () => {
            analyzer.analyze('192.168.1.1', createMockRequest());
            analyzer.analyze('192.168.1.2', createMockRequest());

            expect(analyzer.getActiveSessionCount()).toBe(2);

            analyzer.clearSessions();

            expect(analyzer.getActiveSessionCount()).toBe(0);
        });
    });

    describe('Edge Cases', () => {
        it('should handle requests with missing user-agent', () => {
            const req = createMockRequest({
                headers: {},
                get: () => undefined
            });

            const result = analyzer.analyze(testIp, req);

            expect(result).toBeDefined();
            expect(result.humanLikeScore).toBeGreaterThan(0);
        });

        it('should handle empty navigation patterns', () => {
            const req = createMockRequest();

            const result = analyzer.analyze(testIp, req);

            expect(result.navigationPattern).toHaveLength(1);
            expect(result.timingConsistency).toBe(0);
        });

        it('should handle single request analysis', () => {
            const req = createMockRequest();

            const result = analyzer.analyze(testIp, req);

            expect(result.requestInterval).toBe(0);
            expect(result.sessionDuration).toBe(0);
            expect(result.humanLikeScore).toBe(1.0); // Neutral for single request
        });
    });

    describe('Integration with Requirements', () => {
        // Requirement 2.1: WHEN requests arrive faster than humanly possible THEN the system SHALL flag sub-human timing patterns
        it('should flag sub-human timing patterns (Requirement 2.1)', () => {
            const baseTime = 1000000;
            timeController.setTimeSequence([baseTime, baseTime + 50, baseTime + 100]);

            const req = createMockRequest();

            analyzer.analyze(testIp, req);
            analyzer.analyze(testIp, req);
            const result = analyzer.analyze(testIp, req);

            expect(result.requestInterval).toBe(50);
            expect(result.humanLikeScore).toBeLessThan(0.6); // Should be flagged
        });

        // Requirement 2.2: WHEN sequential endpoint access follows automated patterns THEN the system SHALL detect and log unusual navigation flows
        it('should detect automated navigation patterns (Requirement 2.2)', () => {
            // Simulate systematic endpoint scanning
            const systematicPaths = [
                '/admin', '/admin/users', '/admin/config', '/admin/logs',
                '/api/v1', '/api/v2', '/api/internal', '/api/debug'
            ];

            for (const path of systematicPaths) {
                const req = createMockRequest({ path });
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.navigationPattern.length).toBeGreaterThan(0);
            expect(result.humanLikeScore).toBeLessThan(0.7); // Should detect automated pattern
        });

        // Requirement 2.3: WHEN rapid-fire requests are detected from the same source THEN the system SHALL increase threat scoring
        it('should increase threat scoring for rapid-fire requests (Requirement 2.3)', () => {
            const baseTime = 1000000;
            let currentTime = baseTime;
            const times: number[] = [];

            // Mock rapid-fire requests (every 10ms)
            for (let i = 0; i < 10; i++) {
                times.push(currentTime);
                currentTime += 10; // 10ms intervals
            }

            timeController.setTimeSequence(times);

            for (let i = 0; i < 10; i++) {
                const req = createMockRequest({ path: '/api/data' });
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.requestInterval).toBeLessThan(100);
            expect(result.humanLikeScore).toBeLessThan(0.5); // High threat score
        });

        // Requirement 2.4: WHEN request intervals are too consistent THEN the system SHALL identify machine-like timing patterns
        it('should identify machine-like timing patterns (Requirement 2.4)', () => {
            const baseTime = 1000000;
            const perfectInterval = 1000; // Exactly 1 second
            const times: number[] = [];

            // Create perfectly consistent timing
            for (let i = 0; i < 8; i++) {
                times.push(baseTime + (i * perfectInterval));
            }

            timeController.setTimeSequence(times);

            for (let i = 0; i < 8; i++) {
                const req = createMockRequest();
                analyzer.analyze(testIp, req);
            }

            const result = analyzer.analyze(testIp, createMockRequest());

            expect(result.timingConsistency).toBeGreaterThan(0.6); // Very consistent
            expect(result.humanLikeScore).toBeLessThan(0.7); // Should identify as machine-like
        });
    });
});