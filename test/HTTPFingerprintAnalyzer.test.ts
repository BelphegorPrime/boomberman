import { Request } from 'express';
import { HTTPFingerprintAnalyzer } from '../src/detection/analyzers/HTTPFingerprintAnalyzer.js';

describe('HTTPFingerprintAnalyzer', () => {
    let analyzer: HTTPFingerprintAnalyzer;

    beforeEach(() => {
        analyzer = new HTTPFingerprintAnalyzer();
    });

    describe('analyze', () => {
        it('should return a complete HTTPFingerprint object', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate',
                'connection': 'keep-alive',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result).toHaveProperty('headerSignature');
            expect(result).toHaveProperty('missingHeaders');
            expect(result).toHaveProperty('suspiciousHeaders');
            expect(result).toHaveProperty('headerOrderScore');
            expect(result).toHaveProperty('automationSignatures');
            expect(result).toHaveProperty('tlsFingerprint');
        });
    });

    describe('missing headers detection', () => {
        it('should detect missing common browser headers', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'host': 'example.com'
                // Missing Accept, Accept-Language, Accept-Encoding, Connection, etc.
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.missingHeaders).toContain('accept');
            expect(result.missingHeaders).toContain('accept-language');
            expect(result.missingHeaders).toContain('accept-encoding');
            expect(result.missingHeaders).toContain('connection');
        });

        it('should return empty array when all common headers are present', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate',
                'connection': 'keep-alive',
                'cache-control': 'max-age=0',
                'host': 'example.com',
                'upgrade-insecure-requests': '1',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.missingHeaders).toHaveLength(0);
        });
    });

    describe('automation framework detection', () => {
        it('should detect Selenium signatures', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (compatible; selenium)',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.automationSignatures).toContain('selenium');
        });

        it('should detect Puppeteer signatures', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.114 Safari/537.36',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.automationSignatures).toContain('headlesschrome');
        });

        it('should detect multiple automation signatures', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (compatible; selenium webdriver)',
                'x-automation': 'puppeteer',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.automationSignatures).toContain('selenium');
            expect(result.automationSignatures).toContain('webdriver');
            expect(result.automationSignatures).toContain('puppeteer');
        });

        it('should detect common bot patterns', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'python-requests/2.25.1',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.automationSignatures).toContain('python-requests');
        });

        it('should detect curl and wget', () => {
            const curlRequest = createMockRequest({
                'user-agent': 'curl/7.68.0',
                'host': 'example.com'
            });

            const wgetRequest = createMockRequest({
                'user-agent': 'Wget/1.20.3 (linux-gnu)',
                'host': 'example.com'
            });

            const curlResult = analyzer.analyze(curlRequest);
            const wgetResult = analyzer.analyze(wgetRequest);

            expect(curlResult.automationSignatures).toContain('curl');
            expect(wgetResult.automationSignatures).toContain('wget');
        });

        it('should return empty array for legitimate browser user agents', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.automationSignatures).toHaveLength(0);
        });
    });

    describe('suspicious headers detection', () => {
        it('should detect proxy-related headers', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'x-forwarded-for': '192.168.1.1',
                'x-real-ip': '10.0.0.1',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.suspiciousHeaders).toContain('x-forwarded-for');
            expect(result.suspiciousHeaders).toContain('x-real-ip');
        });

        it('should detect automation-specific headers', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'x-selenium-test': 'true',
                'x-webdriver': 'active',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.suspiciousHeaders).toContain('x-selenium-test');
            expect(result.suspiciousHeaders).toContain('x-webdriver');
        });

        it('should return empty array for normal headers', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.suspiciousHeaders).toHaveLength(0);
        });
    });

    describe('header order scoring', () => {
        it('should give high score for typical browser header order', () => {
            const mockRequest = createMockRequestWithRawHeaders([
                'Host', 'example.com',
                'Connection', 'keep-alive',
                'Cache-Control', 'max-age=0',
                'Upgrade-Insecure-Requests', '1',
                'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Sec-Fetch-Site', 'none',
                'Sec-Fetch-Mode', 'navigate',
                'Sec-Fetch-Dest', 'document',
                'Accept-Encoding', 'gzip, deflate',
                'Accept-Language', 'en-US,en;q=0.9'
            ]);

            const result = analyzer.analyze(mockRequest);

            expect(result.headerOrderScore).toBeGreaterThan(0.5);
        });

        it('should give low score for unusual header order', () => {
            const mockRequest = createMockRequestWithRawHeaders([
                'Accept-Language', 'en-US,en;q=0.9',
                'Accept-Encoding', 'gzip, deflate',
                'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Host', 'example.com',
                'Connection', 'keep-alive'
            ]);

            const result = analyzer.analyze(mockRequest);

            expect(result.headerOrderScore).toBeLessThan(0.5);
        });

        it('should return 0 for empty raw headers', () => {
            const mockRequest = createMockRequestWithRawHeaders([]);

            const result = analyzer.analyze(mockRequest);

            expect(result.headerOrderScore).toBe(0);
        });
    });

    describe('header signature generation', () => {
        it('should generate consistent signatures for identical headers', () => {
            const mockRequest1 = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'accept': 'text/html',
                'host': 'example.com'
            });

            const mockRequest2 = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'accept': 'text/html',
                'host': 'example.com'
            });

            const result1 = analyzer.analyze(mockRequest1);
            const result2 = analyzer.analyze(mockRequest2);

            expect(result1.headerSignature).toBe(result2.headerSignature);
        });

        it('should generate different signatures for different headers', () => {
            const mockRequest1 = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'accept': 'text/html',
                'host': 'example.com'
            });

            const mockRequest2 = createMockRequest({
                'user-agent': 'curl/7.68.0',
                'host': 'example.com'
            });

            const result1 = analyzer.analyze(mockRequest1);
            const result2 = analyzer.analyze(mockRequest2);

            expect(result1.headerSignature).not.toBe(result2.headerSignature);
        });
    });

    describe('TLS fingerprinting', () => {
        it('should return undefined for non-TLS requests', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            expect(result.tlsFingerprint).toBeUndefined();
        });

        it('should return basic TLS indicator for encrypted requests', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'host': 'example.com'
            });

            // Mock encrypted socket
            (mockRequest as any).socket = { encrypted: true };

            const result = analyzer.analyze(mockRequest);

            expect(result.tlsFingerprint).toBe('tls-present');
        });
    });

    describe('header normalization', () => {
        it('should handle array header values', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'accept': ['text/html', 'application/xml'],
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            // Should not throw and should process the array values
            expect(result.headerSignature).toBeDefined();
            expect(result.missingHeaders).toBeDefined();
        });

        it('should handle undefined header values', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'accept': undefined,
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            // Should not throw and should process normally
            expect(result.headerSignature).toBeDefined();
            expect(result.missingHeaders).toContain('accept');
        });

        it('should convert non-string values to strings', () => {
            const mockRequest = createMockRequest({
                'user-agent': 'Mozilla/5.0',
                'content-length': 123,
                'host': 'example.com'
            });

            const result = analyzer.analyze(mockRequest);

            // Should not throw and should process the numeric value
            expect(result.headerSignature).toBeDefined();
        });
    });
});

// Helper functions for creating mock requests
function createMockRequest(headers: Record<string, any>): Request {
    return {
        headers,
        rawHeaders: Object.entries(headers).flat().map(String)
    } as Request;
}

function createMockRequestWithRawHeaders(rawHeaders: string[]): Request {
    const headers: Record<string, string> = {};

    for (let i = 0; i < rawHeaders.length; i += 2) {
        if (i + 1 < rawHeaders.length) {
            headers[rawHeaders[i].toLowerCase()] = rawHeaders[i + 1];
        }
    }

    return {
        headers,
        rawHeaders
    } as Request;
}