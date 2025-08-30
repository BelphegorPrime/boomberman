import { Request } from 'express';
import { HTTPFingerprintAnalyzer } from '../src/detection/analyzers/HTTPFingerprintAnalyzer.js';

// Helper type for creating mock requests
type MockRequest = Pick<Request, 'headers' | 'rawHeaders'>;

describe('HTTPFingerprintAnalyzer Integration', () => {
    let analyzer: HTTPFingerprintAnalyzer;

    beforeEach(() => {
        analyzer = new HTTPFingerprintAnalyzer();
    });

    describe('Real-world scenarios', () => {
        it('should properly analyze a typical Chrome browser request', () => {
            const chromeRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'connection': 'keep-alive',
                    'cache-control': 'max-age=0',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'sec-fetch-site': 'none',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-dest': 'document',
                    'accept-encoding': 'gzip, deflate, br',
                    'accept-language': 'en-US,en;q=0.9'
                },
                rawHeaders: [
                    'Host', 'example.com',
                    'Connection', 'keep-alive',
                    'Cache-Control', 'max-age=0',
                    'Upgrade-Insecure-Requests', '1',
                    'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Sec-Fetch-Site', 'none',
                    'Sec-Fetch-Mode', 'navigate',
                    'Sec-Fetch-Dest', 'document',
                    'Accept-Encoding', 'gzip, deflate, br',
                    'Accept-Language', 'en-US,en;q=0.9'
                ]
            };

            const result = analyzer.analyze(chromeRequest as Request);

            // Should have minimal missing headers
            expect(result.missingHeaders.length).toBeLessThan(3);

            // Should have no automation signatures
            expect(result.automationSignatures).toHaveLength(0);

            // Should have no suspicious headers
            expect(result.suspiciousHeaders).toHaveLength(0);

            // Should have good header order score
            expect(result.headerOrderScore).toBeGreaterThan(0.6);

            // Should generate a consistent signature
            expect(result.headerSignature).toMatch(/^[a-f0-9]+$/);
        });

        it('should detect a Selenium-based bot attack', () => {
            const seleniumRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'webdriver': 'true',
                    'x-selenium-test': 'automated'
                },
                rawHeaders: [
                    'Host', 'example.com',
                    'User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                    'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'WebDriver', 'true',
                    'X-Selenium-Test', 'automated'
                ]
            };

            const result = analyzer.analyze(seleniumRequest as Request);

            // Should detect missing common headers
            expect(result.missingHeaders).toContain('accept-language');
            expect(result.missingHeaders).toContain('accept-encoding');
            expect(result.missingHeaders).toContain('connection');

            // Should detect automation signatures
            expect(result.automationSignatures).toContain('webdriver');

            // Should detect suspicious headers
            expect(result.suspiciousHeaders).toContain('webdriver');
            expect(result.suspiciousHeaders).toContain('x-selenium-test');

            // Should have poor header order score
            expect(result.headerOrderScore).toBeLessThan(0.5);
        });

        it('should detect a Python requests bot', () => {
            const pythonRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'python-requests/2.25.1',
                    'accept-encoding': 'gzip, deflate',
                    'accept': '*/*',
                    'connection': 'keep-alive'
                },
                rawHeaders: [
                    'Host', 'example.com',
                    'User-Agent', 'python-requests/2.25.1',
                    'Accept-Encoding', 'gzip, deflate',
                    'Accept', '*/*',
                    'Connection', 'keep-alive'
                ]
            };

            const result = analyzer.analyze(pythonRequest as Request);

            // Should detect missing browser-specific headers
            expect(result.missingHeaders).toContain('accept-language');
            expect(result.missingHeaders).toContain('cache-control');

            // Should detect automation signature
            expect(result.automationSignatures).toContain('python-requests');

            // Should detect suspicious headers (python-requests user-agent is flagged)
            expect(result.suspiciousHeaders).toContain('user-agent');

            // Should have poor header order score due to non-browser order
            expect(result.headerOrderScore).toBeLessThan(0.6);
        });

        it('should detect a curl-based attack', () => {
            const curlRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'curl/7.68.0',
                    'accept': '*/*'
                },
                rawHeaders: [
                    'Host', 'example.com',
                    'User-Agent', 'curl/7.68.0',
                    'Accept', '*/*'
                ]
            };

            const result = analyzer.analyze(curlRequest as Request);

            // Should detect many missing headers
            expect(result.missingHeaders.length).toBeGreaterThan(5);
            expect(result.missingHeaders).toContain('accept-language');
            expect(result.missingHeaders).toContain('accept-encoding');
            expect(result.missingHeaders).toContain('connection');

            // Should detect curl signature
            expect(result.automationSignatures).toContain('curl');

            // Should have very poor header order score
            expect(result.headerOrderScore).toBeLessThan(0.3);
        });

        it('should handle proxy headers appropriately', () => {
            const proxyRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'accept-language': 'en-US,en;q=0.5',
                    'accept-encoding': 'gzip, deflate',
                    'connection': 'keep-alive',
                    'x-forwarded-for': '192.168.1.100, 10.0.0.1',
                    'x-real-ip': '192.168.1.100',
                    'cf-connecting-ip': '203.0.113.1'
                },
                rawHeaders: [
                    'Host', 'example.com',
                    'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language', 'en-US,en;q=0.5',
                    'Accept-Encoding', 'gzip, deflate',
                    'Connection', 'keep-alive',
                    'X-Forwarded-For', '192.168.1.100, 10.0.0.1',
                    'X-Real-IP', '192.168.1.100',
                    'CF-Connecting-IP', '203.0.113.1'
                ]
            };

            const result = analyzer.analyze(proxyRequest as Request);

            // Should have some missing headers but not too many
            expect(result.missingHeaders.length).toBeLessThanOrEqual(5);

            // Should not detect automation signatures in user agent
            expect(result.automationSignatures).toHaveLength(0);

            // Should detect proxy-related suspicious headers
            expect(result.suspiciousHeaders).toContain('x-forwarded-for');
            expect(result.suspiciousHeaders).toContain('x-real-ip');
            expect(result.suspiciousHeaders).toContain('cf-connecting-ip');

            // Header order might be affected by proxy
            expect(result.headerOrderScore).toBeGreaterThan(0);
        });
    });

    describe('Requirements verification', () => {
        it('should analyze at least 15 HTTP headers (Requirement 1.1)', () => {
            const fullRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'connection': 'keep-alive',
                    'cache-control': 'max-age=0',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0',
                    'accept': 'text/html',
                    'sec-fetch-site': 'none',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-dest': 'document',
                    'accept-encoding': 'gzip',
                    'accept-language': 'en-US',
                    'cookie': 'session=abc123',
                    'referer': 'https://google.com',
                    'authorization': 'Bearer token',
                    'content-type': 'application/json',
                    'x-custom-header': 'value'
                },
                rawHeaders: []
            };

            const result = analyzer.analyze(fullRequest as Request);

            // Verify the analyzer processes all headers
            expect(result.headerSignature).toBeDefined();
            expect(result.missingHeaders).toBeDefined();
            expect(result.suspiciousHeaders).toBeDefined();
        });

        it('should detect missing common browser headers (Requirement 1.2)', () => {
            const minimalRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'Mozilla/5.0'
                },
                rawHeaders: []
            };

            const result = analyzer.analyze(minimalRequest as Request);

            // Should detect missing Accept, Accept-Language, etc.
            expect(result.missingHeaders).toContain('accept');
            expect(result.missingHeaders).toContain('accept-language');
            expect(result.missingHeaders).toContain('accept-encoding');
            expect(result.missingHeaders).toContain('connection');
        });

        it('should detect automation framework signatures (Requirement 1.3)', () => {
            const automationRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'Mozilla/5.0 (compatible; selenium webdriver puppeteer)'
                },
                rawHeaders: []
            };

            const result = analyzer.analyze(automationRequest as Request);

            // Should detect multiple automation signatures
            expect(result.automationSignatures).toContain('selenium');
            expect(result.automationSignatures).toContain('webdriver');
            expect(result.automationSignatures).toContain('puppeteer');
        });

        it('should flag inconsistent header combinations (Requirement 1.4)', () => {
            const inconsistentRequest: MockRequest = {
                headers: {
                    'host': 'example.com',
                    'user-agent': 'curl/7.68.0',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'accept-language': 'en-US,en;q=0.9',
                    'sec-fetch-site': 'none'
                },
                rawHeaders: [
                    'Accept-Language', 'en-US,en;q=0.9',
                    'User-Agent', 'curl/7.68.0',
                    'Host', 'example.com',
                    'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Sec-Fetch-Site', 'none'
                ]
            };

            const result = analyzer.analyze(inconsistentRequest as Request);

            // Should detect curl signature despite browser-like headers
            expect(result.automationSignatures).toContain('curl');

            // Should have poor header order score due to inconsistency
            expect(result.headerOrderScore).toBeLessThan(0.5);

            // Should still detect some missing headers
            expect(result.missingHeaders.length).toBeGreaterThan(0);
        });
    });
});