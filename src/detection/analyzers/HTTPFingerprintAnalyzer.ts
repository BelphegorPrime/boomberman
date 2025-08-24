import { Request } from 'express';
import { HTTPFingerprint } from '../types/HTTPFingerprint.js';

/**
 * Analyzes HTTP requests to generate fingerprints for bot detection
 */
export class HTTPFingerprintAnalyzer {
    private static readonly COMMON_BROWSER_HEADERS = [
        'accept',
        'accept-language',
        'accept-encoding',
        'connection',
        'cache-control',
        'user-agent',
        'host',
        'upgrade-insecure-requests',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site'
    ];

    private static readonly AUTOMATION_SIGNATURES = [
        // Selenium patterns
        /selenium/i,
        /webdriver/i,
        /chromedriver/i,
        /geckodriver/i,

        // Puppeteer patterns
        /puppeteer/i,
        /headlesschrome/i,
        /chrome-headless/i,

        // Playwright patterns
        /playwright/i,

        // Other automation tools
        /phantomjs/i,
        /htmlunit/i,
        /scrapy/i,
        /python-requests/i,
        /curl/i,
        /wget/i,
        /python-urllib/i,
        /go-http-client/i,
        /apache-httpclient/i,
        /okhttp/i,

        // Bot-specific patterns
        /bot/i,
        /crawler/i,
        /spider/i,
        /scraper/i
    ];

    private static readonly SUSPICIOUS_HEADER_PATTERNS = [
        // Headers that shouldn't be present in normal browser requests
        /x-forwarded/i,
        /x-real-ip/i,
        /x-cluster-client-ip/i,
        /cf-connecting-ip/i,
        /x-original-forwarded-for/i,

        // Automation-specific headers
        /selenium/i,
        /webdriver/i,
        /automation/i,
        /headless/i
    ];

    /**
     * Analyzes an HTTP request to generate a fingerprint
     */
    analyze(req: Request): HTTPFingerprint {
        const headers = this.normalizeHeaders(req.headers);

        return {
            headerSignature: this.generateHeaderSignature(headers),
            missingHeaders: this.findMissingHeaders(headers),
            suspiciousHeaders: this.findSuspiciousHeaders(headers),
            headerOrderScore: this.calculateHeaderOrderScore(req.rawHeaders),
            automationSignatures: this.detectAutomationFrameworks(headers),
            tlsFingerprint: this.analyzeTLSFingerprint(req)
        };
    }

    /**
     * Normalizes headers to lowercase for consistent analysis
     */
    private normalizeHeaders(headers: Record<string, any>): Record<string, string> {
        const normalized: Record<string, string> = {};

        for (const [key, value] of Object.entries(headers)) {
            if (typeof value === 'string') {
                normalized[key.toLowerCase()] = value;
            } else if (Array.isArray(value)) {
                normalized[key.toLowerCase()] = value.join(', ');
            } else if (value !== undefined) {
                normalized[key.toLowerCase()] = String(value);
            }
        }

        return normalized;
    }

    /**
     * Generates a unique signature based on header combination
     */
    private generateHeaderSignature(headers: Record<string, string>): string {
        const headerKeys = Object.keys(headers).sort();
        const signatureData = headerKeys.map(key => `${key}:${headers[key].length}`).join('|');

        // Simple hash function for signature generation
        let hash = 0;
        for (let i = 0; i < signatureData.length; i++) {
            const char = signatureData.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }

        return Math.abs(hash).toString(16);
    }

    /**
     * Identifies missing common browser headers
     */
    private findMissingHeaders(headers: Record<string, string>): string[] {
        const presentHeaders = new Set(Object.keys(headers));

        return HTTPFingerprintAnalyzer.COMMON_BROWSER_HEADERS.filter(
            header => !presentHeaders.has(header)
        );
    }

    /**
     * Identifies suspicious or non-standard headers
     */
    private findSuspiciousHeaders(headers: Record<string, string>): string[] {
        const suspiciousHeaders: string[] = [];

        for (const [headerName, headerValue] of Object.entries(headers)) {
            // Check header name patterns
            if (HTTPFingerprintAnalyzer.SUSPICIOUS_HEADER_PATTERNS.some(pattern =>
                pattern.test(headerName))) {
                suspiciousHeaders.push(headerName);
                continue;
            }

            // Check header value patterns
            if (HTTPFingerprintAnalyzer.SUSPICIOUS_HEADER_PATTERNS.some(pattern =>
                pattern.test(headerValue))) {
                suspiciousHeaders.push(headerName);
            }
        }

        return suspiciousHeaders;
    }

    /**
     * Calculates a score based on header order (browsers tend to send headers in consistent order)
     */
    private calculateHeaderOrderScore(rawHeaders: string[]): number {
        if (!rawHeaders || rawHeaders.length === 0) {
            return 0;
        }

        // Extract header names (every even index in rawHeaders array)
        const headerNames = rawHeaders
            .filter((_, index) => index % 2 === 0)
            .map(name => name.toLowerCase());

        // Define expected browser header order patterns
        const expectedOrder = [
            'host',
            'connection',
            'cache-control',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'accept-encoding',
            'accept-language'
        ];

        let score = 0;
        let matches = 0;

        // Calculate order similarity
        for (let i = 0; i < Math.min(headerNames.length, expectedOrder.length); i++) {
            if (headerNames[i] === expectedOrder[i]) {
                matches++;
            }
        }

        if (headerNames.length > 0) {
            score = matches / Math.max(headerNames.length, expectedOrder.length);
        }

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Detects automation framework signatures in headers
     */
    private detectAutomationFrameworks(headers: Record<string, string>): string[] {
        const signatures: string[] = [];

        for (const [headerName, headerValue] of Object.entries(headers)) {
            const combinedText = `${headerName} ${headerValue}`;

            for (const pattern of HTTPFingerprintAnalyzer.AUTOMATION_SIGNATURES) {
                if (pattern.test(combinedText)) {
                    const match = combinedText.match(pattern);
                    if (match) {
                        signatures.push(match[0].toLowerCase());
                    }
                }
            }
        }

        // Remove duplicates
        return [...new Set(signatures)];
    }

    /**
     * Analyzes TLS fingerprint if available (placeholder for future implementation)
     */
    private analyzeTLSFingerprint(req: Request): string | undefined {
        // TLS fingerprinting requires access to the underlying socket
        // This is a placeholder for future implementation when TLS data becomes available

        // Check if we have any TLS-related information
        const socket = (req as any).socket;
        if (socket && socket.encrypted) {
            // For now, return a basic indicator that TLS is present
            return 'tls-present';
        }

        return undefined;
    }
}