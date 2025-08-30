import { Request } from 'express';
import { HTTPFingerprint } from '../types/HTTPFingerprint.js';
import { TLSFingerprintAnalyzer } from './TLSFingerprintAnalyzer.js';
import { TLSFingerprintingConfig } from '../types/TLSFingerprint.js';
import { detectionErrorHandler, DetectionErrorType } from '../ErrorHandler.js';

/**
 * Configuration interface for HTTP fingerprinting
 */
export interface FingerprintingConfig {
    /** Headers that should be present in legitimate browser requests */
    requiredHeaders: string[];
    /** Patterns that indicate suspicious or automated requests */
    suspiciousPatterns: RegExp[];
    /** Signatures of known automation frameworks */
    automationSignatures: RegExp[];
    /** TLS fingerprinting configuration */
    tls?: TLSFingerprintingConfig;
}

/**
 * Analyzes HTTP requests to generate fingerprints for bot detection
 */
export class HTTPFingerprintAnalyzer {
    private readonly requiredHeaders: string[];
    private readonly suspiciousPatterns: RegExp[];
    private readonly automationSignatures: RegExp[];
    private readonly tlsAnalyzer: TLSFingerprintAnalyzer;

    private static readonly DEFAULT_COMMON_BROWSER_HEADERS = [
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

    private static readonly DEFAULT_AUTOMATION_SIGNATURES = [
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
        /headless/i,

        /python-requests/i,
        /curl/i,
        /wget/i,
        /bot/i,
        /crawler/i,
        /spider/i,
    ];

    /**
     * Constructor for HTTPFingerprintAnalyzer
     */
    constructor(config?: FingerprintingConfig) {
        this.requiredHeaders = config?.requiredHeaders || HTTPFingerprintAnalyzer.DEFAULT_COMMON_BROWSER_HEADERS;
        this.suspiciousPatterns = config?.suspiciousPatterns || HTTPFingerprintAnalyzer.SUSPICIOUS_HEADER_PATTERNS;
        this.automationSignatures = config?.automationSignatures || HTTPFingerprintAnalyzer.DEFAULT_AUTOMATION_SIGNATURES;
        this.tlsAnalyzer = new TLSFingerprintAnalyzer(config?.tls);
    }

    /**
     * Analyzes an HTTP request to generate a fingerprint
     */
    analyze(req: Request): HTTPFingerprint {
        try {
            const headers = this.normalizeHeaders(req.headers);

            // Generate basic HTTP fingerprint first
            const httpFingerprint: HTTPFingerprint = {
                headerSignature: this.generateHeaderSignature(headers),
                missingHeaders: this.findMissingHeaders(headers),
                suspiciousHeaders: this.findSuspiciousHeaders(headers),
                headerOrderScore: this.calculateHeaderOrderScore(req.rawHeaders),
                automationSignatures: this.detectAutomationFrameworks(headers),
                tlsFingerprint: this.analyzeTLSFingerprintWithFallback(req)
            };

            // Perform enhanced TLS fingerprinting with error handling
            try {
                const tlsFingerprintData = this.tlsAnalyzer.analyze(req, httpFingerprint);
                httpFingerprint.tlsFingerprintData = tlsFingerprintData;
            } catch (error) {
                const tlsError = error instanceof Error ? error : new Error('TLS analysis failed');
                detectionErrorHandler.handleTLSAnalysisError(tlsError);
                // Continue without TLS fingerprint data
            }

            return httpFingerprint;
        } catch (error) {
            const fingerprintError = error instanceof Error ? error : new Error('HTTP fingerprinting failed');
            return detectionErrorHandler.handleFingerprintingError(req, fingerprintError);
        }
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

        return this.requiredHeaders.filter(
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
            if (this.suspiciousPatterns.some(pattern =>
                pattern.test(headerName))) {
                suspiciousHeaders.push(headerName);
                continue;
            }

            // Check header value patterns
            if (this.suspiciousPatterns.some(pattern =>
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

            for (const pattern of this.automationSignatures) {
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
     * Analyzes TLS fingerprint with error handling
     */
    private analyzeTLSFingerprintWithFallback(req: Request): string | undefined {
        try {
            return this.analyzeTLSFingerprint(req);
        } catch (error) {
            const tlsError = error instanceof Error ? error : new Error('TLS fingerprint analysis failed');
            return detectionErrorHandler.handleTLSAnalysisError(tlsError);
        }
    }

    /**
     * Analyzes TLS fingerprint if available (legacy method for backward compatibility)
     */
    private analyzeTLSFingerprint(req: Request): string | undefined {
        // Check if we have any TLS-related information
        const socket = (req as any).socket;
        if (socket && socket.encrypted) {
            // Return basic indicator for backward compatibility
            return 'tls-present';
        }

        return undefined;
    }
}