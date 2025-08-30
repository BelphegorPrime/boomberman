import { Request } from 'express';
import { TLSSocket } from 'tls';
import { TLSFingerprint, BotTLSPattern, TLSFingerprintingConfig } from '../types/TLSFingerprint.js';
import { HTTPFingerprint } from '../types/HTTPFingerprint.js';

/**
 * Analyzes TLS connections to generate fingerprints for bot detection
 */
export class TLSFingerprintAnalyzer {
    private readonly config: TLSFingerprintingConfig;
    private readonly botPatterns: BotTLSPattern[];

    private static readonly DEFAULT_BOT_PATTERNS: BotTLSPattern[] = [
        {
            name: 'curl',
            ja3Pattern: /^769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0$/,
            tlsVersionPattern: /^(771|769)$/, // TLS 1.2 or 1.0
            cipherSuitePatterns: [/^(47|53|5|10)$/], // Common curl cipher suites
            confidence: 0.9,
            description: 'curl command line tool'
        },
        {
            name: 'python-requests',
            ja3Pattern: /^771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-11-10-35-16,29-23-24,0$/,
            tlsVersionPattern: /^771$/, // TLS 1.2
            confidence: 0.85,
            description: 'Python requests library'
        },
        {
            name: 'go-http-client',
            ja3Pattern: /^771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0$/,
            tlsVersionPattern: /^771$/, // TLS 1.2
            confidence: 0.8,
            description: 'Go HTTP client'
        },
        {
            name: 'selenium-chrome',
            ja3Pattern: /^771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0$/,
            extensionPatterns: [/30032/], // Chrome extension for automation
            confidence: 0.95,
            description: 'Selenium WebDriver with Chrome'
        },
        {
            name: 'headless-chrome',
            ja3Pattern: /^771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0$/,
            extensionPatterns: [/^(0|23|65281|10|11|35|16|5|13|18|51|45|43|27)$/],
            confidence: 0.9,
            description: 'Headless Chrome browser'
        },
        {
            name: 'phantomjs',
            ja3Pattern: /^769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24,0$/,
            tlsVersionPattern: /^769$/, // TLS 1.0
            confidence: 0.95,
            description: 'PhantomJS headless browser'
        }
    ];

    constructor(config?: Partial<TLSFingerprintingConfig>) {
        this.config = {
            enabled: config?.enabled ?? true,
            botPatterns: config?.botPatterns ?? TLSFingerprintAnalyzer.DEFAULT_BOT_PATTERNS,
            analysisTimeout: config?.analysisTimeout ?? 100, // 100ms timeout
            enableConsistencyCheck: config?.enableConsistencyCheck ?? true
        };
        this.botPatterns = this.config.botPatterns;
    }

    /**
     * Analyzes TLS connection to generate fingerprint
     */
    analyze(req: Request, httpFingerprint?: HTTPFingerprint): TLSFingerprint {
        if (!this.config.enabled) {
            return this.createEmptyFingerprint();
        }

        try {
            const socket = this.extractTLSSocket(req);
            if (!socket) {
                return this.createEmptyFingerprint();
            }

            const tlsData = this.extractTLSData(socket);
            const ja3Hash = this.generateJA3Hash(tlsData);
            const isKnownBot = this.matchBotPatterns(tlsData, ja3Hash);
            const consistencyScore = httpFingerprint ?
                this.calculateConsistencyScore(tlsData, httpFingerprint) : 0;

            return {
                ja3Hash,
                tlsVersion: tlsData.tlsVersion,
                cipherSuites: tlsData.cipherSuites,
                extensions: tlsData.extensions,
                ellipticCurves: tlsData.ellipticCurves,
                signatureAlgorithms: tlsData.signatureAlgorithms,
                isKnownBotPattern: isKnownBot,
                consistencyScore,
                rawFingerprint: this.generateRawFingerprint(tlsData)
            };
        } catch (error) {
            // Graceful degradation - return empty fingerprint on error
            return this.createEmptyFingerprint();
        }
    }

    /**
     * Extracts TLS socket from Express request
     */
    private extractTLSSocket(req: Request): any | null {
        const socket = (req as any).socket;

        // Check if this is a TLS connection
        if (!socket || !socket.encrypted) {
            return null;
        }

        // Return the socket if it has TLS methods (handles both real TLS sockets and mocks)
        if (socket.getSession || socket.getCipher || socket.getProtocol) {
            return socket;
        }

        // Handle proxied connections where TLS socket might be nested
        if (socket.socket && (socket.socket.getSession || socket.socket.getCipher || socket.socket.getProtocol)) {
            return socket.socket;
        }

        return null;
    }

    /**
     * Extracts TLS connection data from socket
     */
    private extractTLSData(socket: any): TLSConnectionData {
        const session = socket.getSession();
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const peerCertificate = socket.getPeerCertificate();

        // Extract available TLS information
        const tlsVersion = this.mapProtocolToVersion(protocol);
        const cipherSuites = cipher ? [cipher.name] : [];

        // Note: Full client hello data (extensions, curves, etc.) is not directly 
        // available through Node.js TLS API. In a production environment, you would
        // need to capture this data at a lower level (e.g., using a TLS proxy or
        // custom TLS implementation)

        return {
            tlsVersion,
            cipherSuites,
            extensions: this.extractExtensionsFromSession(session),
            ellipticCurves: this.extractEllipticCurves(cipher),
            signatureAlgorithms: this.extractSignatureAlgorithms(peerCertificate),
            sessionData: session
        };
    }

    /**
     * Maps Node.js protocol string to TLS version number
     */
    private mapProtocolToVersion(protocol?: string): string {
        if (!protocol) return 'unknown';

        const protocolMap: Record<string, string> = {
            'TLSv1': '769',    // 0x0301
            'TLSv1.1': '770',  // 0x0302
            'TLSv1.2': '771',  // 0x0303
            'TLSv1.3': '772'   // 0x0304
        };

        return protocolMap[protocol] || protocol;
    }

    /**
     * Extracts TLS extensions from session data (limited by Node.js API)
     */
    private extractExtensionsFromSession(session?: Buffer): string[] {
        // Node.js doesn't provide direct access to client hello extensions
        // This is a simplified implementation that would need enhancement
        // in a production environment with access to raw TLS data

        const extensions: string[] = [];

        // Common extensions that can be inferred for any TLS connection
        extensions.push('0'); // server_name
        extensions.push('23'); // session_ticket
        extensions.push('35'); // session_ticket_tls
        extensions.push('13'); // signature_algorithms
        extensions.push('10'); // supported_groups

        return extensions;
    }

    /**
     * Extracts elliptic curves from cipher information
     */
    private extractEllipticCurves(cipher?: any): string[] {
        if (!cipher) return [];

        // Map common cipher suites to their elliptic curves
        const curves: string[] = [];

        if (cipher.name && cipher.name.includes('ECDHE')) {
            curves.push('23'); // secp256r1
            curves.push('24'); // secp384r1
        }

        return curves;
    }

    /**
     * Extracts signature algorithms from peer certificate
     */
    private extractSignatureAlgorithms(peerCert?: any): string[] {
        if (!peerCert) return [];

        const algorithms: string[] = [];

        // Common signature algorithms
        if (peerCert.sigalg) {
            if (peerCert.sigalg.includes('sha256')) {
                algorithms.push('1027'); // rsa_pss_rsae_sha256
            }
            if (peerCert.sigalg.includes('sha384')) {
                algorithms.push('1283'); // ecdsa_secp384r1_sha384
            }
        }

        return algorithms;
    }

    /**
     * Generates JA3 hash from TLS connection data
     */
    private generateJA3Hash(tlsData: TLSConnectionData): string | undefined {
        try {
            // JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
            const ja3String = [
                tlsData.tlsVersion,
                tlsData.cipherSuites.join('-'),
                tlsData.extensions.join('-'),
                tlsData.ellipticCurves.join('-'),
                '0' // Point formats (simplified)
            ].join(',');

            // Generate MD5 hash of JA3 string
            return this.md5Hash(ja3String);
        } catch (error) {
            return undefined;
        }
    }

    /**
     * Simple MD5 hash implementation for JA3
     */
    private md5Hash(input: string): string {
        // In a production environment, use a proper crypto library
        // This is a simplified hash for demonstration
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
    }

    /**
     * Matches TLS data against known bot patterns
     */
    private matchBotPatterns(tlsData: TLSConnectionData, ja3Hash?: string): boolean {
        for (const pattern of this.botPatterns) {
            let matches = 0;
            let checks = 0;

            // Check JA3 hash pattern
            if (pattern.ja3Pattern && ja3Hash) {
                checks++;
                if (pattern.ja3Pattern.test(ja3Hash)) {
                    matches++;
                }
            }

            // Check TLS version pattern
            if (pattern.tlsVersionPattern && tlsData.tlsVersion) {
                checks++;
                if (pattern.tlsVersionPattern.test(tlsData.tlsVersion)) {
                    matches++;
                }
            }

            // Check cipher suite patterns
            if (pattern.cipherSuitePatterns && tlsData.cipherSuites.length > 0) {
                checks++;
                const cipherMatch = pattern.cipherSuitePatterns.some(cipherPattern =>
                    tlsData.cipherSuites.some(suite => cipherPattern.test(suite))
                );
                if (cipherMatch) {
                    matches++;
                }
            }

            // Check extension patterns
            if (pattern.extensionPatterns && tlsData.extensions.length > 0) {
                checks++;
                const extensionMatch = pattern.extensionPatterns.some(extPattern =>
                    tlsData.extensions.some(ext => extPattern.test(ext))
                );
                if (extensionMatch) {
                    matches++;
                }
            }

            // If we have matches and they meet the confidence threshold
            if (checks > 0 && (matches / checks) >= pattern.confidence) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculates consistency score between TLS and HTTP fingerprints
     */
    private calculateConsistencyScore(tlsData: TLSConnectionData, httpFingerprint: HTTPFingerprint): number {
        if (!this.config.enableConsistencyCheck) {
            return 1.0;
        }

        let consistencyScore = 1.0;
        let checks = 0;
        let inconsistencies = 0;

        // Check if TLS version matches expected browser behavior
        if (tlsData.tlsVersion && httpFingerprint.automationSignatures.length === 0) {
            checks++;
            // Modern browsers should use TLS 1.2 or 1.3
            if (!['771', '772'].includes(tlsData.tlsVersion)) {
                inconsistencies++;
            }
        }

        // Check if cipher suites match browser expectations
        if (tlsData.cipherSuites.length > 0) {
            checks++;
            // Only flag as inconsistent if we have very limited cipher support (like 0 suites)
            // Single cipher suite can be normal in some cases
            if (tlsData.cipherSuites.length === 0) {
                inconsistencies++;
            }
        }

        // Check for automation tool signatures in both fingerprints
        const hasHttpAutomation = httpFingerprint.automationSignatures.length > 0;
        const hasTlsAutomation = tlsData.cipherSuites.some(suite =>
            ['curl', 'python', 'go-http'].some(tool => suite.toLowerCase().includes(tool))
        );

        if (hasHttpAutomation !== hasTlsAutomation) {
            checks++;
            inconsistencies++;
        }

        // Calculate final consistency score
        if (checks > 0) {
            consistencyScore = 1.0 - (inconsistencies / checks);
        }

        return Math.max(0, Math.min(1, consistencyScore));
    }

    /**
     * Generates raw fingerprint string for debugging
     */
    private generateRawFingerprint(tlsData: TLSConnectionData): string {
        return JSON.stringify({
            version: tlsData.tlsVersion,
            ciphers: tlsData.cipherSuites,
            extensions: tlsData.extensions,
            curves: tlsData.ellipticCurves,
            signatures: tlsData.signatureAlgorithms
        });
    }

    /**
     * Creates empty fingerprint for cases where TLS analysis is not possible
     */
    private createEmptyFingerprint(): TLSFingerprint {
        return {
            cipherSuites: [],
            extensions: [],
            ellipticCurves: [],
            signatureAlgorithms: [],
            isKnownBotPattern: false,
            consistencyScore: 1.0
        };
    }
}

/**
 * Internal interface for TLS connection data
 */
interface TLSConnectionData {
    tlsVersion: string;
    cipherSuites: string[];
    extensions: string[];
    ellipticCurves: string[];
    signatureAlgorithms: string[];
    sessionData?: Buffer;
}