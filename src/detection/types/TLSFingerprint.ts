/**
 * TLS fingerprint analysis result containing cipher suite, version, and extension information
 */
export interface TLSFingerprint {
    /** Unique TLS fingerprint hash based on client hello parameters */
    ja3Hash?: string;
    /** TLS version used in the connection */
    tlsVersion?: string;
    /** Cipher suites supported by the client */
    cipherSuites: string[];
    /** TLS extensions present in client hello */
    extensions: string[];
    /** Elliptic curves supported */
    ellipticCurves: string[];
    /** Signature algorithms supported */
    signatureAlgorithms: string[];
    /** Whether the TLS fingerprint matches known bot patterns */
    isKnownBotPattern: boolean;
    /** Consistency score between TLS and HTTP fingerprints (0-1) */
    consistencyScore: number;
    /** Raw TLS fingerprint data for debugging */
    rawFingerprint?: string;
}

/**
 * Known bot TLS patterns for detection
 */
export interface BotTLSPattern {
    /** Pattern name/identifier */
    name: string;
    /** JA3 hash pattern (can be partial) */
    ja3Pattern?: RegExp;
    /** TLS version pattern */
    tlsVersionPattern?: RegExp;
    /** Cipher suite patterns */
    cipherSuitePatterns?: RegExp[];
    /** Extension patterns */
    extensionPatterns?: RegExp[];
    /** Confidence level of this pattern (0-1) */
    confidence: number;
    /** Description of what this pattern detects */
    description: string;
}

/**
 * TLS fingerprinting configuration
 */
export interface TLSFingerprintingConfig {
    /** Whether TLS fingerprinting is enabled */
    enabled: boolean;
    /** Known bot patterns to match against */
    botPatterns: BotTLSPattern[];
    /** Timeout for TLS analysis in milliseconds */
    analysisTimeout: number;
    /** Whether to perform consistency checking with HTTP fingerprints */
    enableConsistencyCheck: boolean;
}