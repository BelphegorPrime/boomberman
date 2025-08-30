import { TLSFingerprint } from './TLSFingerprint.js';

/**
 * HTTP fingerprint analysis result containing header and TLS information
 */
export interface HTTPFingerprint {
    /** Unique signature based on header combination and order */
    headerSignature: string;
    /** List of common browser headers that are missing */
    missingHeaders: string[];
    /** List of headers that appear suspicious or non-standard */
    suspiciousHeaders: string[];
    /** Score representing how typical the header order is (0-1) */
    headerOrderScore: number;
    /** TLS fingerprint if available (legacy field for backward compatibility) */
    tlsFingerprint?: string;
    /** Enhanced TLS fingerprint analysis */
    tlsFingerprintData?: TLSFingerprint;
    /** Detected automation framework signatures */
    automationSignatures: string[];
}