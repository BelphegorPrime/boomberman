/**
 * Geographic location and infrastructure information for an IP address
 */
export interface GeoLocation {
    /** Country code (ISO 3166-1 alpha-2) */
    country: string;
    /** Region or state name */
    region: string;
    /** City name */
    city: string;
    /** Whether the IP is identified as a VPN endpoint */
    isVPN: boolean;
    /** Whether the IP is identified as a proxy server */
    isProxy: boolean;
    /** Whether the IP belongs to a hosting/cloud provider */
    isHosting: boolean;
    /** Whether the IP is identified as a Tor exit node */
    isTor: boolean;
    /** Risk score based on geographic and infrastructure factors (0-100) */
    riskScore: number;
    /** Autonomous System Number */
    asn: number;
    /** Organization name associated with the ASN */
    organization: string;
}