/**
 * Behavioral analysis metrics for request patterns and timing
 */
export interface BehaviorMetrics {
    /** Average interval between requests in milliseconds */
    requestInterval: number;
    /** Sequence of endpoints accessed in order */
    navigationPattern: string[];
    /** Consistency score of request timing (0-1, higher = more consistent/robotic) */
    timingConsistency: number;
    /** Score indicating how human-like the behavior appears (0-1) */
    humanLikeScore: number;
    /** Total duration of the session in milliseconds */
    sessionDuration: number;
}