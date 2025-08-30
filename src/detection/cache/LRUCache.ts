/**
 * Generic LRU (Least Recently Used) Cache implementation
 * Provides O(1) get/set operations with automatic eviction of least recently used items
 */
export class LRUCache<K, V> {
    private readonly maxSize: number;
    private readonly cache = new Map<K, CacheNode<K, V>>();
    private head: CacheNode<K, V> | null = null;
    private tail: CacheNode<K, V> | null = null;
    private size = 0;

    constructor(maxSize: number) {
        if (maxSize <= 0) {
            throw new Error('Cache size must be greater than 0');
        }
        this.maxSize = maxSize;
    }

    /**
     * Get a value from the cache
     * Moves the accessed item to the front (most recently used)
     */
    get(key: K): V | undefined {
        const node = this.cache.get(key);
        if (!node) {
            return undefined;
        }

        // Move to front (most recently used)
        this.moveToFront(node);
        return node.value;
    }

    /**
     * Set a value in the cache
     * Adds new item to front, evicts least recently used if at capacity
     */
    set(key: K, value: V): void {
        const existingNode = this.cache.get(key);

        if (existingNode) {
            // Update existing node
            existingNode.value = value;
            this.moveToFront(existingNode);
            return;
        }

        // Create new node
        const newNode: CacheNode<K, V> = {
            key,
            value,
            prev: null,
            next: null
        };

        // Add to cache and front of list
        this.cache.set(key, newNode);
        this.addToFront(newNode);
        this.size++;

        // Evict if over capacity
        if (this.size > this.maxSize) {
            this.evictLeastRecentlyUsed();
        }
    }

    /**
     * Check if a key exists in the cache
     */
    has(key: K): boolean {
        return this.cache.has(key);
    }

    /**
     * Delete a key from the cache
     */
    delete(key: K): boolean {
        const node = this.cache.get(key);
        if (!node) {
            return false;
        }

        this.cache.delete(key);
        this.removeNode(node);
        this.size--;
        return true;
    }

    /**
     * Clear all items from the cache
     */
    clear(): void {
        this.cache.clear();
        this.head = null;
        this.tail = null;
        this.size = 0;
    }

    /**
     * Get current cache size
     */
    getSize(): number {
        return this.size;
    }

    /**
     * Get maximum cache size
     */
    getMaxSize(): number {
        return this.maxSize;
    }

    /**
     * Get cache hit ratio (for monitoring)
     */
    getStats(): CacheStats {
        return {
            size: this.size,
            maxSize: this.maxSize,
            utilizationRatio: this.size / this.maxSize
        };
    }

    /**
     * Get all keys in order from most to least recently used
     */
    keys(): K[] {
        const keys: K[] = [];
        let current = this.head;
        while (current) {
            keys.push(current.key);
            current = current.next;
        }
        return keys;
    }

    /**
     * Get all values in order from most to least recently used
     */
    values(): V[] {
        const values: V[] = [];
        let current = this.head;
        while (current) {
            values.push(current.value);
            current = current.next;
        }
        return values;
    }

    /**
     * Move a node to the front of the list (most recently used)
     */
    private moveToFront(node: CacheNode<K, V>): void {
        if (node === this.head) {
            return; // Already at front
        }

        // Remove from current position
        this.removeNode(node);

        // Add to front
        this.addToFront(node);
    }

    /**
     * Add a node to the front of the list
     */
    private addToFront(node: CacheNode<K, V>): void {
        node.prev = null;
        node.next = this.head;

        if (this.head) {
            this.head.prev = node;
        }

        this.head = node;

        if (!this.tail) {
            this.tail = node;
        }
    }

    /**
     * Remove a node from the list
     */
    private removeNode(node: CacheNode<K, V>): void {
        if (node.prev) {
            node.prev.next = node.next;
        } else {
            this.head = node.next;
        }

        if (node.next) {
            node.next.prev = node.prev;
        } else {
            this.tail = node.prev;
        }
    }

    /**
     * Evict the least recently used item
     */
    private evictLeastRecentlyUsed(): void {
        if (!this.tail) {
            return;
        }

        const lruNode = this.tail;
        this.cache.delete(lruNode.key);
        this.removeNode(lruNode);
        this.size--;
    }
}

/**
 * Cache node for doubly-linked list
 */
interface CacheNode<K, V> {
    key: K;
    value: V;
    prev: CacheNode<K, V> | null;
    next: CacheNode<K, V> | null;
}

/**
 * Cache statistics interface
 */
export interface CacheStats {
    size: number;
    maxSize: number;
    utilizationRatio: number;
}