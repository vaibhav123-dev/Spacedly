import NodeCache from 'node-cache';

class CacheService {
  private cache: NodeCache;

  constructor() {
    // Initialize with default TTL of 300 seconds (5 minutes)
    this.cache = new NodeCache({
      stdTTL: 300,
      checkperiod: 60, // Check for expired keys every 60 seconds
      useClones: false, // Better performance
    });

    console.log('[Cache] In-memory cache initialized');
  }

  async get(key: string): Promise<string | null> {
    try {
      const value = this.cache.get<string>(key);
      if (value) {
        console.log(`[Cache] Hit: ${key}`);
        return value;
      }
      console.log(`[Cache] Miss: ${key}`);
      return null;
    } catch (error) {
      console.error('[Cache] Get error:', error);
      return null;
    }
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    try {
      if (ttl) {
        this.cache.set(key, value, ttl);
      } else {
        this.cache.set(key, value);
      }
      console.log(`[Cache] Set: ${key} (TTL: ${ttl || 'default'}s)`);
    } catch (error) {
      console.error('[Cache] Set error:', error);
    }
  }

  async del(key: string): Promise<void> {
    try {
      this.cache.del(key);
      console.log(`[Cache] Deleted: ${key}`);
    } catch (error) {
      console.error('[Cache] Delete error:', error);
    }
  }

  async delPattern(pattern: string): Promise<void> {
    try {
      const keys = this.cache.keys().filter(key => key.includes(pattern));
      if (keys.length > 0) {
        this.cache.del(keys);
        console.log(`[Cache] Deleted ${keys.length} keys matching: ${pattern}`);
      }
    } catch (error) {
      console.error('[Cache] Delete pattern error:', error);
    }
  }

  getStats() {
    return this.cache.getStats();
  }

  flush() {
    this.cache.flushAll();
    console.log('[Cache] Flushed all keys');
  }
}

export const cacheService = new CacheService();
