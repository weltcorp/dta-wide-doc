# 접근 코드 캐싱 전략 기술 명세

## 1. 캐시 구조

### 1.1 Redis 키 구조
```typescript
interface CacheKeys {
  readonly CODE_PREFIX = 'access-code:';
  readonly POLICY_PREFIX = 'access-code:policy:';
  readonly USAGE_PREFIX = 'access-code:usage:';
  readonly RATE_LIMIT_PREFIX = 'access-code:rate-limit:';
  
  getCodeKey(code: string): string {
    return `${this.CODE_PREFIX}${code}`;
  }
  
  getPolicyKey(policyId: string): string {
    return `${this.POLICY_PREFIX}${policyId}`;
  }
  
  getUsageKey(codeId: string): string {
    return `${this.USAGE_PREFIX}${codeId}`;
  }
  
  getRateLimitKey(identifier: string): string {
    return `${this.RATE_LIMIT_PREFIX}${identifier}`;
  }
}
```

### 1.2 캐시 데이터 구조
```typescript
interface CodeCache {
  id: string;
  code: string;
  type: CodeType;
  status: CodeStatus;
  userId: string;
  maxUsageCount: number;
  currentUsageCount: number;
  expiresAt: string;
  metadata?: Record<string, unknown>;
}

interface PolicyCache {
  id: string;
  name: string;
  type: CodeType;
  length: number;
  charset: string;
  expirationMinutes: number;
  maxUsageCount: number;
  isActive: boolean;
}

interface UsageCache {
  codeId: string;
  count: number;
  lastUsedAt: string;
}
```

## 2. 캐싱 전략

### 2.1 코드 캐싱
```typescript
class CodeCacheManager {
  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger
  ) {}
  
  async cacheCode(code: CodeCache): Promise<void> {
    const key = this.keys.getCodeKey(code.code);
    const ttl = this.calculateTTL(code.expiresAt);
    
    await this.redis
      .multi()
      .hmset(key, this.serialize(code))
      .expire(key, ttl)
      .exec();
      
    this.logger.debug(`Cached code ${code.id} with TTL ${ttl}s`);
  }
  
  async getCode(code: string): Promise<CodeCache | null> {
    const key = this.keys.getCodeKey(code);
    const cached = await this.redis.hgetall(key);
    
    if (!cached || Object.keys(cached).length === 0) {
      return null;
    }
    
    return this.deserialize(cached);
  }
}
```

### 2.2 정책 캐싱
```typescript
class PolicyCacheManager {
  private readonly DEFAULT_TTL = 3600; // 1시간
  
  async cachePolicy(policy: PolicyCache): Promise<void> {
    const key = this.keys.getPolicyKey(policy.id);
    
    await this.redis
      .multi()
      .hmset(key, this.serialize(policy))
      .expire(key, this.DEFAULT_TTL)
      .exec();
  }
  
  async invalidatePolicy(policyId: string): Promise<void> {
    const key = this.keys.getPolicyKey(policyId);
    await this.redis.del(key);
  }
}
```

### 2.3 사용량 캐싱
```typescript
class UsageCacheManager {
  async incrementUsage(codeId: string): Promise<number> {
    const key = this.keys.getUsageKey(codeId);
    const multi = this.redis.multi();
    
    multi
      .hincrby(key, 'count', 1)
      .hset(key, 'lastUsedAt', new Date().toISOString());
      
    const results = await multi.exec();
    return results[0][1] as number;
  }
  
  async getUsage(codeId: string): Promise<UsageCache | null> {
    const key = this.keys.getUsageKey(codeId);
    const cached = await this.redis.hgetall(key);
    
    if (!cached || Object.keys(cached).length === 0) {
      return null;
    }
    
    return {
      codeId,
      count: parseInt(cached.count, 10),
      lastUsedAt: cached.lastUsedAt
    };
  }
}
```

## 3. 캐시 동기화

### 3.1 캐시 무효화
```typescript
class CacheInvalidator {
  async invalidateCode(code: string): Promise<void> {
    const keys = [
      this.keys.getCodeKey(code),
      this.keys.getUsageKey(code)
    ];
    
    await this.redis.del(keys);
    this.logger.debug(`Invalidated cache for code ${code}`);
  }
  
  async invalidatePattern(pattern: string): Promise<void> {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(keys);
      this.logger.debug(`Invalidated ${keys.length} keys matching ${pattern}`);
    }
  }
}
```

### 3.2 캐시 재구축
```typescript
class CacheRebuilder {
  @Cron('*/15 * * * *') // 15분마다
  async rebuildExpiredCaches(): Promise<void> {
    const expiredCodes = await this.findExpiredCachedCodes();
    
    for (const code of expiredCodes) {
      await this.rebuildCodeCache(code);
    }
  }
  
  private async rebuildCodeCache(code: string): Promise<void> {
    const codeData = await this.codeRepository.findByCode(code);
    if (!codeData) {
      await this.cacheInvalidator.invalidateCode(code);
      return;
    }
    
    await this.codeCacheManager.cacheCode(this.mapToCache(codeData));
  }
}
```

## 4. 성능 최적화

### 4.1 캐시 압축
```typescript
class CacheCompressor {
  private readonly compression = require('lz4');
  
  compress(data: any): Buffer {
    const serialized = JSON.stringify(data);
    return this.compression.encode(Buffer.from(serialized));
  }
  
  decompress(compressed: Buffer): any {
    const decompressed = this.compression.decode(compressed);
    return JSON.parse(decompressed.toString());
  }
}
```

### 4.2 배치 작업
```typescript
class BatchCacheManager {
  private readonly BATCH_SIZE = 100;
  
  async batchGetCodes(codes: string[]): Promise<Map<string, CodeCache>> {
    const pipeline = this.redis.pipeline();
    
    for (const code of codes) {
      pipeline.hgetall(this.keys.getCodeKey(code));
    }
    
    const results = await pipeline.exec();
    return this.processBatchResults(codes, results);
  }
  
  private processBatchResults(
    codes: string[],
    results: [Error | null, any][]
  ): Map<string, CodeCache> {
    const cacheMap = new Map<string, CodeCache>();
    
    results.forEach((result, index) => {
      const [error, data] = result;
      if (!error && data && Object.keys(data).length > 0) {
        cacheMap.set(codes[index], this.deserialize(data));
      }
    });
    
    return cacheMap;
  }
}
```

## 5. 모니터링

### 5.1 캐시 메트릭
```typescript
class CacheMetrics {
  private readonly metrics = {
    hits: new Counter('cache_hits_total'),
    misses: new Counter('cache_misses_total'),
    errors: new Counter('cache_errors_total'),
    latency: new Histogram('cache_operation_duration_seconds')
  };
  
  recordOperation(operation: string, duration: number, success: boolean): void {
    this.metrics.latency.observe({ operation }, duration);
    if (success) {
      this.metrics.hits.inc({ operation });
    } else {
      this.metrics.misses.inc({ operation });
    }
  }
}
```

### 5.2 캐시 상태 모니터링
```typescript
class CacheHealthCheck {
  @Cron('*/5 * * * *') // 5분마다
  async checkCacheHealth(): Promise<void> {
    const metrics = await this.collectMetrics();
    
    if (metrics.hitRate < 0.8) {
      this.logger.warn('Cache hit rate below threshold', metrics);
    }
    
    if (metrics.memoryUsage > 0.9) {
      this.logger.warn('Cache memory usage high', metrics);
    }
  }
}
```

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |