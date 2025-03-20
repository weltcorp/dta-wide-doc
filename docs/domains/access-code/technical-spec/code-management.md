# 접근 코드 생성 및 관리 기술 명세

## 1. 코드 생성 알고리즘

### 1.1 난수 생성
```typescript
class CodeGenerator {
  private readonly crypto = require('crypto');
  
  private generateRandomBytes(length: number): Buffer {
    return this.crypto.randomBytes(length);
  }
  
  private mapToAllowedCharset(bytes: Buffer, charset: string): string {
    const result = [];
    for (const byte of bytes) {
      result.push(charset[byte % charset.length]);
    }
    return result.join('');
  }
}
```

### 1.2 문자셋 정의
```typescript
const ALLOWED_CHARSET = {
  ALPHA: 'ABCDEFGHJKMNPQRSTUVWXYZ',  // 혼동되기 쉬운 문자 제외
  NUMERIC: '23456789',               // 혼동되기 쉬운 숫자 제외
  ALPHANUMERIC: 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
};
```

### 1.3 코드 검증
```typescript
class CodeValidator {
  private readonly CODE_PATTERN = /^[A-Z2-9]{6,12}$/;
  
  validateFormat(code: string): boolean {
    return this.CODE_PATTERN.test(code);
  }
  
  async validateCode(code: string, userId: string): Promise<ValidationResult> {
    // 구현 세부사항
  }
}
```

## 2. 데이터베이스 스키마

### 2.1 접근 코드 테이블
```sql
CREATE TABLE access_codes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code VARCHAR(12) NOT NULL,
  type VARCHAR(20) NOT NULL,
  status VARCHAR(20) NOT NULL,
  user_id UUID NOT NULL,
  issuer VARCHAR(100) NOT NULL,
  issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  usage_count INTEGER NOT NULL DEFAULT 0,
  max_usage_count INTEGER NOT NULL,
  last_used_at TIMESTAMP WITH TIME ZONE,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_code_format CHECK (code ~ '^[A-Z2-9]{6,12}$'),
  CONSTRAINT valid_type CHECK (type IN ('ONE_TIME', 'TIME_LIMITED', 'MULTI_USE')),
  CONSTRAINT valid_status CHECK (status IN ('ACTIVE', 'USED', 'EXPIRED', 'REVOKED'))
);

CREATE INDEX idx_access_codes_code ON access_codes(code);
CREATE INDEX idx_access_codes_user_id ON access_codes(user_id);
CREATE INDEX idx_access_codes_status ON access_codes(status);
CREATE INDEX idx_access_codes_expires_at ON access_codes(expires_at);
```

### 2.2 사용 이력 테이블
```sql
CREATE TABLE code_usage_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code_id UUID NOT NULL REFERENCES access_codes(id),
  user_id UUID NOT NULL,
  used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ip_address INET NOT NULL,
  user_agent VARCHAR(500),
  status VARCHAR(20) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_status CHECK (status IN ('SUCCESS', 'INVALID_CODE', 'EXPIRED', 'EXCEEDED', 'ERROR'))
);

CREATE INDEX idx_usage_history_code_id ON code_usage_history(code_id);
CREATE INDEX idx_usage_history_user_id ON code_usage_history(user_id);
CREATE INDEX idx_usage_history_used_at ON code_usage_history(used_at);
```

## 3. 캐시 전략

### 3.1 Redis 캐시 구조
```typescript
interface CodeCache {
  // 코드 정보 캐시
  `code:${code}`: {
    id: string;
    userId: string;
    status: string;
    expiresAt: string;
    usageCount: number;
    maxUsageCount: number;
  };
  
  // 사용 제한 캐시
  `rate:ip:${ip}`: number;      // IP별 시도 횟수
  `rate:user:${userId}`: number; // 사용자별 시도 횟수
  `fails:code:${code}`: number;  // 코드별 실패 횟수
}
```

### 3.2 캐시 TTL 설정
```typescript
const CACHE_TTL = {
  CODE_INFO: 30 * 60,        // 30분
  RATE_LIMIT_IP: 60,         // 1분
  RATE_LIMIT_USER: 60,       // 1분
  FAILED_ATTEMPTS: 30 * 60   // 30분
};
```

## 4. 동시성 제어

### 4.1 락 메커니즘
```typescript
class CodeLockManager {
  private readonly redisClient: Redis;
  private readonly LOCK_TTL = 5; // 5초
  
  async acquireLock(codeId: string): Promise<boolean> {
    const key = `lock:code:${codeId}`;
    return await this.redisClient.set(key, '1', 'NX', 'EX', this.LOCK_TTL);
  }
  
  async releaseLock(codeId: string): Promise<void> {
    const key = `lock:code:${codeId}`;
    await this.redisClient.del(key);
  }
}
```

### 4.2 트랜잭션 관리
```typescript
@Injectable()
class CodeUsageService {
  @Transaction()
  async useCode(code: string, userId: string): Promise<UseCodeResult> {
    const lockManager = new CodeLockManager(this.redisClient);
    
    try {
      if (!await lockManager.acquireLock(code)) {
        throw new ConcurrentUseError();
      }
      
      // 코드 사용 로직
      
    } finally {
      await lockManager.releaseLock(code);
    }
  }
}
```

## 5. 성능 최적화

### 5.1 인덱스 전략
- 코드 조회: `idx_access_codes_code`
- 사용자별 조회: `idx_access_codes_user_id`
- 만료 코드 정리: `idx_access_codes_expires_at`
- 상태별 조회: `idx_access_codes_status`

### 5.2 배치 처리
```typescript
@Injectable()
class CodeCleanupService {
  @Cron('0 */1 * * * *') // 매 1분마다
  async cleanupExpiredCodes(): Promise<void> {
    const batch_size = 1000;
    let processed = 0;
    
    while (true) {
      const expired = await this.findExpiredCodes(batch_size);
      if (expired.length === 0) break;
      
      await this.markAsExpired(expired);
      processed += expired.length;
    }
  }
}
```

## 6. 모니터링 및 로깅

### 6.1 메트릭스
```typescript
const METRICS = {
  CODE_GENERATION: 'access_code_generation_total',
  CODE_VALIDATION: 'access_code_validation_total',
  CODE_USAGE: 'access_code_usage_total',
  VALIDATION_ERRORS: 'access_code_validation_errors_total',
  CACHE_HITS: 'access_code_cache_hits_total',
  CACHE_MISSES: 'access_code_cache_misses_total'
};
```

### 6.2 로깅
> **참고**: 모든 로깅은 [공통 로깅 표준](/docs/infrastructure/logging-standards.md)을 준수해야 합니다. 여기서는 액세스 코드 관리와 관련된 주요 로깅 이벤트만 정의합니다.

```typescript
// 액세스 코드 생성
logger.info({
  event: 'ACCESS_CODE_GENERATED',
  code_id: string,
  user_id: string,
  type: string,
  expiration: string, // ISO 날짜 형식
  metadata: {
    policy_id: string,
    max_usage: number
  }
});

// 액세스 코드 검증
logger.info({
  event: 'ACCESS_CODE_VALIDATED',
  code_id: string,
  user_id: string,
  result: 'success' | 'failure',
  metadata: {
    reason: string, // 실패 사유 (실패 시)
    usage_count: number,
    remaining_usage: number
  }
});

// 액세스 코드 만료
logger.info({
  event: 'ACCESS_CODE_EXPIRED',
  code_id: string,
  user_id: string,
  reason: 'time_limit' | 'usage_limit' | 'manual',
  metadata: {
    total_usage: number,
    max_usage: number
  }
});
```

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |