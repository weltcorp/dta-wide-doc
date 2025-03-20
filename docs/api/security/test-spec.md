# Security API 테스트 명세서

## 개요
Security API의 테스트 범위, 테스트 시나리오, 테스트 환경 설정을 정의합니다.

## 테스트 범위

### 1. 단위 테스트
1. 서비스 레이어
   - 보안 정책 관리 서비스
   - 보안 이벤트 서비스
   - 감사 로그 서비스
   - 캐시 처리 서비스

2. 컨트롤러 레이어
   - 입력값 검증
   - 응답 형식
   - 권한 검증
   - 에러 처리

3. 가드/인터셉터
   - JWT 인증 가드
   - 역할 기반 권한 가드
   - 감사 로그 인터셉터
   - 보안 정책 검증 인터셉터

### 2. 통합 테스트
1. API 엔드포인트
   - 보안 정책 CRUD
   - 보안 이벤트 관리
   - 감사 로그 조회
   - 인증/인가 처리

2. 데이터베이스 연동
   - 트랜잭션 처리
   - 데이터 정합성
   - 인덱스 활용
   - 동시성 제어

3. 캐시 연동
   - 캐시 적용
   - 캐시 무효화
   - 캐시 정합성
   - 분산 캐시 동기화

### 3. 성능 테스트
1. 부하 테스트
   - 동시 요청 처리
   - 응답 시간 측정
   - 리소스 사용량
   - 메모리 누수 검사

2. 캐시 성능
   - 캐시 히트율
   - 캐시 응답 시간
   - 캐시 메모리 사용량
   - 캐시 갱신 성능

## 테스트 시나리오

### 1. 보안 정책 관리 테스트

#### 보안 정책 생성 테스트
```typescript
describe('Security Policy Creation', () => {
  it('should create a new security policy', async () => {
    const dto = {
      type: SecurityPolicyType.PASSWORD,
      name: 'Password Policy',
      value: 'min_length:8',
      description: 'Minimum password length requirement',
      isActive: true
    };

    const response = await request(app.getHttpServer())
      .post('/v1/security/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(dto)
      .expect(201);

    expect(response.body.data).toMatchObject({
      type: dto.type,
      name: dto.name,
      value: dto.value
    });
  });

  it('should validate policy data', async () => {
    const invalidDto = {
      type: 'INVALID_TYPE',
      name: '',
      value: null,
      isActive: 'invalid'
    };

    await request(app.getHttpServer())
      .post('/v1/security/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(invalidDto)
      .expect(400);
  });
});
```

#### 보안 정책 조회 테스트
```typescript
describe('Security Policy Retrieval', () => {
  it('should get active security policies', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/security/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(Array.isArray(response.body.data)).toBe(true);
    expect(response.body.data[0]).toHaveProperty('isActive', true);
  });

  it('should get policy by type', async () => {
    const type = SecurityPolicyType.PASSWORD;
    const response = await request(app.getHttpServer())
      .get(`/v1/security/policies/${type}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(response.body.data).toHaveProperty('type', type);
  });
});
```

### 2. 보안 이벤트 테스트

#### 보안 이벤트 생성 테스트
```typescript
describe('Security Event Creation', () => {
  it('should create a security event', async () => {
    const dto = {
      type: SecurityEventType.LOGIN_ATTEMPT,
      severity: SecurityEventSeverity.HIGH,
      source: 'auth-service',
      description: 'Multiple failed login attempts',
      metadata: {
        ip: '192.168.1.1',
        attempts: 5,
        timeWindow: '5m'
      }
    };

    const response = await request(app.getHttpServer())
      .post('/v1/security/events')
      .set('Authorization', `Bearer ${serviceToken}`)
      .send(dto)
      .expect(201);

    expect(response.body.data).toMatchObject({
      type: dto.type,
      severity: dto.severity,
      source: dto.source
    });
  });

  it('should trigger alerts for high severity events', async () => {
    const dto = {
      type: SecurityEventType.SUSPICIOUS_ACCESS,
      severity: SecurityEventSeverity.CRITICAL,
      source: 'api-gateway',
      description: 'Potential security breach detected',
      metadata: {
        ip: '10.0.0.1',
        pattern: 'brute-force'
      }
    };

    await request(app.getHttpServer())
      .post('/v1/security/events')
      .set('Authorization', `Bearer ${serviceToken}`)
      .send(dto)
      .expect(201);

    // 알림 발송 검증
    expect(notificationService.sendAlert).toHaveBeenCalled();
  });
});
```

### 3. 감사 로그 테스트

#### 감사 로그 생성 테스트
```typescript
describe('Audit Log Creation', () => {
  it('should create audit log for sensitive operations', async () => {
    const operation = {
      type: 'UPDATE_POLICY',
      target: 'password-policy',
      changes: {
        minLength: 8,
        requireSpecialChar: true
      }
    };

    await request(app.getHttpServer())
      .patch('/v1/security/policies/password')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(operation)
      .expect(200);

    const auditLog = await auditLogRepository.findOne({
      where: {
        action: 'UPDATE_POLICY',
        resourceType: 'password-policy'
      }
    });

    expect(auditLog).toBeDefined();
    expect(auditLog.changes).toMatchObject(operation.changes);
  });
});
```

### 4. 성능 테스트

#### 부하 테스트
```typescript
describe('Performance Tests', () => {
  it('should handle concurrent policy requests', async () => {
    const concurrentRequests = 100;
    const requests = Array(concurrentRequests).fill(null).map(() =>
      request(app.getHttpServer())
        .get('/v1/security/policies/password')
        .set('Authorization', `Bearer ${userToken}`)
    );

    const responses = await Promise.all(requests);
    responses.forEach(response => {
      expect(response.status).toBe(200);
    });
  });

  it('should maintain response time under threshold', async () => {
    const start = Date.now();
    await request(app.getHttpServer())
      .get('/v1/security/policies/password')
      .set('Authorization', `Bearer ${userToken}`);
    const responseTime = Date.now() - start;

    expect(responseTime).toBeLessThan(500); // 500ms 이내
  });
});
```

## 테스트 환경 설정

### 1. 테스트 데이터베이스 설정
```typescript
const testConfig = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'test',
  password: 'test',
  database: 'security_test',
  entities: ['src/**/*.entity.ts'],
  synchronize: true,
};
```

### 2. 테스트 Redis 설정
```typescript
const redisConfig = {
  host: 'localhost',
  port: 6379,
  db: 1, // 테스트용 DB
};
```

### 3. 테스트 데이터 준비
```typescript
async function setupTestData() {
  // 기본 보안 정책 데이터 생성
  const policies = [
    {
      type: SecurityPolicyType.PASSWORD,
      name: 'Password Policy',
      value: JSON.stringify({
        minLength: 8,
        requireNumbers: true,
        requireSpecialChars: true
      }),
      description: 'Default password policy',
      isActive: true
    },
    {
      type: SecurityPolicyType.SESSION,
      name: 'Session Policy',
      value: JSON.stringify({
        timeout: 3600,
        maxConcurrent: 3
      }),
      description: 'Default session policy',
      isActive: true
    }
  ];

  await policyRepository.save(policies);
}
```

### 4. 테스트 사용자 설정
```typescript
async function setupTestUsers() {
  // 관리자 사용자
  const admin = {
    id: 1,
    email: 'admin@example.com',
    role: UserRole.ADMIN
  };

  // 서비스 계정
  const service = {
    id: 2,
    email: 'service@example.com',
    role: UserRole.SERVICE
  };

  // 일반 사용자
  const user = {
    id: 3,
    email: 'user@example.com',
    role: UserRole.USER
  };

  await userRepository.save([admin, service, user]);
}
```

## 테스트 실행 방법

### 1. 단위 테스트 실행
```bash
# 전체 단위 테스트 실행
npm run test security

# 특정 모듈 테스트 실행
npm run test security/policy.service
npm run test security/event.service

# 테스트 커버리지 확인
npm run test:cov
```

### 2. E2E 테스트 실행
```bash
# 전체 E2E 테스트 실행
npm run test:e2e

# Security API E2E 테스트 실행
npm run test:e2e security
```

### 3. 성능 테스트 실행
```bash
# Artillery를 사용한 부하 테스트 실행
artillery run security-load-test.yml

# K6를 사용한 성능 테스트 실행
k6 run security-performance-test.js
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |