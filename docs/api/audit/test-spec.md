# Audit API 테스트 명세

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 구현 가이드](./implementation.md)
- [API 요구사항](./requirements.md)
- [IAM API 엔드포인트](../iam/endpoints.md)

## 개요
Audit API의 테스트 범위, 테스트 시나리오, 테스트 환경 설정을 정의합니다.

## 테스트 범위

### 1. 단위 테스트
1. 서비스 레이어
   - 감사 로그 서비스
   - 감사 정책 서비스
   - 데이터 보존 서비스
   - 분석 및 보고 서비스
   - IAM 감사 서비스

2. 컨트롤러 레이어
   - 입력값 검증
   - 응답 형식
   - 권한 검증
   - 에러 처리

3. 가드/인터셉터
   - 감사 권한 가드
   - 로깅 인터셉터
   - 정책 검증 가드
   - 데이터 보존 인터셉터
   - IAM 권한 검증 가드

### 2. 통합 테스트
1. API 엔드포인트
   - 감사 로그 생성/조회
   - 감사 정책 관리
   - 데이터 보존 관리
   - 분석 및 보고
   - IAM 감사 로그 관리

2. 데이터베이스 연동
   - 로그 저장/조회
   - 정책 관리
   - 데이터 보존 규칙
   - 분석 데이터 관리
   - IAM 감사 데이터 관리

3. 캐시 연동
   - 정책 캐시
   - 로그 캐시
   - 보고서 캐시
   - 분석 결과 캐시
   - IAM 권한 검증 결과 캐시

### 3. 성능 테스트
1. 부하 테스트
   - 동시 로그 생성
   - 대량 로그 조회
   - 정책 적용 성능
   - 보고서 생성 성능

2. 캐시 성능
   - 캐시 히트율
   - 캐시 응답 시간
   - 캐시 메모리 사용량
   - 캐시 동기화 성능

## 테스트 시나리오

### 1. 감사 로그 테스트

#### 로그 생성 테스트
```typescript
describe('Audit Log Creation', () => {
  it('should create audit log with valid data', async () => {
    const logData = {
      eventType: 'USER_LOGIN',
      source: 'AUTH_SERVICE',
      sessionId: 'session_123',
      userId: 'user_123',
      metadata: {
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0'
      }
    };

    const response = await request(app.getHttpServer())
      .post('/v1/audit/logs')
      .send(logData)
      .expect(201);

    expect(response.body.data).toHaveProperty('id');
    expect(response.body.data).toHaveProperty('timestamp');
  });

  it('should reject invalid log data', async () => {
    const invalidLogData = {
      eventType: 'INVALID_EVENT',
      source: 'UNKNOWN'
    };

    await request(app.getHttpServer())
      .post('/v1/audit/logs')
      .send(invalidLogData)
      .expect(400);
  });

  it('should enforce service account authentication', async () => {
    const logData = {
      eventType: 'USER_LOGIN',
      source: 'AUTH_SERVICE'
    };

    await request(app.getHttpServer())
      .post('/v1/audit/logs')
      .set('Authorization', 'Bearer user_token')
      .send(logData)
      .expect(403);
  });
});
```

#### 로그 조회 테스트
```typescript
describe('Audit Log Retrieval', () => {
  it('should retrieve audit logs with filters', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .query({
        eventType: 'USER_LOGIN',
        source: 'AUTH_SERVICE',
        startDate: '2024-03-01',
        endDate: '2024-03-31'
      })
      .set('Authorization', 'Bearer admin_token')
      .expect(200);

    expect(Array.isArray(response.body.data)).toBe(true);
    expect(response.body.data[0]).toHaveProperty('eventType', 'USER_LOGIN');
  });

  it('should paginate audit logs', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .query({
        page: 1,
        limit: 10
      })
      .set('Authorization', 'Bearer admin_token')
      .expect(200);

    expect(response.body.data.length).toBeLessThanOrEqual(10);
    expect(response.body.meta).toHaveProperty('totalPages');
  });

  it('should enforce admin authentication', async () => {
    await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .set('Authorization', 'Bearer user_token')
      .expect(403);
  });
});
```

### 2. 감사 정책 테스트

#### 정책 관리 테스트
```typescript
describe('Audit Policy Management', () => {
  it('should create new audit policy', async () => {
    const policyData = {
      name: 'Security Events',
      description: 'Audit policy for security events',
      eventTypes: ['USER_LOGIN', 'PASSWORD_CHANGE'],
      sources: ['AUTH_SERVICE', 'USER_SERVICE'],
      retentionPeriod: 365
    };

    const response = await request(app.getHttpServer())
      .post('/v1/audit/policies')
      .set('Authorization', 'Bearer admin_token')
      .send(policyData)
      .expect(201);

    expect(response.body.data).toHaveProperty('id');
    expect(response.body.data.name).toBe(policyData.name);
  });

  it('should update existing policy', async () => {
    const updateData = {
      name: 'Updated Security Events',
      eventTypes: ['USER_LOGIN', 'PASSWORD_CHANGE', 'ROLE_CHANGE']
    };

    await request(app.getHttpServer())
      .put('/v1/audit/policies/policy_123')
      .set('Authorization', 'Bearer admin_token')
      .send(updateData)
      .expect(200);
  });

  it('should activate/deactivate policy', async () => {
    await request(app.getHttpServer())
      .post('/v1/audit/policies/policy_123/activate')
      .set('Authorization', 'Bearer admin_token')
      .expect(200);

    await request(app.getHttpServer())
      .post('/v1/audit/policies/policy_123/deactivate')
      .set('Authorization', 'Bearer admin_token')
      .expect(200);
  });
});
```

### 3. 데이터 보존 테스트

#### 보존 정책 테스트
```typescript
describe('Data Retention', () => {
  it('should apply retention policy', async () => {
    const retentionData = {
      policyId: 'policy_123',
      retentionPeriod: 90,
      archiveEnabled: true
    };

    await request(app.getHttpServer())
      .post('/v1/audit/retention')
      .set('Authorization', 'Bearer admin_token')
      .send(retentionData)
      .expect(200);
  });

  it('should archive old logs', async () => {
    await request(app.getHttpServer())
      .post('/v1/audit/retention/archive')
      .set('Authorization', 'Bearer admin_token')
      .send({ beforeDate: '2024-01-01' })
      .expect(200);
  });

  it('should delete expired logs', async () => {
    await request(app.getHttpServer())
      .delete('/v1/audit/retention/expired')
      .set('Authorization', 'Bearer admin_token')
      .expect(200);
  });
});
```

### 4. 분석 및 보고 테스트

#### 보고서 생성 테스트
```typescript
describe('Analysis and Reporting', () => {
  it('should generate audit report', async () => {
    const reportConfig = {
      startDate: '2024-01-01',
      endDate: '2024-03-31',
      eventTypes: ['USER_LOGIN', 'PASSWORD_CHANGE'],
      groupBy: 'eventType'
    };

    const response = await request(app.getHttpServer())
      .post('/v1/audit/reports')
      .set('Authorization', 'Bearer admin_token')
      .send(reportConfig)
      .expect(200);

    expect(response.body.data).toHaveProperty('reportId');
  });

  it('should retrieve report results', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/audit/reports/report_123')
      .set('Authorization', 'Bearer admin_token')
      .expect(200);

    expect(response.body.data).toHaveProperty('statistics');
    expect(response.body.data).toHaveProperty('charts');
  });
});
```

### 5. IAM 감사 로그 테스트

#### IAM 이벤트 로깅 테스트
```typescript
describe('IAM Audit Logging', () => {
  it('should create IAM audit logs', async () => {
    const iamLogData = {
      eventType: 'IAM_ROLE_ASSIGNED',
      source: 'IAM_SERVICE',
      userId: 'user_123',
      iamResourceId: 'role_456',
      iamScope: 'ORGANIZATION',
      iamActionDetails: {
        roleId: 'ADMIN',
        assignedBy: 'admin_user',
        reason: '직무 변경으로 인한 권한 할당'
      },
      metadata: {
        sessionId: 'session_abc',
        ipAddress: '192.168.1.1'
      }
    };

    await request(app.getHttpServer())
      .post('/v1/audit/logs')
      .set('Authorization', 'Bearer service_token')
      .send(iamLogData)
      .expect(201);
  });

  it('should retrieve IAM audit logs with proper filtering', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .set('Authorization', 'Bearer admin_token')
      .query({
        eventType: 'IAM_ROLE_ASSIGNED',
        userId: 'user_123',
        iamResourceId: 'role_456',
        startDate: '2024-01-01',
        endDate: '2024-03-31'
      })
      .expect(200);

    expect(response.body.data).toHaveLength(1);
    expect(response.body.data[0]).toHaveProperty('eventType', 'IAM_ROLE_ASSIGNED');
    expect(response.body.data[0]).toHaveProperty('iamResourceId', 'role_456');
  });

  it('should enforce access control for IAM audit logs', async () => {
    // 일반 사용자 권한으로 IAM 로그 접근 시도
    await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .set('Authorization', 'Bearer user_token')
      .query({ eventType: 'IAM_ROLE_ASSIGNED' })
      .expect(403);
      
    // IAM Admin 권한으로 IAM 로그 접근
    await request(app.getHttpServer())
      .get('/v1/audit/logs')
      .set('Authorization', 'Bearer iam_admin_token')
      .query({ eventType: 'IAM_ROLE_ASSIGNED' })
      .expect(200);
  });
});
```

#### IAM 권한 검증 로깅 테스트
```typescript
describe('IAM Permission Verification Logs', () => {
  it('should log permission verification attempts', async () => {
    const verifyData = {
      eventType: 'IAM_PERMISSION_VERIFY',
      source: 'API_GATEWAY',
      userId: 'user_123',
      iamResourceId: 'api_endpoint',
      iamScope: 'SYSTEM',
      iamActionDetails: {
        permission: 'READ',
        resource: '/users',
        granted: false,
        reason: 'INSUFFICIENT_PERMISSIONS'
      },
      metadata: {
        requestId: 'req_abc',
        ipAddress: '192.168.1.1'
      }
    };

    await request(app.getHttpServer())
      .post('/v1/audit/logs')
      .set('Authorization', 'Bearer service_token')
      .send(verifyData)
      .expect(201);
  });

  it('should generate reports on permission verification patterns', async () => {
    const reportConfig = {
      startDate: '2024-01-01',
      endDate: '2024-03-31',
      eventTypes: ['IAM_PERMISSION_VERIFY'],
      groupBy: 'iamActionDetails.granted',
      filters: {
        userId: 'user_123'
      }
    };

    const response = await request(app.getHttpServer())
      .post('/v1/audit/reports')
      .set('Authorization', 'Bearer admin_token')
      .send(reportConfig)
      .expect(200);

    expect(response.body.data).toHaveProperty('reportId');
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
  database: 'audit_test',
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
  // 테스트 정책 생성
  const policies = [
    {
      name: 'Security Audit',
      eventTypes: ['USER_LOGIN', 'PASSWORD_CHANGE'],
      sources: ['AUTH_SERVICE'],
      enabled: true,
      retentionPeriod: 365
    },
    {
      name: 'Data Access Audit',
      eventTypes: ['DATA_READ', 'DATA_WRITE'],
      sources: ['DATA_SERVICE'],
      enabled: true,
      retentionPeriod: 180
    }
  ];

  await policyRepository.save(policies);

  // 테스트 로그 생성
  const logs = [
    {
      eventType: 'USER_LOGIN',
      source: 'AUTH_SERVICE',
      sessionId: 'test_session_1',
      userId: 'test_user_1',
      timestamp: new Date(),
      metadata: {
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent'
      }
    }
  ];

  await logRepository.save(logs);
}
```

### 4. 테스트 권한 설정
```typescript
const testPermissions = {
  serviceAccount: {
    token: jwt.sign(
      { type: 'SERVICE_ACCOUNT', permissions: ['AUDIT_WRITE'] },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    ),
  },
  admin: {
    token: jwt.sign(
      { type: 'ADMIN', permissions: ['AUDIT_READ', 'AUDIT_ADMIN'] },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    ),
  }
};
```

## 테스트 실행 방법

### 1. 단위 테스트 실행
```bash
# 전체 단위 테스트 실행
npm run test audit

# 특정 모듈 테스트 실행
npm run test audit/audit.service
npm run test audit/policy.service

# 테스트 커버리지 확인
npm run test:cov
```

### 2. E2E 테스트 실행
```bash
# 전체 E2E 테스트 실행
npm run test:e2e

# Audit API E2E 테스트 실행
npm run test:e2e audit
```

### 3. 성능 테스트 실행
```bash
# Artillery를 사용한 부하 테스트 실행
artillery run audit-load-test.yml

# K6를 사용한 성능 테스트 실행
k6 run audit-performance-test.js
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | IAM 감사 로그 테스트 명세 추가 |
