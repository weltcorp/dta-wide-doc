# Auth API 테스트 명세

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 구현 가이드](./implementation.md)
- [API 요구사항](./requirements.md)

## 개요
Auth API의 테스트 범위, 테스트 시나리오, 테스트 환경 설정을 정의합니다.

## 테스트 범위

### 1. 단위 테스트
1. 서비스 레이어
   - 인증 서비스
   - 토큰 서비스
   - 권한 서비스
   - 앱 토큰 서비스

2. 컨트롤러 레이어
   - 입력값 검증
   - 응답 형식
   - 권한 검증
   - 에러 처리

3. 가드/인터셉터
   - JWT 인증 가드
   - 역할 기반 권한 가드
   - 앱 토큰 인증 가드
   - 로깅 인터셉터

### 2. 통합 테스트
1. API 엔드포인트
   - 로그인/로그아웃
   - 토큰 발급/갱신
   - 권한 검증
   - 앱 토큰 관리

2. 데이터베이스 연동
   - 토큰 저장/조회
   - 권한 정보 관리
   - 앱 토큰 관리
   - 세션 관리

3. 캐시 연동
   - 토큰 캐시
   - 권한 캐시
   - 블랙리스트 관리
   - 세션 캐시

### 3. 성능 테스트
1. 부하 테스트
   - 동시 인증 요청
   - 토큰 검증 성능
   - 권한 검증 성능
   - 세션 관리 성능

2. 캐시 성능
   - 캐시 히트율
   - 캐시 응답 시간
   - 캐시 메모리 사용량
   - 캐시 동기화 성능

## 테스트 시나리오

### 1. 인증 테스트

#### 로그인 테스트
```typescript
describe('Authentication', () => {
  it('should authenticate user with valid credentials', async () => {
    const credentials = {
      email: 'test@example.com',
      password: 'validPassword123!'
    };

    const response = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send(credentials)
      .expect(200);

    expect(response.body.data).toHaveProperty('accessToken');
    expect(response.body.data).toHaveProperty('refreshToken');
  });

  it('should reject invalid credentials', async () => {
    const invalidCredentials = {
      email: 'test@example.com',
      password: 'wrongPassword'
    };

    await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send(invalidCredentials)
      .expect(401);
  });

  it('should handle rate limiting', async () => {
    const credentials = {
      email: 'test@example.com',
      password: 'wrongPassword'
    };

    // 여러 번의 로그인 시도
    for (let i = 0; i < 5; i++) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send(credentials);
    }

    // 추가 시도 시 rate limit 에러
    await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send(credentials)
      .expect(429);
  });
});
```

#### 토큰 갱신 테스트
```typescript
describe('Token Refresh', () => {
  it('should refresh access token with valid refresh token', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/auth/refresh')
      .send({ refreshToken: validRefreshToken })
      .expect(200);

    expect(response.body.data).toHaveProperty('accessToken');
    expect(response.body.data.accessToken).not.toBe(oldAccessToken);
  });

  it('should reject expired refresh token', async () => {
    await request(app.getHttpServer())
      .post('/v1/auth/refresh')
      .send({ refreshToken: expiredRefreshToken })
      .expect(401);
  });
});
```

### 2. 앱 토큰 테스트

#### 앱 토큰 생성 테스트
```typescript
describe('App Token Management', () => {
  it('should create new app token', async () => {
    const dto = {
      appId: 'test-app',
      description: 'Test Application',
      permissions: ['read:users', 'write:logs']
    };

    const response = await request(app.getHttpServer())
      .post('/v1/auth/app-tokens')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(dto)
      .expect(201);

    expect(response.body.data).toHaveProperty('token');
    expect(response.body.data).toHaveProperty('appId', dto.appId);
  });

  it('should validate app token permissions', async () => {
    const invalidDto = {
      appId: 'test-app',
      description: 'Test Application',
      permissions: ['invalid:permission']
    };

    await request(app.getHttpServer())
      .post('/v1/auth/app-tokens')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(invalidDto)
      .expect(400);
  });
});
```

### 3. 권한 검증 테스트

#### 권한 가드 테스트
```typescript
describe('Authorization Guards', () => {
  it('should allow access with correct permissions', async () => {
    await request(app.getHttpServer())
      .get('/v1/auth/protected-resource')
      .set('Authorization', `Bearer ${tokenWithPermission}`)
      .expect(200);
  });

  it('should deny access without required permissions', async () => {
    await request(app.getHttpServer())
      .get('/v1/auth/protected-resource')
      .set('Authorization', `Bearer ${tokenWithoutPermission}`)
      .expect(403);
  });

  it('should handle invalid tokens', async () => {
    await request(app.getHttpServer())
      .get('/v1/auth/protected-resource')
      .set('Authorization', 'Bearer invalid-token')
      .expect(401);
  });
});
```

## 1. 사용자 유형별 권한 테스트

### TC-1: System Admin 권한 테스트
#### TC-1.1: 전체 시스템 설정 관리
```typescript
describe('System Admin 권한 테스트', () => {
  it('모든 인증 설정을 관리할 수 있어야 함', async () => {
    const admin = await createSystemAdmin();
    const result = await authClient.updateAuthSettings(admin.token, newSettings);
    expect(result.status).toBe(200);
  });

  it('모든 사용자의 2FA를 관리할 수 있어야 함', async () => {
    const admin = await createSystemAdmin();
    const user = await createRegularUser();
    const result = await authClient.enable2FA(admin.token, user.id);
    expect(result.status).toBe(200);
  });

  it('API 호출 제한이 없어야 함', async () => {
    const admin = await createSystemAdmin();
    for (let i = 0; i < 20000; i++) {
      const result = await authClient.getAuthStatus(admin.token);
      expect(result.status).toBe(200);
    }
  });
});
```

### TC-2: IAM Admin 권한 테스트
#### TC-2.1: 범위 기반 권한 관리
```typescript
describe('IAM Admin 권한 테스트', () => {
  it('할당된 범위 내 사용자의 인증 상태를 관리할 수 있어야 함', async () => {
    const admin = await createIAMAdmin({ scope: 'dept-a' });
    const user = await createRegularUser({ department: 'dept-a' });
    const result = await authClient.updateAuthStatus(admin.token, user.id);
    expect(result.status).toBe(200);
  });

  it('할당되지 않은 범위의 사용자는 관리할 수 없어야 함', async () => {
    const admin = await createIAMAdmin({ scope: 'dept-a' });
    const user = await createRegularUser({ department: 'dept-b' });
    const result = await authClient.updateAuthStatus(admin.token, user.id);
    expect(result.status).toBe(403);
  });

  it('시간당 10,000 요청 제한이 적용되어야 함', async () => {
    const admin = await createIAMAdmin();
    for (let i = 0; i < 10001; i++) {
      const result = await authClient.getAuthStatus(admin.token);
      if (i === 10000) {
        expect(result.status).toBe(429);
      } else {
        expect(result.status).toBe(200);
      }
    }
  });
});
```

### TC-3: Service Account 권한 테스트
#### TC-3.1: 제한된 API 접근
```typescript
describe('Service Account 권한 테스트', () => {
  it('토큰 검증을 수행할 수 있어야 함', async () => {
    const service = await createServiceAccount();
    const token = await generateTestToken();
    const result = await authClient.validateToken(service.token, token);
    expect(result.status).toBe(200);
  });

  it('사용자 정보를 수정할 수 없어야 함', async () => {
    const service = await createServiceAccount();
    const user = await createRegularUser();
    const result = await authClient.updateUserInfo(service.token, user.id);
    expect(result.status).toBe(403);
  });

  it('시간당 100,000 요청 제한이 적용되어야 함', async () => {
    const service = await createServiceAccount();
    for (let i = 0; i < 100001; i++) {
      const result = await authClient.validateToken(service.token);
      if (i === 100000) {
        expect(result.status).toBe(429);
      } else {
        expect(result.status).toBe(200);
      }
    }
  });
});
```

### TC-4: Regular User 권한 테스트
#### TC-4.1: 자신의 리소스 접근
```typescript
describe('Regular User 권한 테스트', () => {
  it('자신의 2FA를 관리할 수 있어야 함', async () => {
    const user = await createRegularUser();
    const result = await authClient.enable2FA(user.token);
    expect(result.status).toBe(200);
  });

  it('다른 사용자의 2FA를 관리할 수 없어야 함', async () => {
    const user1 = await createRegularUser();
    const user2 = await createRegularUser();
    const result = await authClient.enable2FA(user1.token, user2.id);
    expect(result.status).toBe(403);
  });

  it('시간당 100 요청 제한이 적용되어야 함', async () => {
    const user = await createRegularUser();
    for (let i = 0; i < 101; i++) {
      const result = await authClient.getAuthStatus(user.token);
      if (i === 100) {
        expect(result.status).toBe(429);
      } else {
        expect(result.status).toBe(200);
      }
    }
  });
});
```

## 2. 권한 검증 테스트

### TC-5: 접근 제어 테스트
```typescript
describe('접근 제어 테스트', () => {
  it('유효하지 않은 토큰으로 접근 시 401 응답을 반환해야 함', async () => {
    const result = await authClient.getAuthStatus('invalid-token');
    expect(result.status).toBe(401);
  });

  it('권한이 없는 리소스 접근 시 403 응답을 반환해야 함', async () => {
    const user = await createRegularUser();
    const result = await authClient.getSystemSettings(user.token);
    expect(result.status).toBe(403);
  });

  it('삭제 작업은 System Admin만 수행할 수 있어야 함', async () => {
    const admin = await createIAMAdmin();
    const result = await authClient.deleteAuthSettings(admin.token);
    expect(result.status).toBe(403);
  });
});
```

### TC-6: Rate Limiting 테스트
```typescript
describe('Rate Limiting 테스트', () => {
  it('System Admin은 요청 제한이 없어야 함', async () => {
    const admin = await createSystemAdmin();
    for (let i = 0; i < 20000; i++) {
      const result = await authClient.getAuthStatus(admin.token);
      expect(result.status).toBe(200);
    }
  });

  it('IAM Admin은 시간당 10,000 요청으로 제한되어야 함', async () => {
    const admin = await createIAMAdmin();
    const results = await Promise.all(
      Array(10001).fill(0).map(() => authClient.getAuthStatus(admin.token))
    );
    expect(results[10000].status).toBe(429);
  });

  it('Rate Limit 초과 시 적절한 에러 응답을 반환해야 함', async () => {
    const user = await createRegularUser();
    for (let i = 0; i < 101; i++) {
      const result = await authClient.getAuthStatus(user.token);
      if (i === 100) {
        expect(result.status).toBe(429);
        expect(result.body).toMatchObject({
          code: 'RATE_LIMIT_EXCEEDED',
          message: expect.any(String),
          retryAfter: expect.any(Number)
        });
      }
    }
  });
});
```

### TC-7: 감사 로깅 테스트
```typescript
describe('감사 로깅 테스트', () => {
  it('권한 검증 실패 시 감사 로그가 생성되어야 함', async () => {
    const user = await createRegularUser();
    await authClient.getSystemSettings(user.token);
    
    const auditLog = await getLatestAuditLog();
    expect(auditLog).toMatchObject({
      action: 'getSystemSettings',
      actor: user.id,
      status: 'DENIED',
      reason: 'INSUFFICIENT_PERMISSIONS'
    });
  });

  it('권한 변경 시 감사 로그가 생성되어야 함', async () => {
    const admin = await createSystemAdmin();
    const user = await createRegularUser();
    await authClient.updateUserPermissions(admin.token, user.id);
    
    const auditLog = await getLatestAuditLog();
    expect(auditLog).toMatchObject({
      action: 'updateUserPermissions',
      actor: admin.id,
      target: user.id,
      status: 'SUCCESS'
    });
  });
});
```

## 3. 성능 테스트

### TC-8: 응답 시간 테스트
```typescript
describe('응답 시간 테스트', () => {
  it('권한 검증은 100ms 이내에 완료되어야 함', async () => {
    const startTime = Date.now();
    await authClient.validatePermissions(token);
    const endTime = Date.now();
    expect(endTime - startTime).toBeLessThan(100);
  });

  it('Rate Limiting 검사는 50ms 이내에 완료되어야 함', async () => {
    const startTime = Date.now();
    await authClient.checkRateLimit(token);
    const endTime = Date.now();
    expect(endTime - startTime).toBeLessThan(50);
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
  database: 'auth_test',
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
  // 테스트 사용자 생성
  const users = [
    {
      email: 'test@example.com',
      password: await bcrypt.hash('validPassword123!', 10),
      role: UserRole.USER
    },
    {
      email: 'admin@example.com',
      password: await bcrypt.hash('adminPassword123!', 10),
      role: UserRole.ADMIN
    }
  ];

  await userRepository.save(users);

  // 테스트 앱 토큰 생성
  const appTokens = [
    {
      appId: 'test-app',
      token: 'valid-app-token',
      permissions: ['read:users'],
      isActive: true
    }
  ];

  await appTokenRepository.save(appTokens);
}
```

### 4. 테스트 토큰 설정
```typescript
const testTokens = {
  validAccessToken: jwt.sign(
    { userId: 1, role: UserRole.USER },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  ),
  expiredAccessToken: jwt.sign(
    { userId: 1, role: UserRole.USER },
    process.env.JWT_SECRET,
    { expiresIn: '0s' }
  ),
  validRefreshToken: jwt.sign(
    { userId: 1, tokenId: 'test-refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  )
};
```

## 테스트 실행 방법

### 1. 단위 테스트 실행
```bash
# 전체 단위 테스트 실행
npm run test auth

# 특정 모듈 테스트 실행
npm run test auth/auth.service
npm run test auth/token.service

# 테스트 커버리지 확인
npm run test:cov
```

### 2. E2E 테스트 실행
```bash
# 전체 E2E 테스트 실행
npm run test:e2e

# Auth API E2E 테스트 실행
npm run test:e2e auth
```

### 3. 성능 테스트 실행
```bash
# Artillery를 사용한 부하 테스트 실행
artillery run auth-load-test.yml

# K6를 사용한 성능 테스트 실행
k6 run auth-performance-test.js
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 1.0.0 | 2024-03-21 | Auth Team | 최초 작성 |
| 1.1.0 | 2024-03-21 | Auth Team | 사용자 유형별 권한 테스트 케이스 추가 |