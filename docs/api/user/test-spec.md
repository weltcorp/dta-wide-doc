# User Domain 테스트 명세서

## 개요
User Domain의 테스트 범위, 전략, 시나리오를 정의합니다. 이 문서는 사용자 관리 및 IAM(Identity and Access Management) 관련 테스트를 포함합니다.

## 테스트 범위

### 단위 테스트
- UserService
- OrganizationService
- RoleService
- PermissionService
- IAMService
- PolicyEnforcer
- 각종 DTO 유효성 검증
- 에러 처리 로직

### 통합 테스트
- API 엔드포인트
- 데이터베이스 연동
- 캐시 연동
- 외부 서비스 연동 (Auth 서비스 포함)
- IAM 정책 평가 엔진
- 권한 캐싱 및 무효화

### E2E 테스트
- 사용자 등록부터 로그인까지의 전체 흐름 (Auth 서비스와 연동)
- 권한 관리 흐름 (역할 생성, 권한 할당, 접근 제어 검증)
- 정책 기반 접근 제어 흐름
- 조직 관리 흐름

## 테스트 시나리오

### 1. UserService 테스트

#### 1.1 사용자 등록
```typescript
describe('UserService.create', () => {
  it('should create a new user with valid input and verified email', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'password123!',
      name: 'Test User',
      deviceId: 'device_123',
      verificationId: 'ver_456',
      privacyConsent: {
        termsAndConditions: true,
        privacyPolicy: true,
        marketingConsent: false
      }
    };
    
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(true);
    
    const result = await userService.create(dto);
    expect(result).toHaveProperty('id');
    expect(result.email).toBe(dto.email);
  });

  it('should throw EMAIL_NOT_VERIFIED when email is not verified', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'password123!',
      name: 'Test User',
      deviceId: 'device_123',
      verificationId: 'invalid_ver_id',
      privacyConsent: {
        termsAndConditions: true,
        privacyPolicy: true,
        marketingConsent: false
      }
    };
    
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(false);
    
    await expect(userService.create(dto)).rejects.toThrow('EMAIL_NOT_VERIFIED');
  });

  it('should throw EMAIL_EXISTS error for duplicate email', async () => {
    const dto = {
      email: 'existing@example.com',
      password: 'password123!',
      name: 'Test User',
      deviceId: 'device_123',
      verificationId: 'ver_456',
      privacyConsent: {
        termsAndConditions: true,
        privacyPolicy: true,
        marketingConsent: false
      }
    };
    
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(true);
    
    // 이메일 중복 시나리오 설정
    jest.spyOn(userRepository, 'findOne').mockResolvedValue({ id: 'existing_user' } as User);
    
    await expect(userService.create(dto)).rejects.toThrow('EMAIL_EXISTS');
  });

  it('should hash password before saving', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'password123!',
      name: 'Test User',
      deviceId: 'device_123',
      verificationId: 'ver_456',
      privacyConsent: {
        termsAndConditions: true,
        privacyPolicy: true,
        marketingConsent: false
      }
    };
    
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(true);
    
    const result = await userService.create(dto);
    const savedUser = await userRepository.findOne(result.id);
    expect(savedUser.password).not.toBe(dto.password);
    expect(await bcrypt.compare(dto.password, savedUser.password)).toBe(true);
  });
});
```

#### 1.2 사용자 정보 조회
```typescript
describe('UserService.findById', () => {
  it('should return user by id', async () => {
    const user = await userService.findById('user123');
    expect(user).toBeDefined();
    expect(user.id).toBe('user123');
  });

  it('should throw USER_NOT_FOUND for non-existing user', async () => {
    await expect(userService.findById('nonexistent')).rejects.toThrow('USER_NOT_FOUND');
  });

  it('should include roles when withRoles is true', async () => {
    const user = await userService.findById('user123', { withRoles: true });
    expect(user.roles).toBeDefined();
    expect(Array.isArray(user.roles)).toBe(true);
  });
});
```

### 2. IAMService 테스트

#### 2.1 역할 관리
```typescript
describe('IAMService.createRole', () => {
  it('should create a new role with valid input', async () => {
    const dto = {
      name: 'editor',
      description: '콘텐츠 편집 가능한 역할',
      permissionIds: ['perm1', 'perm2']
    };
    
    const result = await iamService.createRole(dto, 'admin1');
    expect(result).toHaveProperty('id');
    expect(result.name).toBe(dto.name);
    expect(result.permissions).toHaveLength(2);
    expect(result.permissions[0].id).toBe('perm1');
  });

  it('should throw ROLE_NAME_EXISTS for duplicate role name', async () => {
    const dto = {
      name: 'existing-role',
      description: '이미 존재하는 역할'
    };
    
    // 역할 이름 중복 시나리오 설정
    jest.spyOn(prismaService.role, 'findUnique').mockResolvedValue({ id: 'existing_role' } as any);
    
    await expect(iamService.createRole(dto)).rejects.toThrow('ROLE_NAME_EXISTS');
  });
});

describe('IAMService.assignRolesToUser', () => {
  it('should assign roles to a user', async () => {
    const userId = 'user123';
    const dto = {
      roleIds: ['role1', 'role2']
    };
    
    const updateSpy = jest.spyOn(prismaService.user, 'update').mockResolvedValue({} as any);
    await iamService.assignRolesToUser(userId, dto);
    
    expect(updateSpy).toHaveBeenCalledWith({
      where: { id: userId },
      data: {
        roles: {
          set: dto.roleIds.map(id => ({ id }))
        }
      }
    });
  });

  it('should throw USER_NOT_FOUND for non-existing user', async () => {
    jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(null);
    
    await expect(iamService.assignRolesToUser('nonexistent', { roleIds: ['role1'] }))
      .rejects.toThrow('USER_NOT_FOUND');
  });
});
```

#### 2.2 권한 관리
```typescript
describe('IAMService.createPermission', () => {
  it('should create a new permission with valid input', async () => {
    const dto = {
      name: 'content:edit',
      resource: 'content',
      action: 'edit',
      description: '콘텐츠 편집 권한'
    };
    
    const result = await iamService.createPermission(dto);
    expect(result).toHaveProperty('id');
    expect(result.name).toBe(dto.name);
    expect(result.resource).toBe(dto.resource);
    expect(result.action).toBe(dto.action);
  });

  it('should throw PERMISSION_NAME_EXISTS for duplicate permission name', async () => {
    const dto = {
      name: 'existing-permission',
      resource: 'content',
      action: 'edit'
    };
    
    // 권한 이름 중복 시나리오 설정
    jest.spyOn(prismaService.permission, 'findUnique').mockResolvedValue({ id: 'existing_perm' } as any);
    
    await expect(iamService.createPermission(dto)).rejects.toThrow('PERMISSION_NAME_EXISTS');
  });
});
```

#### 2.3 정책 평가
```typescript
describe('IAMService.checkPermission', () => {
  it('should return true when user has direct policy permission', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'read';
    
    jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue({
      id: userId,
      isActive: true,
      roles: [],
      policies: [
        { resource, action, isAllow: true }
      ]
    } as any);
    
    const result = await iamService.checkPermission(userId, resource, action);
    expect(result).toBe(true);
  });
  
  it('should return true when user has role-based permission', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'read';
    
    jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue({
      id: userId,
      isActive: true,
      roles: [
        {
          permissions: [
            { resource, action, scope: '*' }
          ]
        }
      ],
      policies: []
    } as any);
    
    const result = await iamService.checkPermission(userId, resource, action);
    expect(result).toBe(true);
  });
  
  it('should return false when user has no permission', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'delete';
    
    jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue({
      id: userId,
      isActive: true,
      roles: [
        {
          permissions: [
            { resource, action: 'read', scope: '*' }
          ]
        }
      ],
      policies: []
    } as any);
    
    const result = await iamService.checkPermission(userId, resource, action);
    expect(result).toBe(false);
  });
  
  it('should use cache for repeated permission checks', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'read';
    
    jest.spyOn(cacheService, 'get').mockResolvedValue(true);
    const findSpy = jest.spyOn(prismaService.user, 'findUnique');
    
    const result = await iamService.checkPermission(userId, resource, action);
    
    expect(result).toBe(true);
    expect(findSpy).not.toHaveBeenCalled();
  });
});
```

### 3. API 엔드포인트 테스트

#### 3.1 사용자 등록 API
```typescript
describe('POST /v1/users/signup', () => {
  it('should return 201 for valid registration with verified email', async () => {
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(true);
    
    const response = await request(app.getHttpServer())
      .post('/v1/users/signup')
      .send({
        email: 'test@example.com',
        password: 'password123!',
        name: 'Test User',
        deviceId: 'device_123',
        verificationId: 'ver_456',
        privacyConsent: {
          termsAndConditions: true,
          privacyPolicy: true,
          marketingConsent: false
        }
      });

    expect(response.status).toBe(201);
    expect(response.body.data).toHaveProperty('userId');
  });

  it('should return 403 when email is not verified', async () => {
    // Auth 서비스의 이메일 인증 확인 메서드를 모킹
    jest.spyOn(authService, 'checkEmailVerification').mockResolvedValue(false);
    
    const response = await request(app.getHttpServer())
      .post('/v1/users/signup')
      .send({
        email: 'test@example.com',
        password: 'password123!',
        name: 'Test User',
        deviceId: 'device_123',
        verificationId: 'invalid_ver_id',
        privacyConsent: {
          termsAndConditions: true,
          privacyPolicy: true,
          marketingConsent: false
        }
      });

    expect(response.status).toBe(403);
    expect(response.body.code).toBe('USER008');
  });

  it('should return 400 for invalid input', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/users/signup')
      .send({
        email: 'invalid-email',
        password: 'short',
        name: '',
        deviceId: '',
        verificationId: '',
        privacyConsent: {
          termsAndConditions: false,
          privacyPolicy: false
        }
      });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('USER001');
  });
});

#### 3.2 IAM API 테스트
```typescript
describe('POST /v1/iam/roles', () => {
  it('should return 201 for valid role creation', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/iam/roles')
      .set('Authorization', 'Bearer admin_token')
      .send({
        name: 'editor',
        description: '콘텐츠 편집 가능한 역할',
        permissionIds: ['perm1', 'perm2']
      });

    expect(response.status).toBe(201);
    expect(response.body.data).toHaveProperty('id');
    expect(response.body.data.name).toBe('editor');
  });

  it('should return 403 for non-admin users', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/iam/roles')
      .set('Authorization', 'Bearer user_token')
      .send({
        name: 'editor',
        description: '콘텐츠 편집 가능한 역할'
      });

    expect(response.status).toBe(403);
  });
});

describe('POST /v1/iam/permissions', () => {
  it('should return 201 for valid permission creation', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/iam/permissions')
      .set('Authorization', 'Bearer admin_token')
      .send({
        name: 'content:edit',
        resource: 'content',
        action: 'edit',
        description: '콘텐츠 편집 권한'
      });

    expect(response.status).toBe(201);
    expect(response.body.data).toHaveProperty('id');
    expect(response.body.data.name).toBe('content:edit');
  });
});

describe('POST /v1/users/:userId/roles', () => {
  it('should return 204 for successful role assignment', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/users/user123/roles')
      .set('Authorization', 'Bearer admin_token')
      .send({
        roleIds: ['role1', 'role2']
      });

    expect(response.status).toBe(204);
  });
});
```

> **참고**: 인증 관련 테스트(로그인, 토큰 갱신 등)는 [Auth 도메인 테스트 명세서](../auth/test-spec.md)를 참조하세요.

### 4. 성능 테스트

#### 4.1 IAM 성능 테스트
```typescript
describe('IAM Performance Testing', () => {
  it('should evaluate permissions in less than 20ms', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'read';
    
    // 캐시 비우기
    await cacheService.delete(`permissions:${userId}:${resource}:${action}`);
    
    const start = Date.now();
    await iamService.checkPermission(userId, resource, action);
    const duration = Date.now() - start;
    
    expect(duration).toBeLessThan(20);
  });
  
  it('should handle 5000 permission checks per second', async () => {
    const userId = 'user123';
    const resource = 'content';
    const action = 'read';
    
    // 캐시 설정 (실제 로직 실행 없이 캐시된 결과 사용)
    await cacheService.set(`permissions:${userId}:${resource}:${action}`, true, 300);
    
    const requestCount = 5000;
    const start = Date.now();
    
    const requests = Array(requestCount).fill().map(() => 
      iamService.checkPermission(userId, resource, action)
    );
    
    await Promise.all(requests);
    const duration = Date.now() - start;
    
    // 5000개 요청이 1초 이내에 처리되어야 함
    expect(duration).toBeLessThan(1000);
  });
});
```

#### 4.2 부하 테스트 시나리오
```typescript
describe('Load Testing', () => {
  it('should handle 100 concurrent login requests', async () => {
    const requests = Array(100).fill().map(() => (
      request(app.getHttpServer())
        .post('/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123!',
        })
    ));

    const results = await Promise.all(requests);
    const successCount = results.filter(r => r.status === 200).length;
    expect(successCount).toBe(100);
  });

  it('should maintain response time under 300ms for user lookup', async () => {
    const start = Date.now();
    await request(app.getHttpServer())
      .get('/v1/users/user123')
      .set('Authorization', 'Bearer token');
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(300);
  });
});
```

### 5. 보안 테스트

#### 5.1 인증 테스트
```typescript
describe('Security Testing - Authentication', () => {
  it('should reject requests without valid token', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/users/user123');
    expect(response.status).toBe(401);
  });

  it('should reject expired tokens', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/users/user123')
      .set('Authorization', 'Bearer expired_token');
    expect(response.status).toBe(401);
    expect(response.body.code).toBe('AUTH002');
  });
});
```

#### 5.2 권한 테스트
```typescript
describe('Security Testing - Authorization', () => {
  it('should reject access to admin endpoints for non-admin users', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/users/user123/roles')
      .set('Authorization', 'Bearer user_token')
      .send({
        roles: ['admin'],
      });
    expect(response.status).toBe(403);
  });
  
  it('should reject access when required permission is missing', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/iam/roles')
      .set('Authorization', 'Bearer limited_admin_token')
      .send({
        name: 'new-role',
        description: '새 역할'
      });
    
    expect(response.status).toBe(403);
    expect(response.body.code).toBe('IAM006');
  });
  
  it('should allow access when required permission is present', async () => {
    const response = await request(app.getHttpServer())
      .get('/v1/iam/roles')
      .set('Authorization', 'Bearer role_admin_token');
    
    expect(response.status).toBe(200);
  });
});
```

## 테스트 환경 설정

### 1. 테스트 데이터베이스
```typescript
const testConfig = {
  type: 'postgres',
  host: process.env.TEST_DB_HOST,
  port: process.env.TEST_DB_PORT,
  username: process.env.TEST_DB_USERNAME,
  password: process.env.TEST_DB_PASSWORD,
  database: process.env.TEST_DB_NAME,
  synchronize: true,
  logging: false,
};
```

### 2. 테스트 캐시
```typescript
const testCacheConfig = {
  store: redisStore,
  host: process.env.TEST_REDIS_HOST,
  port: process.env.TEST_REDIS_PORT,
  ttl: 60,
};
```

## 테스트 커버리지 요구사항

### 코드 커버리지
- 라인 커버리지: 85% 이상
- 브랜치 커버리지: 80% 이상
- 함수 커버리지: 90% 이상

### 시나리오 커버리지
- 모든 API 엔드포인트에 대한 성공/실패 케이스 포함
- 모든 비즈니스 로직 시나리오 포함
- 모든 에러 케이스 포함

### IAM 특화 커버리지 요구사항
- 모든 IAM 정책 평가 로직에 대한 테스트 (90% 이상)
- 다양한 정책 조합 시나리오 테스트
- 역할 계층 구조 관련 테스트
- 정책 충돌 해결 케이스 테스트
- 캐싱 및 무효화 로직 테스트

## 테스트 자동화

### CI/CD 파이프라인 설정
```yaml
test:
  stage: test
  script:
    - npm install
    - npm run test:unit
    - npm run test:integration
    - npm run test:e2e
  coverage:
    '/^Statements\\s*:\\s*(\\d+\\.\\d+)%/'
```

### 테스트 리포트 형식
```typescript
const reportConfig = {
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'reports/junit',
      outputName: 'junit.xml',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}',
    }],
    ['jest-html-reporter', {
      pageTitle: 'Test Report',
      outputPath: 'reports/html/test-report.html',
    }],
  ],
};
```

## 변경 이력

| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 |
| 0.1.1 | 2025-03-20 | bok@weltcorp.com | IAM 관련 테스트 시나리오 추가 |