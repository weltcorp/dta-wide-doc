# User 도메인 테스트 명세서

## 1. 개요
이 문서는 User 도메인의 테스트 범위, 시나리오, 환경 설정을 정의합니다.

## 2. 테스트 범위

### 2.1 단위 테스트
1. 엔티티 테스트
   - User
   - Account
   - UserCycle
   - UserProfile (값 객체)
   - AccountSettings (값 객체)
   - UserIAMMapping (IAM 역할 매핑)
   - IAMChangeRequest (IAM 변경 요청)

2. 서비스 테스트
   - UserService
   - AuthService
   - AccountService
   - CycleService
   - UserIAMService
   - IAMPermissionValidationService

3. 이벤트 핸들러 테스트
   - UserEventHandler
   - CycleEventHandler
   - IAMEventHandler

4. 캐시 서비스 테스트
   - UserCacheService
   - IAMPermissionCacheService

### 2.2 통합 테스트
1. API 엔드포인트 테스트
   - 사용자 등록/수정/조회
   - 로그인/토큰 갱신
   - 계정 관리
   - 주기 관리
   - IAM 역할 할당/회수
   - 권한 검증
   - 권한 변경 요청 관리

2. 데이터베이스 연동 테스트
   - TypeORM 리포지토리
   - 트랜잭션 처리
   - 인덱스 성능

3. 캐시 연동 테스트
   - Redis 캐시 동작
   - 캐시 무효화

4. 이벤트 발행/구독 테스트
   - 이벤트 전파
   - 이벤트 핸들링

### 2.3 E2E 테스트
1. 사용자 시나리오
   - 회원가입부터 로그인까지
   - 프로필 수정 및 조회
   - 주기 생성 및 관리
   - IAM 역할 할당 및 검증
   - 권한 요청 및 승인 흐름

2. 에러 처리
   - 유효성 검증
   - 권한 검증
   - 예외 상황 처리

3. 성능 테스트
   - 부하 테스트
   - 응답 시간
   - 동시성 처리

## 3. 테스트 시나리오

### 3.1 User 엔티티 테스트
```typescript
describe('User Entity', () => {
  describe('validatePassword', () => {
    it('올바른 비밀번호 검증', () => {
      const user = new User();
      const password = 'password123';
      user.setPassword(password);
      
      expect(user.validatePassword(password)).toBe(true);
    });

    it('잘못된 비밀번호 검증', () => {
      const user = new User();
      user.setPassword('password123');
      
      expect(user.validatePassword('wrong')).toBe(false);
    });
  });
});
```

### 3.2 UserService 테스트
```typescript
describe('UserService', () => {
  describe('createUser', () => {
    it('새로운 사용자 생성', async () => {
      const dto = {
        email: 'test@example.com',
        password: 'password123',
        name: '홍길동'
      };

      const user = await userService.createUser(dto);
      
      expect(user).toBeDefined();
      expect(user.email).toBe(dto.email);
      expect(user.validatePassword(dto.password)).toBe(true);
    });

    it('중복 이메일 오류', async () => {
      const dto = {
        email: 'existing@example.com',
        password: 'password123',
        name: '홍길동'
      };

      await expect(userService.createUser(dto))
        .rejects
        .toThrow(UserError);
    });
  });
});
```

### 3.3 API 통합 테스트
```typescript
describe('UserController (e2e)', () => {
  describe('POST /users/register', () => {
    it('사용자 등록 성공', () => {
      return request(app.getHttpServer())
        .post('/v1/users/register')
        .send({
          email: 'test@example.com',
          password: 'password123',
          name: '홍길동'
        })
        .expect(201)
        .expect(res => {
          expect(res.body.data.email).toBe('test@example.com');
          expect(res.body.data.name).toBe('홍길동');
        });
    });

    it('유효하지 않은 이메일', () => {
      return request(app.getHttpServer())
        .post('/v1/users/register')
        .send({
          email: 'invalid-email',
          password: 'password123',
          name: '홍길동'
        })
        .expect(400)
        .expect(res => {
          expect(res.body.code).toBe('INVALID_EMAIL');
        });
    });
  });
});
```

### 3.4 IAM 통합 테스트
```typescript
describe('UserIAMService', () => {
  describe('getUserRoles', () => {
    it('사용자 역할 목록 조회', async () => {
      // 사용자 역할 매핑 데이터 설정
      const userId = 1;
      const roles = await userIAMService.getUserRoles(userId);
      
      expect(roles).toBeDefined();
      expect(Array.isArray(roles)).toBe(true);
      expect(roles.length).toBeGreaterThan(0);
      expect(roles[0]).toHaveProperty('id');
      expect(roles[0]).toHaveProperty('name');
    });

    it('존재하지 않는 사용자 조회 시 빈 배열 반환', async () => {
      const nonExistingUserId = 9999;
      const roles = await userIAMService.getUserRoles(nonExistingUserId);
      
      expect(roles).toBeDefined();
      expect(Array.isArray(roles)).toBe(true);
      expect(roles.length).toBe(0);
    });
  });

  describe('hasPermission', () => {
    it('권한 있는 경우 true 반환', async () => {
      const userId = 1;
      const resourceType = 'user';
      const resourceId = '1';
      const action = 'read';
      
      const hasPermission = await userIAMService.hasPermission(
        userId, resourceType, resourceId, action
      );
      
      expect(hasPermission).toBe(true);
    });

    it('권한 없는 경우 false 반환', async () => {
      const userId = 2;
      const resourceType = 'admin';
      const resourceId = '1';
      const action = 'write';
      
      const hasPermission = await userIAMService.hasPermission(
        userId, resourceType, resourceId, action
      );
      
      expect(hasPermission).toBe(false);
    });
  });

  describe('requestRoleAssignment', () => {
    it('역할 할당 요청 생성 성공', async () => {
      const requesterId = 1;
      const userId = 2;
      const roleId = 'USER_ADMIN';
      const reason = '업무 수행을 위한 권한 요청';
      
      const request = await userIAMService.requestRoleAssignment(
        requesterId, userId, roleId, reason
      );
      
      expect(request).toBeDefined();
      expect(request.requesterId).toBe(requesterId);
      expect(request.userId).toBe(userId);
      expect(request.iamRoleId).toBe(roleId);
      expect(request.reason).toBe(reason);
      expect(request.status).toBe('PENDING');
    });

    it('이미 할당된 역할 중복 요청 시 오류 발생', async () => {
      const requesterId = 1;
      const userId = 2;
      const roleId = 'ALREADY_ASSIGNED_ROLE';
      const reason = '이미 할당된 역할 요청';
      
      await expect(userIAMService.requestRoleAssignment(
        requesterId, userId, roleId, reason
      )).rejects.toThrow('이미 할당된 역할입니다');
    });
  });

  describe('processRequest', () => {
    it('권한 요청 승인', async () => {
      const requestId = 1;
      const approverId = 3;
      const approved = true;
      const notes = '업무 목적 확인';
      
      const processedRequest = await userIAMService.processRequest(
        requestId, approverId, approved, notes
      );
      
      expect(processedRequest).toBeDefined();
      expect(processedRequest.status).toBe('APPROVED');
      expect(processedRequest.approvedBy).toBe(approverId);
      expect(processedRequest.approvalNotes).toBe(notes);
    });

    it('권한 요청 거부', async () => {
      const requestId = 2;
      const approverId = 3;
      const approved = false;
      const notes = '불필요한 권한 요청';
      
      const processedRequest = await userIAMService.processRequest(
        requestId, approverId, approved, notes
      );
      
      expect(processedRequest).toBeDefined();
      expect(processedRequest.status).toBe('REJECTED');
      expect(processedRequest.approvedBy).toBe(approverId);
      expect(processedRequest.approvalNotes).toBe(notes);
    });
    
    it('자신의 요청을 승인 시도할 경우 오류 발생', async () => {
      const requestId = 3;
      const approverId = 1; // 요청자와 동일한 ID
      const approved = true;
      
      await expect(userIAMService.processRequest(
        requestId, approverId, approved
      )).rejects.toThrow('자신의 요청을 승인할 수 없습니다');
    });
  });
});
```

### 3.5 IAM API 통합 테스트
```typescript
describe('IAM Controller (e2e)', () => {
  describe('GET /users/roles', () => {
    it('사용자 역할 목록 조회 성공', async () => {
      const token = await getAdminToken();
      
      return request(app.getHttpServer())
        .get('/v1/users/roles')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .expect(res => {
          expect(res.body.data).toBeDefined();
          expect(Array.isArray(res.body.data)).toBe(true);
          expect(res.body.data.length).toBeGreaterThan(0);
        });
    });

    it('인증되지 않은 요청 거부', async () => {
      return request(app.getHttpServer())
        .get('/v1/users/roles')
        .expect(401);
    });
  });

  describe('POST /users/:id/role-assignments', () => {
    it('역할 할당 요청 성공', async () => {
      const token = await getAdminToken();
      const userId = 2;
      
      return request(app.getHttpServer())
        .post(`/v1/users/${userId}/role-assignments`)
        .set('Authorization', `Bearer ${token}`)
        .send({
          roleId: 'USER_MANAGER',
          reason: '사용자 관리 업무 담당'
        })
        .expect(201)
        .expect(res => {
          expect(res.body.data).toBeDefined();
          expect(res.body.data.status).toBe('PENDING');
        });
    });

    it('권한 없는 역할 할당 요청 시 거부', async () => {
      const token = await getUserToken();
      const userId = 3;
      
      return request(app.getHttpServer())
        .post(`/v1/users/${userId}/role-assignments`)
        .set('Authorization', `Bearer ${token}`)
        .send({
          roleId: 'SYSTEM_ADMIN',
          reason: '관리자 권한 요청'
        })
        .expect(403);
    });
  });

  describe('PUT /iam/requests/:id/approve', () => {
    it('권한 요청 승인 성공', async () => {
      const token = await getAdminToken();
      const requestId = 1;
      
      return request(app.getHttpServer())
        .put(`/v1/iam/requests/${requestId}/approve`)
        .set('Authorization', `Bearer ${token}`)
        .send({
          notes: '업무 필요성 확인됨'
        })
        .expect(200)
        .expect(res => {
          expect(res.body.data).toBeDefined();
          expect(res.body.data.status).toBe('APPROVED');
        });
    });

    it('승인 권한 없는 사용자 요청 거부', async () => {
      const token = await getUserToken();
      const requestId = 2;
      
      return request(app.getHttpServer())
        .put(`/v1/iam/requests/${requestId}/approve`)
        .set('Authorization', `Bearer ${token}`)
        .send({
          notes: '승인합니다'
        })
        .expect(403);
    });
  });
});
```

## 4. 성능 테스트

### 4.1 부하 테스트 시나리오
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 50 },  // 램프 업
    { duration: '3m', target: 50 },  // 부하 유지
    { duration: '1m', target: 0 }    // 램프 다운
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95%의 요청이 500ms 이내
    http_req_failed: ['rate<0.01']     // 실패율 1% 미만
  }
};

export default function() {
  const BASE_URL = 'https://api.example.com/v1';
  
  // 로그인
  const loginRes = http.post(`${BASE_URL}/users/login`, {
    email: 'test@example.com',
    password: 'password123'
  });
  
  check(loginRes, {
    'login successful': (r) => r.status === 200,
    'has access token': (r) => r.json('data.accessToken') !== undefined
  });

  sleep(1);

  // 사용자 정보 조회
  const token = loginRes.json('data.accessToken');
  const userRes = http.get(`${BASE_URL}/users/me`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  check(userRes, {
    'get user successful': (r) => r.status === 200
  });

  sleep(1);
}
```

### 4.2 성능 요구사항
1. 응답 시간
   - API 응답 시간 p95 < 500ms
   - API 응답 시간 p99 < 1000ms

2. 처리량
   - 초당 트랜잭션: 100 TPS
   - 동시 사용자: 1,000명

3. 에러율
   - 일반 요청: < 0.1%
   - 인증 요청: < 0.5%

## 5. 보안 테스트

### 5.1 인증/인가 테스트
```typescript
describe('Auth Security', () => {
  it('만료된 토큰 거부', async () => {
    const expiredToken = 'expired.jwt.token';
    
    return request(app.getHttpServer())
      .get('/v1/users/me')
      .set('Authorization', `Bearer ${expiredToken}`)
      .expect(401)
      .expect(res => {
        expect(res.body.code).toBe('TOKEN_EXPIRED');
      });
  });

  it('권한 없는 접근 거부', async () => {
    const userToken = await getTestUserToken();
    
    return request(app.getHttpServer())
      .get('/v1/users/admin-only')
      .set('Authorization', `Bearer ${userToken}`)
      .expect(403)
      .expect(res => {
        expect(res.body.code).toBe('FORBIDDEN');
      });
  });
});
```

### 5.2 입력 검증 테스트
```typescript
describe('Input Validation', () => {
  it('SQL 인젝션 방지', async () => {
    return request(app.getHttpServer())
      .get('/v1/users/search')
      .query({ email: "' OR '1'='1" })
      .expect(400)
      .expect(res => {
        expect(res.body.code).toBe('INVALID_INPUT');
      });
  });

  it('XSS 방지', async () => {
    return request(app.getHttpServer())
      .post('/v1/users/register')
      .send({
        name: '<script>alert("xss")</script>',
        email: 'test@example.com',
        password: 'password123'
      })
      .expect(400)
      .expect(res => {
        expect(res.body.code).toBe('INVALID_INPUT');
      });
  });
});
```

## 6. 테스트 환경

### 6.1 데이터베이스 설정
```typescript
// test-database.config.ts
export const testDbConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'test_user',
  password: 'test_password',
  database: 'test_db',
  synchronize: true,
  dropSchema: true,
  entities: ['src/domains/user/infrastructure/persistence/*.ts']
};
```

### 6.2 Redis 설정
```typescript
// test-redis.config.ts
export const testRedisConfig: RedisModuleOptions = {
  host: 'localhost',
  port: 6379,
  db: 1,  // 테스트용 DB
  keyPrefix: 'test:'
};
```

### 6.3 환경 변수
```bash
# test.env
NODE_ENV=test
DB_HOST=localhost
DB_PORT=5432
DB_NAME=test_db
DB_USER=test_user
DB_PASSWORD=test_password
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET=test_secret
```

## 7. 테스트 커버리지 요구사항

### 7.1 커버리지 목표
```javascript
// jest.config.js
module.exports = {
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85
    },
    'src/domains/user/domain/**/*.ts': {
      branches: 90,
      functions: 95,
      lines: 95,
      statements: 95
    },
    'src/domains/user/infrastructure/persistence/iam/*.ts': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90
    }
  }
};
```

### 7.2 중점 커버리지 영역
1. 도메인 로직
   - 엔티티 메서드
   - 값 객체 메서드
   - 도메인 서비스

2. 유효성 검증
   - 입력 값 검증
   - 비즈니스 규칙 검증

3. 에러 처리
   - 예외 발생
   - 에러 변환
   - 에러 응답

## 8. 테스트 자동화

### 8.1 CI/CD 파이프라인
```yaml
# .github/workflows/test.yml
name: User Domain Tests

on:
  push:
    paths:
      - 'src/domains/user/**'
      - 'test/domains/user/**'

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_DB: test_db
          POSTGRES_USER: test_user
          POSTGRES_PASSWORD: test_password
        ports:
          - 5432:5432
      
      redis:
        image: redis:6
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run tests
        run: npm run test:user
        env:
          NODE_ENV: test
          
      - name: Upload coverage
        uses: actions/upload-artifact@v2
        with:
          name: coverage
          path: coverage/
```

### 8.2 테스트 리포트 형식
```typescript
// jest.config.js
module.exports = {
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'reports/junit',
      outputName: 'user-domain.xml',
      classNameTemplate: '{filepath}',
      titleTemplate: '{title}'
    }],
    ['jest-html-reporter', {
      pageTitle: 'User Domain Test Report',
      outputPath: 'reports/html/user-domain.html',
      includeFailureMsg: true
    }]
  ]
};
```

## 변경 이력
|------|------|------|--------|
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-20 | bok@weltcorp.com | 최초 작성 |