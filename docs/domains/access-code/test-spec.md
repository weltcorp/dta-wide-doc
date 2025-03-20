# Access Code 도메인 테스트 명세서

## 1. 개요
이 문서는 AccessCode 도메인의 테스트 전략과 구체적인 테스트 시나리오를 정의합니다. DDD 원칙에 따라 도메인 모델의 무결성과 비즈니스 규칙을 검증하는 것에 중점을 둡니다. 특히 GDPR 준수를 위한 개인정보 보호 요구사항의 검증을 포함합니다.

## 2. 테스트 범위

### 2.1 단위 테스트
#### 도메인 모델
- AccessCode 엔티티
  - 비즈니스 규칙 검증
  - 도메인 이벤트 발행
  - 상태 변경 로직
  - GDPR 관련 메서드
    - 개인정보 처리 동의 검증
    - 데이터 보관 기간 검증
    - 개인정보 마스킹 처리
    - 개인정보 암호화/복호화

- 값 객체
  - TreatmentPeriod
  - TimeMachineOptions
  - PrivacyConsent (신규)
  - PersonalDataMask (신규)

- 도메인 서비스
  - AccessCodeService
  - TimeMachineService
  - AccessCodeFactory
  - PrivacyService (신규)
  - ConsentManagementService (신규)

#### 인프라스트럭처
- AccessCodeRepository
- AccessCodeCache
- AccessCodeEventHandler

### 2.2 통합 테스트
#### API 엔드포인트
- 코드 생성 API
- 코드 검증 API
- 코드 사용 API
- 일괄 생성 API

#### 데이터베이스
- TypeORM 리포지토리
- 트랜잭션 처리
- 인덱스 성능

#### 외부 시스템 통합
- TimeMachine 서비스 연동
- 이메일 서비스 연동
- 이벤트 발행/구독

#### 캐시
- Redis 캐시 동작
- 캐시 무효화
- 동시성 처리

### 2.3 E2E 테스트
#### 사용자 시나리오
- 코드 생성부터 사용까지 전체 흐름
- 이메일 발송 및 확인
- 만료 처리 자동화

#### 에러 처리
- 입력 값 검증
- 권한 검증
- 예외 상황 처리

#### 성능 테스트
- 부하 테스트
- 응답 시간
- 동시성 처리

## 3. 테스트 시나리오

### 3.1 도메인 모델 테스트

#### AccessCode 엔티티 테스트
```typescript
describe('AccessCode Entity', () => {
  let accessCode: AccessCode;
  let timeMachine: TimeMachine;

  beforeEach(() => {
    timeMachine = new TimeMachine();
    accessCode = AccessCodeFactory.create({
      type: AccessCodeType.TREATMENT,
      email: 'test@example.com',
      treatmentPeriodDays: 30,
      timeMachineOptions: {
        useTimeMachine: true,
        testTime: '2024-03-22T00:00:00Z'
      }
    });
  });

  test('isExpired should return true when code is expired', async () => {
    // Arrange
    await timeMachine.advanceTime({ days: 31 });

    // Act
    const result = accessCode.isExpired();

    // Assert
    expect(result).toBe(true);
  });

  test('canBeUsed should validate all usage conditions', () => {
    // Arrange
    const validationResult = accessCode.canBeUsed();

    // Assert
    expect(validationResult.isSuccess).toBe(true);
  });

  test('should emit CodeCreatedEvent when created', () => {
    // Arrange & Act
    const events = accessCode.getDomainEvents();

    // Assert
    expect(events).toContainEqual(
      expect.objectContaining({
        type: 'CodeCreatedEvent',
        payload: expect.objectContaining({
          code: accessCode.code,
          type: accessCode.type
        })
      })
    );
  });
});
```

#### TreatmentPeriod 값 객체 테스트
```typescript
describe('TreatmentPeriod Value Object', () => {
  test('should calculate correct expiration date', () => {
    // Arrange
    const period = new TreatmentPeriod(30);
    const startDate = new Date('2024-03-22');

    // Act
    const expirationDate = period.calculateExpirationDate(startDate);

    // Assert
    expect(expirationDate).toEqual(new Date('2024-04-21'));
  });
});
```

### 3.2 도메인 서비스 테스트

#### AccessCodeService 테스트
```typescript
describe('AccessCodeService', () => {
  let service: AccessCodeService;
  let repository: MockAccessCodeRepository;
  let eventEmitter: MockEventEmitter;
  let timeMachine: TimeMachine;

  beforeEach(() => {
    repository = new MockAccessCodeRepository();
    eventEmitter = new MockEventEmitter();
    timeMachine = new TimeMachine();
    service = new AccessCodeService(repository, eventEmitter, timeMachine);
  });

  test('createAccessCode should create and save new code', async () => {
    // Arrange
    const command = {
      type: AccessCodeType.TREATMENT,
      email: 'test@example.com',
      treatmentPeriodDays: 30
    };

    // Act
    const result = await service.createAccessCode(command);

    // Assert
    expect(result.isSuccess).toBe(true);
    expect(repository.save).toHaveBeenCalledTimes(1);
    expect(eventEmitter.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'CodeCreatedEvent'
      })
    );
  });

  test('validateAccessCode should handle expired codes', async () => {
    // Arrange
    const expiredCode = AccessCodeFactory.createExpired();
    repository.findByCode.mockResolvedValue(expiredCode);

    // Act
    const result = await service.validateAccessCode(expiredCode.code);

    // Assert
    expect(result.isError).toBe(true);
    expect(result.error.code).toBe('CODE_EXPIRED');
  });
});
```

### 3.3 API 통합 테스트

#### AccessCodeController 테스트
```typescript
describe('AccessCodeController (e2e)', () => {
  let app: INestApplication;
  let accessCodeService: AccessCodeService;

  beforeEach(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AccessCodeModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    accessCodeService = moduleFixture.get<AccessCodeService>(AccessCodeService);
  });

  test('/v1/access-codes (POST)', () => {
    // Arrange
    const createDto = {
      type: AccessCodeType.TREATMENT,
      email: 'test@example.com',
      treatmentPeriodDays: 30
    };

    // Act & Assert
    return request(app.getHttpServer())
      .post('/v1/access-codes')
      .send(createDto)
      .expect(201)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('code');
        expect(res.body.status).toBe(201);
      });
  });

  test('/v1/access-codes/validate (POST) - should handle invalid codes', () => {
    // Arrange
    const invalidCode = 'INVALID123';

    // Act & Assert
    return request(app.getHttpServer())
      .post('/v1/access-codes/validate')
      .send({ code: invalidCode })
      .expect(400)
      .expect((res) => {
        expect(res.body.code).toBe('INVALID_ACCESS_CODE');
        expect(res.body.status).toBe(400);
      });
  });
});
```

### 3.4 GDPR 컴플라이언스 테스트

#### 데이터 주체 권리 보장 테스트
```typescript
describe('Data Subject Rights', () => {
  let app: INestApplication;
  let privacyService: PrivacyService;

  beforeEach(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AccessCodeModule, PrivacyModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  test('should allow data access request', async () => {
    const userId = 'user_123';
    
    const response = await request(app.getHttpServer())
      .get(`/v1/access-codes/personal-data/${userId}`)
      .set('Authorization', 'Bearer token')
      .expect(200);

    expect(response.body.data).toHaveProperty('personalData');
    expect(response.body.data.personalData).not.toHaveProperty('password');
  });

  test('should handle data deletion request', async () => {
    const userId = 'user_123';
    
    await request(app.getHttpServer())
      .delete(`/v1/access-codes/personal-data/${userId}`)
      .set('Authorization', 'Bearer token')
      .expect(200);

    const userData = await privacyService.findPersonalData(userId);
    expect(userData).toBeNull();
  });

  test('should process data portability request', async () => {
    const userId = 'user_123';
    
    const response = await request(app.getHttpServer())
      .get(`/v1/access-codes/personal-data/${userId}/export`)
      .set('Authorization', 'Bearer token')
      .expect(200);

    expect(response.body.data).toHaveProperty('format', 'JSON');
    expect(response.body.data).toHaveProperty('personalData');
  });
});
```

#### 동의 관리 API 테스트
```typescript
describe('Consent Management', () => {
  test('should update consent settings', async () => {
    const userId = 'user_123';
    const consentUpdate = {
      consents: {
        dataProcessing: true,
        emailMarketing: false,
        thirdPartySharing: false
      }
    };

    const response = await request(app.getHttpServer())
      .put(`/v1/access-codes/consent/${userId}`)
      .send(consentUpdate)
      .set('Authorization', 'Bearer token')
      .expect(200);

    expect(response.body.data.consents).toEqual(consentUpdate.consents);
  });

  test('should validate consent requirements', async () => {
    const userId = 'user_123';
    const invalidConsent = {
      consents: {
        dataProcessing: false  // 필수 동의 항목
      }
    };

    await request(app.getHttpServer())
      .put(`/v1/access-codes/consent/${userId}`)
      .send(invalidConsent)
      .set('Authorization', 'Bearer token')
      .expect(400);
  });
});
```

#### 개인정보 처리 로그 테스트
```typescript
describe('Personal Data Processing Logs', () => {
  test('should log all personal data access', async () => {
    const userId = 'user_123';
    
    await request(app.getHttpServer())
      .get(`/v1/access-codes/personal-data/${userId}`)
      .set('Authorization', 'Bearer token');

    const logs = await request(app.getHttpServer())
      .get(`/v1/access-codes/personal-data/${userId}/logs`)
      .set('Authorization', 'Bearer token')
      .expect(200);

    expect(logs.body.data.logs).toContainEqual(
      expect.objectContaining({
        action: 'ACCESS',
        category: 'PERSONAL_DATA',
        purpose: 'DATA_SUBJECT_REQUEST'
      })
    );
  });

  test('should track consent changes', async () => {
    const userId = 'user_123';
    
    await request(app.getHttpServer())
      .put(`/v1/access-codes/consent/${userId}`)
      .send({
        consents: {
          emailMarketing: true
        }
      })
      .set('Authorization', 'Bearer token');

    const logs = await request(app.getHttpServer())
      .get(`/v1/access-codes/personal-data/${userId}/logs`)
      .set('Authorization', 'Bearer token')
      .expect(200);

    expect(logs.body.data.logs).toContainEqual(
      expect.objectContaining({
        action: 'UPDATE',
        category: 'CONSENT',
        detail: 'emailMarketing:true'
      })
    );
  });
});
```

### 3.5 보안 테스트

#### 데이터 암호화 테스트
```typescript
describe('Data Encryption', () => {
  test('should encrypt personal data at rest', () => {
    const personalData = new PersonalData({
      email: 'test@example.com',
      deviceId: 'device_123'
    });

    expect(personalData.email.isEncrypted()).toBe(true);
    expect(personalData.deviceId.isEncrypted()).toBe(true);
  });

  test('should use proper encryption for data in transit', async () => {
    const response = await request(app.getHttpServer())
      .post('/v1/access-codes')
      .send({
        email: 'test@example.com'
      })
      .expect(201);

    expect(response.get('Content-Security-Policy')).toBeDefined();
    expect(response.get('Strict-Transport-Security')).toBeDefined();
  });
});
```

## 4. 성능 테스트

### 4.1 부하 테스트 시나리오
- 동시 사용자 100명
- 초당 트랜잭션 50건
- 응답시간 P95 < 500ms
- CPU 사용률 < 70%
- 메모리 사용률 < 80%

### 4.2 데이터 보호 성능 테스트
- 암호화/복호화 작업 < 10ms
- 개인정보 마스킹 처리 < 5ms
- 로그 기록 지연시간 < 100ms
- 동의 처리 응답시간 < 200ms

## 5. IAM 통합 테스트

### 5.1 권한 검증 테스트

#### `AccessCodePermissionService` 테스트
```typescript
describe('AccessCodePermissionService', () => {
  describe('hasPermission', () => {
    it('시스템 관리자는 모든 접근 코드에 대한 권한을 가짐', async () => {
      // 시스템 관리자 역할을 가진 사용자 설정
      const userId = 1;
      mockIAMService.getUserRoles.mockResolvedValue(['SYSTEM_ADMIN']);
      
      const result = await accessCodePermissionService.hasPermission(
        userId,
        'test-access-code-id',
        AccessCodePermission.READ
      );
      
      expect(result).toBe(true);
    });
    
    it('권한이 없는 사용자는 false 반환', async () => {
      const userId = 2;
      mockIAMService.getUserRoles.mockResolvedValue(['REGULAR_USER']);
      
      const result = await accessCodePermissionService.hasPermission(
        userId,
        'test-access-code-id',
        AccessCodePermission.DELETE
      );
      
      expect(result).toBe(false);
    });
    
    it('사이트 관리자는 자신의 사이트 코드에만 접근 가능', async () => {
      const userId = 3;
      const siteId = 10;
      mockIAMService.getUserRoles.mockResolvedValue(['SITE_ADMIN']);
      mockSiteService.getUserSites.mockResolvedValue([10, 11, 12]);
      
      // 사용자의 사이트에 속한 코드
      const result1 = await accessCodePermissionService.hasPermission(
        userId,
        'site-10-code',
        AccessCodePermission.REVOKE,
        { siteId: 10 }
      );
      
      // 사용자의 사이트에 속하지 않은 코드
      const result2 = await accessCodePermissionService.hasPermission(
        userId,
        'site-20-code',
        AccessCodePermission.REVOKE,
        { siteId: 20 }
      );
      
      expect(result1).toBe(true);
      expect(result2).toBe(false);
    });
  });
  
  describe('canCreateAccessCodes', () => {
    it('대량 코드 생성은 ACCESS_CODE_ADMIN 권한 필요', async () => {
      const userId = 1;
      
      // 관리자 권한 케이스
      mockIAMService.getUserRoles.mockResolvedValue(['ACCESS_CODE_ADMIN']);
      const result1 = await accessCodePermissionService.canCreateAccessCodes(
        userId,
        10,
        AccessCodeType.TREATMENT,
        200
      );
      
      // 일반 관리자 권한 케이스
      mockIAMService.getUserRoles.mockResolvedValue(['ACCESS_CODE_MANAGER']);
      const result2 = await accessCodePermissionService.canCreateAccessCodes(
        userId,
        10,
        AccessCodeType.TREATMENT,
        200
      );
      
      expect(result1).toBe(true);
      expect(result2).toBe(false);
    });
    
    it('데모 코드는 ACCESS_CODE_MANAGER 권한으로 생성 가능', async () => {
      const userId = 2;
      mockIAMService.getUserRoles.mockResolvedValue(['ACCESS_CODE_MANAGER']);
      
      const result = await accessCodePermissionService.canCreateAccessCodes(
        userId,
        10,
        AccessCodeType.DEMO,
        50
      );
      
      expect(result).toBe(true);
    });
  });
});
```

### 5.2 권한 정책 테스트

#### `AccessCodeSecurityService` 테스트
```typescript
describe('AccessCodeSecurityService', () => {
  describe('handlePermissionDenied', () => {
    it('권한 거부 이벤트 발생 시 감사 로그 생성', async () => {
      const userId = 1;
      
      await accessCodeSecurityService.handlePermissionDenied(
        userId,
        AccessCodePermission.DELETE,
        'access-code-123'
      );
      
      expect(mockAccessCodeAuditLogRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 1,
          action: 'PERMISSION_DENIED',
          details: expect.objectContaining({
            permissionRequired: AccessCodePermission.DELETE,
            resourceIdentifier: 'access-code-123'
          })
        })
      );
    });
    
    it('특정 횟수 이상 권한 거부 시 알림 발송', async () => {
      const userId = 1;
      
      // 감사 로그에서 최근 실패 횟수 3회로 설정
      mockAccessCodeAuditLogRepository.countRecentDenials.mockResolvedValue(3);
      
      await accessCodeSecurityService.handlePermissionDenied(
        userId,
        AccessCodePermission.DELETE,
        'access-code-123'
      );
      
      expect(mockNotificationService.sendSecurityAlert).toHaveBeenCalled();
    });
  });
  
  describe('detectSuspiciousActivity', () => {
    it('짧은 시간 내 다수의 요청은 비정상 활동으로 감지', async () => {
      const userId = 1;
      const ipAddress = '192.168.1.1';
      
      // 최근 요청 횟수 설정
      mockRequestRateRepository.getRecentRequests.mockResolvedValue(20);
      
      const result = await accessCodeSecurityService.detectSuspiciousActivity(
        userId,
        ipAddress
      );
      
      expect(result).toBe(true);
      expect(mockBlocklistService.addToBlocklist).toHaveBeenCalledWith(
        ipAddress,
        expect.any(Number)
      );
    });
  });
});
```

### 5.3 통합 테스트

#### AccessCode 컨트롤러 IAM 통합 테스트
```typescript
describe('AccessCodeController (E2E)', () => {
  it('권한이 없는 사용자의 코드 생성 요청은 403 반환', async () => {
    // 일반 사용자 권한의 토큰 생성
    const token = await generateToken({ userId: 1, roles: ['REGULAR_USER'] });
    
    const response = await request(app.getHttpServer())
      .post('/v1/access-codes')
      .set('Authorization', `Bearer ${token}`)
      .send({
        siteId: 10,
        type: 'TREATMENT',
        count: 5
      })
      .expect(403);
      
    expect(response.body).toEqual(
      expect.objectContaining({
        error: 'Forbidden',
        message: expect.stringContaining('permission')
      })
    );
  });
  
  it('권한이 있는 사용자의 코드 생성 요청은 201 반환', async () => {
    // 코드 관리자 권한의 토큰 생성
    const token = await generateToken({ userId: 2, roles: ['ACCESS_CODE_MANAGER'] });
    
    const response = await request(app.getHttpServer())
      .post('/v1/access-codes')
      .set('Authorization', `Bearer ${token}`)
      .send({
        siteId: 10,
        type: 'TREATMENT',
        count: 5
      })
      .expect(201);
      
    expect(response.body.data).toHaveLength(5);
    expect(response.body.data[0]).toHaveProperty('code');
  });
  
  it('사이트 관리자는 자신의 사이트 코드만 조회 가능', async () => {
    // 사이트 관리자 권한의 토큰 생성
    const token = await generateToken({ 
      userId: 3, 
      roles: ['SITE_ADMIN'],
      sites: [10, 11]
    });
    
    // 사용자의 사이트에 속한 코드 조회
    await request(app.getHttpServer())
      .get('/v1/access-codes?siteId=10')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
      
    // 사용자의 사이트에 속하지 않은 코드 조회
    await request(app.getHttpServer())
      .get('/v1/access-codes?siteId=20')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  });
});
```

## 6. 테스트 데이터 관리

### 6.1 테스트 데이터 요구사항
- 실제 개인정보 사용 금지
- 가상의 테스트 데이터 사용
- 테스트 완료 후 데이터 자동 삭제
- 민감정보 마스킹 처리

### 6.2 테스트 환경 설정
- 개발 환경과 분리된 테스트 DB
- 테스트용 암호화 키 사용
- 테스트 로그 별도 관리
- 테스트 이메일 서버 구성

## 7. 모니터링 및 알림 테스트

### 7.1 모니터링 지표
- 개인정보 접근 로그
- 동의 변경 이력
- 데이터 삭제 요청 처리
- 보안 이벤트 감지

### 7.2 알림 테스트
- 비정상 접근 탐지
- 대량 데이터 접근 감지
- 동의 철회 알림
- 보관 기간 만료 알림

## 8. 변경 이력

### 버전 1.1 (2024-03-22)
- GDPR 컴플라이언스 테스트 추가
- 개인정보 보호 테스트 시나리오 추가
- 성능 테스트 기준 강화
- 테스트 데이터 관리 정책 추가
- IAM 통합 관련 테스트 케이스 추가

### 버전 1.0 (2024-03-15)
- 초기 테스트 명세서 작성

## 9. 테스트 커버리지 요구사항

### 9.1 코드 커버리지 목표
| 유형 | 목표 커버리지 | 중요 영역 |
|------|--------------|-----------|
| 라인 커버리지 | 80% 이상 | 도메인 로직, 유효성 검증 |
| 브랜치 커버리지 | 75% 이상 | 조건문, 에러 처리 |
| 함수 커버리지 | 90% 이상 | public API, 이벤트 핸들러 |

### 9.2 중요 테스트 영역
- 도메인 모델의 비즈니스 규칙
- TimeMachine 관련 로직
- 보안 및 인증 로직
- 에러 처리 로직
- 캐시 처리 로직

## 10. 테스트 자동화

### 10.1 CI/CD 파이프라인 설정
```yaml
test:
  stage: test
  script:
    - npm ci
    - npm run test:unit
    - npm run test:integration
    - npm run test:e2e
    - npm run test:security
    - npm run test:performance
  coverage:
    '/^All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      junit:
        - junit.xml
      coverage:
        - coverage/
```

### 10.2 테스트 실행 스크립트
```json
{
  "scripts": {
    "test:unit": "jest --config jest.unit.config.js",
    "test:integration": "jest --config jest.integration.config.js",
    "test:e2e": "jest --config jest.e2e.config.js",
    "test:security": "jest --config jest.security.config.js",
    "test:performance": "k6 run performance.test.js",
    "test:coverage": "jest --coverage",
    "test:watch": "jest --watch",
    "test:ci": "npm run test:unit && npm run test:integration && npm run test:e2e"
  }
}
```

## 11. 테스트 리포트

### 11.1 리포트 형식
- JUnit XML 형식의 테스트 결과
- Istanbul 커버리지 리포트
- k6 성능 테스트 리포트
- 보안 테스트 결과 리포트

### 11.2 리포트 항목
- 테스트 실행 시간
- 성공/실패 케이스 수
- 에러 상세 내용
- 코드 커버리지 메트릭스
- 성능 테스트 메트릭스

## 12. TimeMachine 테스트 케이스

### 12.1 시간 조작 테스트
```typescript
describe('TimeMachine Integration', () => {
  describe('시간 조작', () => {
    it('테스트 시간 설정 후 코드 생성', async () => {
      const testTime = new Date('2024-03-20T10:00:00Z');
      await timeMachineService.setTestTime(testTime);

      const result = await service.createAccessCode({
        type: AccessCodeType.TREATMENT,
        creatorUserId: 'user-123',
        treatmentPeriodDays: 30
      });

      expect(result.createdAt).toEqual(testTime);
    });

    it('시간 이동 후 만료 체크', async () => {
      const testTime = new Date('2024-03-20T10:00:00Z');
      const futureTime = new Date('2024-04-20T10:00:00Z');
      
      // 코드 생성 시점 설정
      await timeMachineService.setTestTime(testTime);
      const code = await service.createAccessCode({
        type: AccessCodeType.TREATMENT,
        creatorUserId: 'user-123',
        treatmentPeriodDays: 30
      });

      // 미래로 시간 이동
      await timeMachineService.setTestTime(futureTime);
      const isExpired = await code.isExpired(timeMachineService);
      
      expect(isExpired).toBe(true);
    });
  });

  describe('시스템 시간 대체', () => {
    it('TimeMachine 서비스 실패 시 시스템 시간 사용', async () => {
      jest.spyOn(timeMachineService, 'getCurrentTime')
        .mockRejectedValue(new Error('Service unavailable'));

      const result = await service.createAccessCode({
        type: AccessCodeType.TREATMENT,
        creatorUserId: 'user-123',
        treatmentPeriodDays: 30
      });

      expect(result.createdAt).toBeDefined();
      expect(result.createdAt.getTime())
        .toBeCloseTo(new Date().getTime(), -2); // 2초 이내 오차 허용
    });
  });

  describe('일괄 처리 테스트', () => {
    it('다수의 코드 생성 시 동일 시간 적용', async () => {
      const testTime = new Date('2024-03-20T10:00:00Z');
      await timeMachineService.setTestTime(testTime);

      const results = await service.createAccessCodes({
        count: 10,
        type: AccessCodeType.TREATMENT,
        creatorUserId: 'user-123',
        treatmentPeriodDays: 30
      });

      results.forEach(result => {
        expect(result.createdAt).toEqual(testTime);
      });
    });
  });
});
```

### 12.2 시간 의존성 테스트
```typescript
describe('TimeMachine Dependencies', () => {
  it('외부 라이브러리의 시간 의존성 오버라이드', async () => {
    const testTime = new Date('2024-03-20T10:00:00Z');
    await timeMachineService.setTestTime(testTime);

    // 외부 라이브러리 호출
    const result = await externalService.processWithTimestamp();
    
    expect(result.timestamp).toEqual(testTime.getTime());
  });

  it('캐시 만료 시간 계산', async () => {
    const testTime = new Date('2024-03-20T10:00:00Z');
    await timeMachineService.setTestTime(testTime);

    const ttl = 3600; // 1시간
    await cacheService.set('key', 'value', ttl);
    
    // 59분 후
    await timeMachineService.addSeconds(3540);
    expect(await cacheService.get('key')).toBeDefined();
    
    // 1시간 1분 후
    await timeMachineService.addSeconds(120);
    expect(await cacheService.get('key')).toBeNull();
  });
});
``` 