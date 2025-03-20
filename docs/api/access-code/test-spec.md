# AccessCode API 테스트 명세

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 구현 가이드](./implementation.md)
- [API 요구사항](./requirements.md)

## 개요

## 1. 테스트 범위

### 1.1 단위 테스트
- AccessCodeService의 각 메소드
- DTO 유효성 검증
- 에러 처리
- 유틸리티 함수

### 1.2 통합 테스트
- API 엔드포인트
- 데이터베이스 연동
- 캐시 동작
- 이벤트 발행/구독

### 1.3 E2E 테스트
- 전체 사용자 시나리오
- 성능 테스트
- 부하 테스트

## 2. 테스트 시나리오

### 2.1 코드 생성 테스트
```typescript
describe('AccessCodeService.createCode', () => {
  it('should create a new access code', async () => {
    const dto = {
      type: AccessCodeType.TREATMENT,
      creatorId: 'user_123',
      treatmentPeriod: 90,
      usagePeriod: 30,
      registrationChannel: RegistrationChannel.WEB,
      deliveryMethod: DeliveryMethod.EMAIL
    };

    const result = await service.createCode(dto);

    expect(result).toBeDefined();
    expect(result.code).toMatch(/^[A-Z0-9]{16}$/);
    expect(result.status).toBe(AccessCodeStatus.UNUSED);
  });

  it('should fail with invalid treatment period', async () => {
    const dto = {
      ...validDto,
      treatmentPeriod: 366 // 최대 365일
    };

    await expect(service.createCode(dto)).rejects.toThrow();
  });
});
```

### 2.2 코드 검증 테스트
```typescript
describe('AccessCodeService.validateCode', () => {
  it('should validate unused code', async () => {
    const code = 'AB12CD34EF56GH78';
    const deviceId = 'DEVICE_001';

    const result = await service.validateCode(code, deviceId);

    expect(result.isValid).toBe(true);
    expect(result.codeInfo).toBeDefined();
  });

  it('should fail with expired code', async () => {
    // 만료된 코드 테스트
    const expiredCode = 'XX99YY88ZZ77WW66';
    
    await expect(
      service.validateCode(expiredCode, 'DEVICE_001')
    ).rejects.toThrow(ErrorResponseDto);
  });
});
```

### 2.3 코드 사용 테스트
```typescript
describe('AccessCodeService.useCode', () => {
  it('should mark code as used', async () => {
    const code = await service.useCode({
      codeId: 'code_123',
      userId: 'user_123',
      deviceId: 'DEVICE_001'
    });

    expect(code.status).toBe(AccessCodeStatus.USED);
    expect(code.usedAt).toBeDefined();
  });

  it('should fail with already used code', async () => {
    // 이미 사용된 코드 테스트
    await expect(
      service.useCode({
        codeId: 'used_code_123',
        userId: 'user_123',
        deviceId: 'DEVICE_001'
      })
    ).rejects.toThrow(ErrorResponseDto);
  });
});
```

## 3. 테스트 환경 설정

### 3.1 테스트 데이터베이스
```typescript
const testConfig = {
  type: 'postgres',
  host: process.env.TEST_DB_HOST,
  port: process.env.TEST_DB_PORT,
  username: process.env.TEST_DB_USER,
  password: process.env.TEST_DB_PASSWORD,
  database: process.env.TEST_DB_NAME,
  entities: ['src/**/*.entity.ts'],
  synchronize: true
};
```

### 3.2 테스트 Redis
```typescript
const testRedisConfig = {
  host: process.env.TEST_REDIS_HOST,
  port: process.env.TEST_REDIS_PORT,
  db: 1 // 테스트용 DB
};
```

### 3.3 TimeMachine 모의 객체
```typescript
@Injectable()
class MockTimeMachineService {
  private currentTime: Date = new Date();

  async getCurrentTime(): Promise<Date> {
    return this.currentTime;
  }

  setCurrentTime(time: Date): void {
    this.currentTime = time;
  }
}
```

## 4. API 테스트

### 4.1 엔드포인트 테스트
```typescript
describe('AccessCodeController (e2e)', () => {
  it('/access-codes (POST)', () => {
    return request(app.getHttpServer())
      .post('/v1/access-codes')
      .set('Authorization', `Bearer ${token}`)
      .send(createCodeDto)
      .expect(201)
      .expect(res => {
        expect(res.body.data).toBeDefined();
        expect(res.body.data.code).toMatch(/^[A-Z0-9]{16}$/);
      });
  });

  it('/access-codes/validate (POST)', () => {
    return request(app.getHttpServer())
      .post('/v1/access-codes/validate')
      .send({ code: 'AB12CD34EF56GH78', deviceId: 'DEVICE_001' })
      .expect(200)
      .expect(res => {
        expect(res.body.data.isValid).toBe(true);
      });
  });
});
```

### 4.2 에러 응답 테스트
```typescript
describe('Error Responses', () => {
  it('should return 400 for invalid input', () => {
    return request(app.getHttpServer())
      .post('/v1/access-codes')
      .set('Authorization', `Bearer ${token}`)
      .send({}) // 빈 요청
      .expect(400)
      .expect(res => {
        expect(res.body.code).toBe(ErrorCode.INVALID_INPUT);
      });
  });

  it('should return 401 for invalid token', () => {
    return request(app.getHttpServer())
      .post('/v1/access-codes')
      .set('Authorization', 'Bearer invalid_token')
      .send(createCodeDto)
      .expect(401)
      .expect(res => {
        expect(res.body.code).toBe(ErrorCode.UNAUTHORIZED);
      });
  });
});
```

## 5. 성능 테스트

### 5.1 부하 테스트 시나리오
```typescript
describe('Load Testing', () => {
  it('should handle concurrent code creation', async () => {
    const concurrentRequests = 100;
    const requests = Array(concurrentRequests).fill(createCodeDto);
    
    const results = await Promise.all(
      requests.map(dto => service.createCode(dto))
    );

    expect(results).toHaveLength(concurrentRequests);
    results.forEach(result => {
      expect(result.code).toBeDefined();
    });
  });

  it('should maintain response time under load', async () => {
    const start = Date.now();
    
    await service.validateCode('TEST_CODE', 'DEVICE_001');
    
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(200); // 200ms 이내
  });
});
```

### 5.2 캐시 성능 테스트
```typescript
describe('Cache Performance', () => {
  it('should use cache for repeated validation', async () => {
    const code = 'TEST_CODE';
    const deviceId = 'DEVICE_001';

    // 첫 번째 요청 (캐시 미스)
    const start1 = Date.now();
    await service.validateCode(code, deviceId);
    const duration1 = Date.now() - start1;

    // 두 번째 요청 (캐시 히트)
    const start2 = Date.now();
    await service.validateCode(code, deviceId);
    const duration2 = Date.now() - start2;

    expect(duration2).toBeLessThan(duration1);
  });
});
```

## 6. 테스트 데이터

### 6.1 테스트 데이터 생성
```typescript
const createTestData = async () => {
  const codes = [
    {
      type: AccessCodeType.TREATMENT,
      status: AccessCodeStatus.UNUSED,
      expiresAt: addDays(new Date(), 30)
    },
    {
      type: AccessCodeType.CLINICAL_TRIAL,
      status: AccessCodeStatus.USED,
      expiresAt: addDays(new Date(), -1)
    }
  ];

  await accessCodeRepository.save(codes);
};
```

### 6.2 테스트 데이터 정리
```typescript
const cleanupTestData = async () => {
  await accessCodeRepository.clear();
  await cacheManager.reset();
};
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 | 