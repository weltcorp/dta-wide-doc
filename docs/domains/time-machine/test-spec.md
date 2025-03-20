# TimeMachine 도메인 테스트 명세

## 1. 개요
이 문서는 TimeMachine 도메인의 테스트 범위, 시나리오, 환경 설정 등을 정의합니다.

## 2. 테스트 범위

### 2.1 단위 테스트
- TimeContext 엔티티
- TimeMachineOptions 값 객체
- TimeMachineService
- TimeMachineEventHandler
- TimeMachineCacheService

### 2.2 통합 테스트
- TimeMachineController API 엔드포인트
- 데이터베이스 상호작용
- 이벤트 발행 및 구독
- 캐시 작업

### 2.3 E2E 테스트
- 시간 조회 및 설정 전체 흐름
- 에러 처리 및 복구
- 성능 및 부하 테스트

## 3. 테스트 시나리오

### 3.1 TimeContext 엔티티 테스트
```typescript
describe('TimeContext', () => {
  it('getCurrentTime이 올바른 시간을 반환해야 함', () => {
    const context = new TimeContext();
    context.offsetMs = 3600000; // 1시간
    const currentTime = context.getCurrentTime();
    expect(currentTime.getTime()).toBe(Date.now() + 3600000);
  });

  it('setOffset이 offset과 lastModified를 업데이트해야 함', () => {
    const context = new TimeContext();
    const before = context.lastModified;
    context.setOffset(3600000);
    expect(context.offsetMs).toBe(3600000);
    expect(context.lastModified).not.toBe(before);
  });
});
```

### 3.2 TimeMachineService 테스트
```typescript
describe('TimeMachineService', () => {
  describe('getCurrentTime', () => {
    it('캐시된 시간이 있으면 캐시된 값을 반환해야 함', async () => {
      const cachedTime = new Date();
      jest.spyOn(cacheService, 'get').mockResolvedValue(cachedTime.toISOString());
      
      const result = await service.getCurrentTime(options);
      expect(result).toEqual(cachedTime);
    });

    it('캐시가 없으면 새로운 시간을 계산하고 캐시해야 함', async () => {
      jest.spyOn(cacheService, 'get').mockResolvedValue(null);
      const context = new TimeContext();
      jest.spyOn(repository, 'findByUserId').mockResolvedValue(context);
      
      await service.getCurrentTime(options);
      expect(cacheService.set).toHaveBeenCalled();
    });
  });

  describe('setTime', () => {
    it('시간 설정 후 이벤트를 발행하고 캐시를 무효화해야 함', async () => {
      const context = new TimeContext();
      jest.spyOn(repository, 'findByUserId').mockResolvedValue(context);
      
      await service.setTime(1, new Date(), 'test');
      expect(eventEmitter.emit).toHaveBeenCalledWith('time.set', expect.any(Object));
      expect(cacheService.invalidate).toHaveBeenCalledWith(1);
    });
  });
});
```

### 3.3 API 통합 테스트
```typescript
describe('TimeMachineController (e2e)', () => {
  it('GET /v1/time-machine/current-time 성공 응답', () => {
    return request(app.getHttpServer())
      .get('/v1/time-machine/current-time')
      .query({ userId: 1 })
      .expect(200)
      .expect(res => {
        expect(res.body.data).toHaveProperty('currentTime');
        expect(res.body.data).toHaveProperty('timezone');
        expect(res.body.data).toHaveProperty('offset');
      });
  });

  it('POST /v1/time-machine/set-time 인증 없이 실패', () => {
    return request(app.getHttpServer())
      .post('/v1/time-machine/set-time')
      .send({
        userId: 1,
        targetTime: new Date().toISOString(),
        reason: 'test'
      })
      .expect(401);
  });
});
```

### 3.4 이벤트 핸들러 테스트
```typescript
describe('TimeMachineEventHandler', () => {
  it('TimeSet 이벤트 발생 시 캐시를 무효화해야 함', async () => {
    const handler = new TimeMachineEventHandler(cacheService);
    await handler.handleTimeSet({
      userId: 1,
      oldTime: new Date(),
      newTime: new Date(),
      reason: 'test'
    });
    expect(cacheService.invalidate).toHaveBeenCalledWith(1);
  });
});
```

## 4. 성능 테스트

### 4.1 부하 테스트 시나리오
- 동시 사용자 100명이 초당 10회 시간 조회
- 동시 사용자 10명이 초당 1회 시간 설정
- 24시간 연속 운영 테스트

### 4.2 성능 요구사항
- API 응답 시간: 95%가 100ms 이내
- 에러율: 0.1% 미만
- 초당 처리량: 1000 TPS 이상

### 4.3 k6 테스트 스크립트
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 100,
  duration: '5m',
};

export default function () {
  const res = http.get('http://api.example.com/v1/time-machine/current-time');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 100ms': (r) => r.timings.duration < 100,
  });
  sleep(0.1);
}
```

## 5. 보안 테스트

### 5.1 인증/인가 테스트
- 관리자 API에 대한 권한 검증
- 잘못된 토큰으로의 접근 시도
- 권한 없는 사용자의 시간 설정 시도

### 5.2 입력 검증 테스트
- 잘못된 시간 형식 입력
- 범위를 벗어난 offset 값
- SQL 인젝션 시도
- XSS 시도

## 6. 테스트 환경

### 6.1 테스트 데이터베이스 설정
```typescript
const testConfig = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'test',
  password: 'test',
  database: 'time_machine_test',
  synchronize: true,
  logging: false,
};
```

### 6.2 Redis 설정
```typescript
const redisConfig = {
  host: 'localhost',
  port: 6379,
  db: 1, // 테스트용 DB
};
```

### 6.3 테스트 환경 변수
```env
NODE_ENV=test
TIME_MACHINE_CACHE_TTL=60
TIME_MACHINE_MAX_OFFSET=86400000
```

## 7. 테스트 커버리지 요구사항

### 7.1 커버리지 목표
- 라인 커버리지: 90% 이상
- 브랜치 커버리지: 85% 이상
- 함수 커버리지: 95% 이상

### 7.2 Jest 설정
```json
{
  "coverageThreshold": {
    "global": {
      "branches": 85,
      "functions": 95,
      "lines": 90,
      "statements": 90
    }
  }
}
```

## 8. 테스트 자동화

### 8.1 CI/CD 파이프라인
```yaml
name: Test Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      - name: Install dependencies
        run: npm ci
      - name: Run tests
        run: npm test
      - name: Run E2E tests
        run: npm run test:e2e
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

### 8.2 테스트 리포트
- JUnit XML 형식의 테스트 결과
- Istanbul 커버리지 리포트
- k6 성능 테스트 리포트

## 변경 이력

| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |