# TimeMachine 테스트 명세서

## 개요
이 문서는 TimeMachine 서비스의 테스트 요구사항과 시나리오를 정의합니다.

## 테스트 범위

### 1. 단위 테스트
#### TimeService
```typescript
describe('TimeService', () => {
  // 현재 시간 조회
  describe('getCurrentTime', () => {
    it('should return cached time when available', async () => {
      // given: 캐시된 시간 정보가 있는 경우
      // when: getCurrentTime 호출
      // then: 캐시된 시간 정보 반환
    });

    it('should fetch from database when cache miss', async () => {
      // given: 캐시가 없는 경우
      // when: getCurrentTime 호출
      // then: DB에서 조회 후 캐시 저장
    });

    it('should handle timezone conversion', async () => {
      // given: UTC 외 시간대 요청
      // when: getCurrentTime('Asia/Seoul') 호출
      // then: 변환된 시간 반환
    });
  });

  // 시스템 시간 설정
  describe('setSystemTime', () => {
    it('should update system time', async () => {
      // given: 유효한 시간 설정 요청
      // when: setSystemTime 호출
      // then: 시간 업데이트 및 캐시 갱신
    });

    it('should validate timestamp range', async () => {
      // given: 유효하지 않은 타임스탬프
      // when: setSystemTime 호출
      // then: INVALID_TIMESTAMP 에러
    });
  });
});
```

#### SyncService
```typescript
describe('SyncService', () => {
  describe('syncTime', () => {
    it('should calculate drift correctly', async () => {
      // given: 노드 시간 정보
      // when: syncTime 호출
      // then: 드리프트 계산 및 상태 업데이트
    });

    it('should handle sync failure', async () => {
      // given: 동기화 실패 상황
      // when: syncTime 호출
      // then: SYNC_ERROR 에러
    });
  });
});
```

### 2. 통합 테스트
```typescript
describe('TimeMachine Integration', () => {
  describe('Time Management Flow', () => {
    it('should maintain time consistency', async () => {
      // 1. 시스템 시간 설정
      // 2. 시간 조회
      // 3. 캐시 검증
      // 4. DB 상태 검증
    });

    it('should handle concurrent requests', async () => {
      // 1. 다중 시간 조회 요청
      // 2. 성능 측정
      // 3. 응답 일관성 검증
    });
  });

  describe('Node Synchronization', () => {
    it('should synchronize across nodes', async () => {
      // 1. 여러 노드 시간 설정
      // 2. 동기화 수행
      // 3. 드리프트 검증
    });
  });
});
```

### 3. E2E 테스트
```typescript
describe('TimeMachine E2E', () => {
  describe('API Endpoints', () => {
    it('GET /v1/time-machine/current-time', async () => {
      // 1. API 호출
      // 2. 응답 형식 검증
      // 3. 상태 코드 검증
      // 4. 성능 측정
    });

    it('POST /v1/time-machine/system-time', async () => {
      // 1. 인증 토큰 준비
      // 2. API 호출
      // 3. 권한 검증
      // 4. 결과 검증
    });
  });
});
```

## 성능 테스트

### 1. 부하 테스트 시나리오
```typescript
describe('Load Testing', () => {
  it('should handle 1000 concurrent requests', async () => {
    const requests = 1000;
    const maxResponseTime = 50; // ms
    const errorRate = 0.1; // 0.1%

    // 1. 동시 요청 생성
    // 2. 응답 시간 측정
    // 3. 에러율 계산
    // 4. 성능 기준 검증
  });
});
```

### 2. 스트레스 테스트
```typescript
describe('Stress Testing', () => {
  it('should maintain performance under sustained load', async () => {
    const duration = 3600; // 1시간
    const rps = 100; // 초당 요청 수

    // 1. 지속적 부하 생성
    // 2. 시스템 리소스 모니터링
    // 3. 성능 저하 측정
    // 4. 복구 능력 검증
  });
});
```

## 보안 테스트

### 1. 인증/인가 테스트
```typescript
describe('Security Testing', () => {
  it('should require valid authentication', async () => {
    // 1. 유효하지 않은 토큰으로 요청
    // 2. 만료된 토큰으로 요청
    // 3. 권한 없는 토큰으로 요청
  });

  it('should validate input parameters', async () => {
    // 1. SQL 인젝션 시도
    // 2. XSS 시도
    // 3. 입력값 검증
  });
});
```

### 2. 감사 로그 테스트
```typescript
describe('Audit Logging', () => {
  it('should log all time changes', async () => {
    // 1. 시간 변경 수행
    // 2. 로그 엔트리 검증
    // 3. 로그 포맷 검증
  });
});
```

## 테스트 환경 설정

### 1. 테스트 데이터베이스
```typescript
const testDbConfig = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'test',
  password: 'test',
  database: 'time_machine_test',
  synchronize: true
};
```

### 2. 테스트 캐시
```typescript
const testCacheConfig = {
  store: 'memory',
  ttl: 60,
  max: 100
};
```

### 3. 모의 객체 설정
```typescript
const mockTimeRepository = {
  findOne: jest.fn(),
  save: jest.fn()
};

const mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn()
};
```

## 테스트 커버리지 요구사항

### 1. 코드 커버리지
- 라인 커버리지: 90% 이상
- 브랜치 커버리지: 85% 이상
- 함수 커버리지: 95% 이상

### 2. 시나리오 커버리지
- 모든 API 엔드포인트 테스트
- 모든 에러 케이스 테스트
- 주요 비즈니스 시나리오 테스트

## 테스트 자동화

### 1. CI/CD 파이프라인
```yaml
test:
  stage: test
  script:
    - npm run test:unit
    - npm run test:integration
    - npm run test:e2e
    - npm run test:coverage
  coverage:
    report:
      coverage_format: cobertura
```

### 2. 테스트 보고서
- JUnit XML 형식 테스트 결과
- Istanbul 코드 커버리지 리포트
- 성능 테스트 결과 그래프

## 변경 이력
| 버전 | 날짜 | 작성자 | 설명 |
|------|------|--------|------|
| 0.1.0 | 2025-03-15 | bok@weltcorp.com | 최초 작성 |