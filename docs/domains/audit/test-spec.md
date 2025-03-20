# Audit 테스트 명세

## 1. 테스트 전략

### 테스트 수준
- **단위 테스트**: 개별 클래스와 메서드 수준의 테스트
- **통합 테스트**: 컴포넌트 간 상호작용 검증
- **시스템 테스트**: 전체 시스템 기능 검증
- **성능 테스트**: 부하 및 확장성 검증

### 테스트 환경
| 환경 | 목적 | 인프라 | 데이터 |
|-----|-----|-----|-----|
| 로컬 | 개발자 테스트 | 로컬 에뮬레이터 | 테스트 데이터 |
| 개발 | 통합 테스트 | 개발 클러스터 | 익명화된 샘플 데이터 |
| 스테이징 | 시스템 테스트 | 프로덕션 유사 환경 | 프로덕션 데이터 복제본 |
| 프로덕션 | 카나리 테스트 | 프로덕션 인프라 | 프로덕션 데이터 |

### 테스트 도구
- **단위 테스트**: Jest
- **통합 테스트**: Jest + Supertest
- **API 테스트**: Postman
- **성능 테스트**: k6
- **모니터링**: Google Cloud Monitoring

## 2. 단위 테스트

### 도메인 모델 테스트
```typescript
// audit-log.model.spec.ts
describe('AuditLog', () => {
  describe('validate', () => {
    it('should throw error when timestamp is missing', () => {
      expect(() => new AuditLog({
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      })).toThrow('Timestamp is required');
    });

    it('should throw error when eventType is missing', () => {
      expect(() => new AuditLog({
        timestamp: new Date(),
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      })).toThrow('Event type is required');
    });

    it('should throw error when source is missing', () => {
      expect(() => new AuditLog({
        timestamp: new Date(),
        eventType: 'USER_LOGIN',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      })).toThrow('Source is required');
    });

    it('should throw error when both actor and target are missing', () => {
      expect(() => new AuditLog({
        timestamp: new Date(),
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      })).toThrow('At least one of actor or target must be provided');
    });

    it('should create valid AuditLog with minimum required fields', () => {
      const auditLog = new AuditLog({
        timestamp: new Date(),
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      });

      expect(auditLog).toBeDefined();
      expect(auditLog.eventType).toBe('USER_LOGIN');
    });
  });
});
```

### 서비스 계층 테스트
```typescript
// audit.service.spec.ts
describe('AuditService', () => {
  let service: AuditService;
  let repository: MockType<AuditLogRepository>;
  let timeMachineService: MockType<TimeMachineService>;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        AuditService,
        {
          provide: AuditLogRepository,
          useFactory: mockRepository,
        },
        {
          provide: TimeMachineService,
          useFactory: mockTimeMachineService,
        },
      ],
    }).compile();

    service = module.get(AuditService);
    repository = module.get(AuditLogRepository);
    timeMachineService = module.get(TimeMachineService);
  });

  describe('createAuditLog', () => {
    it('should create audit log with current time', async () => {
      // Arrange
      const mockDate = new Date('2023-01-01T00:00:00Z');
      timeMachineService.getCurrentDate.mockResolvedValue(mockDate);
      
      const request: AuditLogRequest = {
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      };
      
      repository.save.mockResolvedValue({
        id: 'test-id',
        timestamp: mockDate,
        ...request
      });

      // Act
      const result = await service.createAuditLog(request);

      // Assert
      expect(timeMachineService.getCurrentDate).toHaveBeenCalled();
      expect(repository.save).toHaveBeenCalledWith(expect.objectContaining({
        timestamp: mockDate,
        eventType: 'USER_LOGIN',
        source: 'auth-service'
      }));
      expect(result.id).toBeDefined();
      expect(result.timestamp).toEqual(mockDate);
    });

    it('should use provided timestamp if available', async () => {
      // Arrange
      const providedDate = new Date('2023-01-01T00:00:00Z');
      const mockCurrentDate = new Date('2023-01-02T00:00:00Z');
      timeMachineService.getCurrentDate.mockResolvedValue(mockCurrentDate);
      
      const request: AuditLogRequest = {
        timestamp: providedDate,
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      };
      
      repository.save.mockResolvedValue({
        id: 'test-id',
        ...request
      });

      // Act
      const result = await service.createAuditLog(request);

      // Assert
      expect(timeMachineService.getCurrentDate).toHaveBeenCalled();
      expect(repository.save).toHaveBeenCalledWith(expect.objectContaining({
        timestamp: providedDate,
        eventType: 'USER_LOGIN',
        source: 'auth-service'
      }));
      expect(result.timestamp).toEqual(providedDate);
    });
  });

  describe('queryAuditLogs', () => {
    it('should return audit logs matching query', async () => {
      // Arrange
      const query: AuditLogQuery = {
        startDate: new Date('2023-01-01T00:00:00Z'),
        endDate: new Date('2023-01-02T00:00:00Z'),
        eventTypes: ['USER_LOGIN'],
        sources: ['auth-service'],
        page: 1,
        limit: 10
      };
      
      const mockLogs = [
        {
          id: 'log1',
          timestamp: new Date('2023-01-01T12:00:00Z'),
          eventType: 'USER_LOGIN',
          source: 'auth-service',
          actor: { type: ActorType.USER, id: 'user1' },
          action: 'LOGIN',
          metadata: {},
          status: AuditStatus.SUCCESS
        }
      ];
      
      repository.search.mockResolvedValue(mockLogs);

      // Act
      const result = await service.queryAuditLogs(query);

      // Assert
      expect(repository.search).toHaveBeenCalledWith(query);
      expect(result).toEqual(mockLogs);
      expect(result.length).toBe(1);
    });
  });
});
```

### 리포지토리 계층 테스트
```typescript
// bigquery-audit-log.repository.spec.ts
describe('BigQueryAuditLogRepository', () => {
  let repository: BigQueryAuditLogRepository;
  let bigQueryMock: DeepMock<BigQuery>;

  beforeEach(async () => {
    bigQueryMock = createMock<BigQuery>();
    
    const module = await Test.createTestingModule({
      providers: [
        BigQueryAuditLogRepository,
        {
          provide: BigQuery,
          useValue: bigQueryMock,
        },
      ],
    }).compile();

    repository = module.get(BigQueryAuditLogRepository);
  });

  describe('save', () => {
    it('should insert audit log into BigQuery', async () => {
      // Arrange
      const mockTable = {
        insert: jest.fn().mockResolvedValue([])
      };
      
      const mockDataset = {
        table: jest.fn().mockReturnValue(mockTable)
      };
      
      bigQueryMock.dataset.mockReturnValue(mockDataset as any);
      
      const auditLog = new AuditLog({
        id: 'test-id',
        timestamp: new Date('2023-01-01T00:00:00Z'),
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: ActorType.USER, id: 'user1' },
        action: 'LOGIN',
        metadata: {},
        status: AuditStatus.SUCCESS
      });

      // Act
      await repository.save(auditLog);

      // Assert
      expect(bigQueryMock.dataset).toHaveBeenCalledWith('de');
      expect(mockDataset.table).toHaveBeenCalledWith('audit_logs');
      expect(mockTable.insert).toHaveBeenCalledWith(expect.objectContaining({
        id: 'test-id',
        timestamp: auditLog.timestamp,
        event_type: 'USER_LOGIN',
        source: 'auth-service'
      }));
    });
  });

  describe('search', () => {
    it('should query audit logs by criteria', async () => {
      // Arrange
      const mockRows = [
        {
          id: 'log1',
          timestamp: '2023-01-01T12:00:00Z',
          event_type: 'USER_LOGIN',
          source: 'auth-service',
          actor: JSON.stringify({ type: 'USER', id: 'user1' }),
          action: 'LOGIN',
          status: 'SUCCESS'
        }
      ];
      
      bigQueryMock.query.mockResolvedValue([mockRows]);
      
      const query: AuditLogQuery = {
        startDate: new Date('2023-01-01T00:00:00Z'),
        endDate: new Date('2023-01-02T00:00:00Z'),
        eventTypes: ['USER_LOGIN'],
        sources: ['auth-service'],
        page: 1,
        limit: 10
      };

      // Mock buildSearchQuery method
      jest.spyOn(repository as any, 'buildSearchQuery').mockReturnValue({
        query: 'SELECT * FROM table',
        params: {}
      });

      // Act
      const result = await repository.search(query);

      // Assert
      expect(bigQueryMock.query).toHaveBeenCalled();
      expect(result.length).toBe(1);
      expect(result[0].eventType).toBe('USER_LOGIN');
      expect(result[0].source).toBe('auth-service');
    });
  });
});
```

## 3. 통합 테스트

### API 계층 통합 테스트
```typescript
// audit-log.controller.e2e-spec.ts
describe('AuditLogController (e2e)', () => {
  let app: INestApplication;
  let authService: AuthService;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [
        AuditModule,
        // Mock dependencies
        MockAuthModule,
        MockTimeMachineModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    
    authService = moduleFixture.get<AuthService>(AuthService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('/v1/audit-logs (POST)', () => {
    it('should create audit log and return 201', async () => {
      // Arrange
      const adminToken = await authService.generateTestToken({
        userId: 'admin1',
        roles: ['AUDIT_ADMIN']
      });
      
      const createDto = {
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: 'USER', id: 'user1' },
        action: 'LOGIN'
      };

      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/audit-logs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(createDto)
        .expect(201)
        .expect(res => {
          expect(res.body.eventType).toBe('USER_LOGIN');
          expect(res.body.source).toBe('auth-service');
          expect(res.body.id).toBeDefined();
        });
    });

    it('should return 403 for non-admin user', async () => {
      // Arrange
      const userToken = await authService.generateTestToken({
        userId: 'user1',
        roles: ['AUDIT_VIEWER']
      });
      
      const createDto = {
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: 'USER', id: 'user1' },
        action: 'LOGIN'
      };

      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/audit-logs')
        .set('Authorization', `Bearer ${userToken}`)
        .send(createDto)
        .expect(403);
    });
  });

  describe('/v1/audit-logs (GET)', () => {
    it('should return audit logs matching query params', async () => {
      // Arrange
      const viewerToken = await authService.generateTestToken({
        userId: 'viewer1',
        roles: ['AUDIT_VIEWER']
      });

      // Act & Assert
      return request(app.getHttpServer())
        .get('/v1/audit-logs')
        .set('Authorization', `Bearer ${viewerToken}`)
        .query({
          startDate: '2023-01-01T00:00:00Z',
          endDate: '2023-01-02T00:00:00Z',
          eventTypes: 'USER_LOGIN',
          sources: 'auth-service',
          page: 1,
          limit: 10
        })
        .expect(200)
        .expect(res => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });

    it('should return 401 without authentication', async () => {
      // Act & Assert
      return request(app.getHttpServer())
        .get('/v1/audit-logs')
        .expect(401);
    });
  });
});
```

### 이벤트 수집 통합 테스트
```typescript
// event-collector.e2e-spec.ts
describe('EventCollectorService (e2e)', () => {
  let app: INestApplication;
  let pubSubMock: PubSubMock;
  let auditService: AuditService;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [
        AuditModule,
        // Mock dependencies
        MockPubSubModule,
        MockTimeMachineModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    
    pubSubMock = moduleFixture.get<PubSubMock>(PubSubMock);
    auditService = moduleFixture.get<AuditService>(AuditService);
    
    jest.spyOn(auditService, 'createAuditLog');
  });

  afterAll(async () => {
    await app.close();
  });

  describe('event processing', () => {
    it('should process valid event from PubSub', async () => {
      // Arrange
      const event = {
        eventType: 'USER_LOGIN',
        source: 'auth-service',
        actor: { type: 'USER', id: 'user1' },
        action: 'LOGIN',
        correlationId: 'corr-123',
        requestId: 'req-456',
        ipAddress: '192.168.1.1'
      };

      // Act
      await pubSubMock.simulateMessage('audit-events', JSON.stringify(event));
      
      // Wait for async processing
      await new Promise(r => setTimeout(r, 100));

      // Assert
      expect(auditService.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'USER_LOGIN',
          source: 'auth-service',
          metadata: expect.objectContaining({
            correlationId: 'corr-123',
            requestId: 'req-456',
            ipAddress: '192.168.1.1'
          })
        })
      );
    });

    it('should filter out events based on policy', async () => {
      // Arrange
      const event = {
        eventType: 'EXCLUDED_EVENT',
        source: 'test-service',
        actor: { type: 'USER', id: 'user1' },
        action: 'TEST'
      };

      // Configure policy mock to exclude this event
      const policyService = app.get<AuditPolicyService>(AuditPolicyService);
      jest.spyOn(policyService, 'shouldCollectEvent').mockResolvedValue(false);

      // Act
      await pubSubMock.simulateMessage('audit-events', JSON.stringify(event));
      
      // Wait for async processing
      await new Promise(r => setTimeout(r, 100));

      // Assert
      expect(policyService.shouldCollectEvent).toHaveBeenCalledWith('EXCLUDED_EVENT', 'test-service');
      expect(auditService.createAuditLog).not.toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'EXCLUDED_EVENT'
        })
      );
    });
  });
});
```

## 4. 성능 테스트

### 이벤트 수집 성능
```javascript
// k6-event-collection.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 50 },   // Ramp up to 50 users
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 100 },  // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
  },
};

export default function() {
  let url = 'https://test-api.example.com/v1/audit-logs';
  let payload = JSON.stringify({
    eventType: 'PERFORMANCE_TEST',
    source: 'k6-test',
    actor: { type: 'SYSTEM', id: 'perf-test' },
    action: 'TEST',
    details: { testId: `test-${__VU}-${__ITER}` }
  });
  
  let params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.AUTH_TOKEN}`,
    },
  };
  
  let res = http.post(url, payload, params);
  
  check(res, {
    'status is 201': (r) => r.status === 201,
    'response has id': (r) => JSON.parse(r.body).id !== undefined,
  });
  
  sleep(1);
}
```

### 쿼리 성능
```javascript
// k6-query-performance.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 20 },  // Ramp up to 20 users
    { duration: '1m', target: 20 },   // Stay at 20 users
    { duration: '30s', target: 50 },  // Ramp up to 50 users
    { duration: '1m', target: 50 },   // Stay at 50 users
    { duration: '30s', target: 0 },   // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'], // 95% of queries should be below 3s
  },
};

export default function() {
  const queries = [
    { // Simple recent logs query
      startDate: new Date(Date.now() - 3600000).toISOString(), // Last hour
      endDate: new Date().toISOString(),
      limit: 20
    },
    { // Filtered query
      startDate: new Date(Date.now() - 86400000).toISOString(), // Last day
      endDate: new Date().toISOString(),
      eventTypes: 'USER_LOGIN,USER_LOGOUT',
      sources: 'auth-service',
      limit: 50
    },
    { // Complex query
      startDate: new Date(Date.now() - 604800000).toISOString(), // Last week
      endDate: new Date().toISOString(),
      eventTypes: 'DATA_CHANGE',
      actorIds: 'user1,user2,user3',
      targetTypes: 'RESOURCE',
      limit: 100
    }
  ];
  
  // Select random query from the list
  const query = queries[Math.floor(Math.random() * queries.length)];
  let queryString = Object.keys(query)
    .map(key => `${key}=${encodeURIComponent(query[key])}`)
    .join('&');
  
  let url = `https://test-api.example.com/v1/audit-logs?${queryString}`;
  
  let params = {
    headers: {
      'Authorization': `Bearer ${__ENV.AUTH_TOKEN}`,
    },
  };
  
  let res = http.get(url, params);
  
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response is array': (r) => Array.isArray(JSON.parse(r.body)),
  });
  
  sleep(3);
}
```

## 5. 테스트 자동화

### CI/CD 파이프라인
```yaml
# .github/workflows/audit-tests.yml
name: Audit Domain Tests

on:
  push:
    paths:
      - 'libs/audit/**'
      - '.github/workflows/audit-tests.yml'
  pull_request:
    paths:
      - 'libs/audit/**'

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
        
      - name: Lint
        run: npx nx lint audit
        
      - name: Unit tests
        run: npx nx test audit
      
      - name: Integration tests
        run: npx nx test audit-e2e
        
      - name: Build
        run: npx nx build audit
        
  performance:
    runs-on: ubuntu-latest
    needs: test
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup k6
        run: |
          curl -L https://github.com/loadimpact/k6/releases/download/v0.33.0/k6-v0.33.0-linux-amd64.tar.gz | tar xzf -
          sudo cp k6-v0.33.0-linux-amd64/k6 /usr/local/bin
          
      - name: Run performance tests
        run: |
          k6 run tests/performance/k6-event-collection.js
          k6 run tests/performance/k6-query-performance.js
        env:
          K6_CLOUD_TOKEN: ${{ secrets.K6_CLOUD_TOKEN }}
          AUTH_TOKEN: ${{ secrets.PERF_TEST_AUTH_TOKEN }}
```

## 6. 테스트 측정 기준

### 코드 커버리지 목표
| 영역 | 목표 커버리지 |
|-----|-----|
| 도메인 모델 | 95% |
| 서비스 | 90% |
| 리포지토리 | 85% |
| 컨트롤러 | 80% |
| 전체 | 85% |

### 성능 목표
| 지표 | 목표 |
|-----|-----|
| 이벤트 수집 지연 | < 5초 (P95) |
| 이벤트 처리량 | > 10,000 TPS |
| 단순 쿼리 응답 시간 | < 500ms (P95) |
| 복잡 쿼리 응답 시간 | < 3초 (P95) |
| CPU 사용률 | < 70% |
| 메모리 사용률 | < 80% |

### 신뢰성 목표
| 지표 | 목표 |
|-----|-----|
| 업타임 | 99.9% |
| 오류율 | < 0.1% |
| MTTR | < 30분 |
| 실패 쿼리 비율 | < 0.01% |

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|---|-----|-----|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 | 