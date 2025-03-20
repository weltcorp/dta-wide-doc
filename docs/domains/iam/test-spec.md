# IAM 도메인 테스트 명세서

## 1. 테스트 범위

### 1.1 단위 테스트
1. **서비스 레이어**
   - PermissionService
   - RoleService
   - PolicyService
   - PermissionEvaluationService
   - CacheService

2. **컨트롤러 레이어**
   - PermissionController
   - RoleController
   - PolicyController

3. **가드/인터셉터**
   - PermissionGuard
   - RoleGuard
   - PolicyEvaluationInterceptor

### 1.2 통합 테스트
1. **API 엔드포인트**
   - Permission API
   - Role API
   - Policy API

2. **데이터베이스 연동**
   - TypeORM Repository
   - 트랜잭션 처리
   - 인덱스 성능

3. **캐시 연동**
   - Redis 캐시
   - 캐시 무효화
   - 캐시 정합성

### 1.3 성능 테스트
1. **부하 테스트**
   - API 엔드포인트 부하
   - 데이터베이스 부하
   - 캐시 부하

2. **캐시 성능**
   - 캐시 히트율
   - 캐시 응답시간
   - 캐시 메모리 사용량

## 2. 테스트 시나리오

### 2.1 Permission 테스트

#### 단위 테스트
```typescript
describe('PermissionService', () => {
  let service: PermissionService;
  let repository: Repository<Permission>;
  let eventEmitter: EventEmitter2;
  let cacheService: CacheService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PermissionService,
        {
          provide: getRepositoryToken(Permission),
          useClass: MockRepository,
        },
        {
          provide: EventEmitter2,
          useClass: MockEventEmitter,
        },
        {
          provide: CacheService,
          useClass: MockCacheService,
        },
      ],
    }).compile();

    service = module.get<PermissionService>(PermissionService);
    repository = module.get<Repository<Permission>>(getRepositoryToken(Permission));
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
    cacheService = module.get<CacheService>(CacheService);
  });

  it('should create a permission', async () => {
    const createDto = {
      name: 'test.permission',
      description: 'Test Permission',
      domain: 'test',
      action: 'read',
      resource: 'document',
    };

    const permission = new Permission();
    Object.assign(permission, createDto);

    jest.spyOn(repository, 'create').mockReturnValue(permission);
    jest.spyOn(repository, 'save').mockResolvedValue(permission);
    jest.spyOn(eventEmitter, 'emit');
    jest.spyOn(cacheService, 'invalidatePermissionCache');

    const result = await service.create(createDto);

    expect(result).toEqual(permission);
    expect(repository.create).toHaveBeenCalledWith(createDto);
    expect(repository.save).toHaveBeenCalledWith(permission);
    expect(eventEmitter.emit).toHaveBeenCalledWith('permission.created', permission);
    expect(cacheService.invalidatePermissionCache).toHaveBeenCalled();
  });
});
```

#### 통합 테스트
```typescript
describe('Permission (e2e)', () => {
  let app: INestApplication;
  let repository: Repository<Permission>;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    repository = moduleFixture.get<Repository<Permission>>(
      getRepositoryToken(Permission),
    );
  });

  it('/permissions (POST)', () => {
    const createDto = {
      name: 'test.permission',
      description: 'Test Permission',
      domain: 'test',
      action: 'read',
      resource: 'document',
    };

    return request(app.getHttpServer())
      .post('/permissions')
      .send(createDto)
      .expect(201)
      .expect(res => {
        expect(res.body).toMatchObject(createDto);
        expect(res.body.id).toBeDefined();
      });
  });
});
```

### 2.2 Role 테스트

#### 단위 테스트
```typescript
describe('RoleService', () => {
  let service: RoleService;
  let repository: Repository<Role>;
  let eventEmitter: EventEmitter2;
  let cacheService: CacheService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoleService,
        {
          provide: getRepositoryToken(Role),
          useClass: MockRepository,
        },
        {
          provide: EventEmitter2,
          useClass: MockEventEmitter,
        },
        {
          provide: CacheService,
          useClass: MockCacheService,
        },
      ],
    }).compile();

    service = module.get<RoleService>(RoleService);
    repository = module.get<Repository<Role>>(getRepositoryToken(Role));
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
    cacheService = module.get<CacheService>(CacheService);
  });

  it('should assign permissions to role', async () => {
    const role = new Role();
    role.id = 'test-role-id';
    role.name = 'test-role';

    const permissions = [
      { id: 'perm1', name: 'permission1' },
      { id: 'perm2', name: 'permission2' },
    ];

    jest.spyOn(repository, 'findOne').mockResolvedValue(role);
    jest.spyOn(repository, 'save').mockResolvedValue({ ...role, permissions });
    jest.spyOn(eventEmitter, 'emit');
    jest.spyOn(cacheService, 'invalidateRoleCache');

    const result = await service.assignPermissions(role.id, permissions.map(p => p.id));

    expect(result.permissions).toEqual(permissions);
    expect(eventEmitter.emit).toHaveBeenCalledWith('role.permissions.updated', result);
    expect(cacheService.invalidateRoleCache).toHaveBeenCalled();
  });
});
```

#### 통합 테스트
```typescript
describe('Role (e2e)', () => {
  let app: INestApplication;
  let repository: Repository<Role>;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    repository = moduleFixture.get<Repository<Role>>(
      getRepositoryToken(Role),
    );
  });

  it('/roles/:id/permissions (POST)', async () => {
    const role = await repository.save({
      name: 'test-role',
      description: 'Test Role',
    });

    const permissionIds = ['perm1', 'perm2'];

    return request(app.getHttpServer())
      .post(`/roles/${role.id}/permissions`)
      .send({ permissionIds })
      .expect(200)
      .expect(res => {
        expect(res.body.permissions).toHaveLength(2);
        expect(res.body.permissions.map(p => p.id)).toEqual(expect.arrayContaining(permissionIds));
      });
  });
});
```

### 2.3 Policy 테스트

#### 단위 테스트
```typescript
describe('PolicyService', () => {
  let service: PolicyService;
  let repository: Repository<Policy>;
  let eventEmitter: EventEmitter2;
  let cacheService: CacheService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PolicyService,
        {
          provide: getRepositoryToken(Policy),
          useClass: MockRepository,
        },
        {
          provide: EventEmitter2,
          useClass: MockEventEmitter,
        },
        {
          provide: CacheService,
          useClass: MockCacheService,
        },
      ],
    }).compile();

    service = module.get<PolicyService>(PolicyService);
    repository = module.get<Repository<Policy>>(getRepositoryToken(Policy));
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
    cacheService = module.get<CacheService>(CacheService);
  });

  it('should evaluate policy', async () => {
    const policy = new Policy();
    policy.id = 'test-policy-id';
    policy.name = 'test-policy';
    policy.effect = PolicyEffect.ALLOW;
    policy.conditions = [
      {
        type: 'StringEquals',
        field: 'resource.type',
        value: 'document',
      },
    ];

    const context = {
      principal: { id: 'user1', type: 'user' },
      resource: { type: 'document', id: 'doc1' },
      action: 'read',
    };

    jest.spyOn(repository, 'find').mockResolvedValue([policy]);
    jest.spyOn(cacheService, 'get').mockResolvedValue(null);
    jest.spyOn(cacheService, 'set');

    const result = await service.evaluate(context);

    expect(result.effect).toBe(PolicyEffect.ALLOW);
    expect(cacheService.set).toHaveBeenCalled();
  });
});
```

#### 통합 테스트
```typescript
describe('Policy (e2e)', () => {
  let app: INestApplication;
  let repository: Repository<Policy>;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    repository = moduleFixture.get<Repository<Policy>>(
      getRepositoryToken(Policy),
    );
  });

  it('/policies/evaluate (POST)', async () => {
    await repository.save({
      name: 'test-policy',
      effect: PolicyEffect.ALLOW,
      conditions: [
        {
          type: 'StringEquals',
          field: 'resource.type',
          value: 'document',
        },
      ],
      priority: 1,
    });

    const context = {
      principal: { id: 'user1', type: 'user' },
      resource: { type: 'document', id: 'doc1' },
      action: 'read',
    };

    return request(app.getHttpServer())
      .post('/policies/evaluate')
      .send(context)
      .expect(200)
      .expect(res => {
        expect(res.body.effect).toBe('allow');
      });
  });
});
```

## 3. 성능 테스트 시나리오

### 3.1 API 성능 테스트
```typescript
describe('IAM API Performance', () => {
  it('should handle 1000 permission validations per second', async () => {
    const start = Date.now();
    const requests = [];

    for (let i = 0; i < 1000; i++) {
      requests.push(
        request(app.getHttpServer())
          .post('/permissions/validate')
          .send({
            principal: { id: 'user1', type: 'user' },
            permission: 'document:read',
          }),
      );
    }

    await Promise.all(requests);
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(1000);
  });

  it('should handle 100 role assignments per second', async () => {
    const start = Date.now();
    const requests = [];

    for (let i = 0; i < 100; i++) {
      requests.push(
        request(app.getHttpServer())
          .post('/roles/role1/permissions')
          .send({
            permissionIds: ['perm1', 'perm2'],
          }),
      );
    }

    await Promise.all(requests);
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(1000);
  });
});
```

### 3.2 캐시 성능 테스트
```typescript
describe('Cache Performance', () => {
  it('should achieve 95% cache hit rate', async () => {
    const totalRequests = 1000;
    let cacheHits = 0;

    for (let i = 0; i < totalRequests; i++) {
      const result = await cacheService.get('test-key');
      if (result !== null) {
        cacheHits++;
      }
    }

    const hitRate = (cacheHits / totalRequests) * 100;
    expect(hitRate).toBeGreaterThan(95);
  });

  it('should respond within 10ms for cached results', async () => {
    await cacheService.set('test-key', 'test-value');

    const start = Date.now();
    await cacheService.get('test-key');
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(10);
  });
});
```

## 4. 테스트 환경 설정

### 4.1 테스트 데이터베이스
```typescript
const testConfig = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'test',
  password: 'test',
  database: 'iam_test',
  entities: [Permission, Role, Policy],
  synchronize: true,
};
```

### 4.2 테스트 Redis
```typescript
const testRedisConfig = {
  host: 'localhost',
  port: 6379,
  db: 1,
};
```

### 4.3 테스트 데이터 준비
```typescript
async function setupTestData() {
  // 기본 권한 생성
  const permissions = await Promise.all([
    permissionRepository.save({
      name: 'document:read',
      domain: 'document',
      action: 'read',
      resource: '*',
    }),
    permissionRepository.save({
      name: 'document:write',
      domain: 'document',
      action: 'write',
      resource: '*',
    }),
  ]);

  // 기본 역할 생성
  const role = await roleRepository.save({
    name: 'document-reader',
    permissions: [permissions[0]],
  });

  // 기본 정책 생성
  await policyRepository.save({
    name: 'allow-document-read',
    effect: PolicyEffect.ALLOW,
    conditions: [
      {
        type: 'StringEquals',
        field: 'resource.type',
        value: 'document',
      },
    ],
    priority: 1,
  });
}
```

## 5. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2024-03-21 | bok@weltcorp.com | 최초 작성 | 