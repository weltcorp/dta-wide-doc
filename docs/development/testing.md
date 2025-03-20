# 테스트 가이드라인

## 1. 테스트 종류

### 1.1 단위 테스트
- 모듈의 개별 컴포넌트 테스트
- Jest 프레임워크 사용
- 모든 public 메서드 테스트 필수
- 의존성 모킹 필수

### 1.2 통합 테스트
- 모듈 간 상호작용 테스트
- 실제 데이터베이스 사용
- API 엔드포인트 테스트
- E2E 테스트 포함

## 2. 테스트 구조

### 2.1 파일 구조
```
module/
└── tests/
    ├── unit/
    │   ├── controllers/
    │   ├── services/
    │   └── repositories/
    └── integration/
        ├── api/
        └── database/
```

### 2.2 네이밍 규칙
- 단위 테스트: `*.spec.ts`
- 통합 테스트: `*.e2e-spec.ts`
- 테스트 데이터: `*.fixture.ts`

## 3. 테스트 작성 가이드라인

### 3.1 단위 테스트 예시
```typescript
describe('UserService', () => {
  let service: UserService;
  let repository: MockType<Repository<User>>;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(User),
          useFactory: repositoryMockFactory,
        },
      ],
    }).compile();

    service = module.get(UserService);
    repository = module.get(getRepositoryToken(User));
  });

  it('should find a user by id', async () => {
    const user = { id: 1, name: 'Test User' };
    repository.findOne.mockReturnValue(user);

    expect(await service.findOne(1)).toEqual(user);
    expect(repository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
  });
});
```

### 3.2 통합 테스트 예시
```typescript
describe('User API (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/v1/users (GET)', () => {
    return request(app.getHttpServer())
      .get('/v1/users')
      .expect(200)
      .expect('Content-Type', /json/);
  });

  afterAll(async () => {
    await app.close();
  });
});
```

## 4. 테스트 데이터 관리

### 4.1 테스트 픽스처
```typescript
export const userFixture = {
  validUser: {
    id: 1,
    email: 'test@example.com',
    name: 'Test User',
  },
  invalidUser: {
    id: 2,
    email: 'invalid-email',
    name: '',
  },
};
```

### 4.2 데이터베이스 시딩
- 테스트 데이터베이스 사용
- 매 테스트 전 데이터 초기화
- 트랜잭션 롤백 활용

## 5. 모킹 가이드라인

### 5.1 모킹 대상
- 외부 API 호출
- 데이터베이스 연산
- 이메일 서비스
- 캐시 서비스

### 5.2 모킹 예시
```typescript
const mockEmailService = {
  sendEmail: jest.fn().mockResolvedValue(true),
};

const mockCacheService = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
};
```

## 6. 테스트 커버리지

### 6.1 커버리지 요구사항
- 전체 코드 커버리지: 80% 이상
- 모듈별 커버리지: 85% 이상
- 핵심 비즈니스 로직: 90% 이상

### 6.2 커버리지 측정
```bash
npm run test:cov
```

## 7. 테스트 자동화

### 7.1 CI/CD 파이프라인
- 커밋 시 단위 테스트 실행
- PR 시 전체 테스트 실행
- 배포 전 E2E 테스트 실행

### 7.2 테스트 환경
- 개발 환경
- 스테이징 환경
- 프로덕션 환경

## 8. 성능 테스트

### 8.1 부하 테스트
- 동시 사용자 처리
- 응답 시간 측정
- 리소스 사용량 모니터링

### 8.2 스트레스 테스트
- 최대 부하 테스트
- 장애 복구 테스트
- 메모리 누수 테스트

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |