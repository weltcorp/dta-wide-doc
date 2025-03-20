# 개발 가이드라인

## 1. 프로젝트 구조
```
src/
├── modules/           # 도메인 모듈
│   ├── user/         # 사용자 모듈
│   ├── time-machine/ # TimeMachine 모듈
│   └── access-code/  # AccessCode 모듈
├── shared/           # 공유 모듈
│   ├── utils/       # 유틸리티 함수
│   ├── config/      # 설정
│   └── types/       # 공유 타입 정의
└── core/            # 코어 모듈
    ├── database/    # 데이터베이스 연결
    ├── cache/       # 캐시 관리
    └── email/       # 이메일 서비스
```

## 2. 모듈 구조
각 모듈은 다음 구조를 따릅니다:
```
module/
├── controllers/     # API 엔드포인트
├── services/       # 비즈니스 로직
├── repositories/   # 데이터 접근
├── entities/       # 데이터베이스 엔티티
├── dtos/          # 데이터 전송 객체
├── interfaces/    # 타입 정의
└── tests/         # 테스트 파일
```

## 3. 코드 스타일
- TypeScript strict 모드 사용
- ESLint 규칙 준수
- async/await 사용
- 의미 있는 변수명 사용
- 영어로 코드 작성
- JSDoc 주석 사용

## 4. 모듈 개발 가이드라인

### 4.1 모듈 정의
```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([Entity]),
    SharedModule,
  ],
  controllers: [Controller],
  providers: [Service],
  exports: [Service],
})
export class FeatureModule {}
```

### 4.2 컨트롤러
```typescript
@Controller('v1/resource')
export class ResourceController {
  constructor(private readonly service: ResourceService) {}

  @Get()
  async findAll(): Promise<ResourceDto[]> {
    return this.service.findAll();
  }
}
```

### 4.3 서비스
```typescript
@Injectable()
export class ResourceService {
  constructor(
    @InjectRepository(Resource)
    private readonly repository: Repository<Resource>,
  ) {}

  async findAll(): Promise<Resource[]> {
    return this.repository.find();
  }
}
```

## 5. 에러 처리
- 모듈별 에러 코드 정의
- ErrorResponseDto 사용
- 글로벌 예외 필터 활용
- 적절한 HTTP 상태 코드 사용

## 6. 테스트
- 단위 테스트 필수
- 통합 테스트 권장
- 테스트 커버리지 80% 이상
- 테스트 데이터 분리

## 7. API 개발
- RESTful 원칙 준수
- 버전 관리 (/v1)
- DTO 검증
- Swagger 문서화

## 8. 데이터베이스
- TypeORM 사용
- 마이그레이션 관리
- 인덱스 최적화
- 트랜잭션 관리

## 9. 캐시 전략
- Redis 활용
- 캐시 키 네이밍 규칙
- TTL 설정
- 캐시 무효화 전략

## 10. 보안
- 인증/인가 처리
- 입력값 검증
- GDPR 준수
- 보안 헤더 설정

## 11. 모니터링
- 로깅 전략
- 메트릭스 수집
- 알림 설정
- 성능 모니터링

## 12. 배포
- Docker 컨테이너화
- 환경 설정 분리
- 무중단 배포
- 롤백 전략

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |