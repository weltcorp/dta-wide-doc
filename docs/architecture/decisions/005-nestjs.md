# ADR 5: NestJS 프레임워크 사용

## 상태
승인됨 (2025-03-16)

## 컨텍스트
- TypeScript 기반의 서버 프레임워크 필요
- 모듈형 아키텍처 지원 필요
- 엔터프라이즈급 애플리케이션 개발 필요
- 강력한 DI(Dependency Injection) 시스템 필요
- 확장 가능한 구조 필요
- 표준화된 개발 패턴 적용 필요

## 결정
NestJS를 주요 백엔드 프레임워크로 채택

### 주요 기능 활용
1. 모듈 시스템
   - 기능별 모듈 분리
   - 모듈 간 의존성 관리
   - 공유 모듈 활용

2. 의존성 주입
   - 생성자 기반 DI
   - 프로바이더 시스템
   - 스코프 관리

3. 미들웨어 및 인터셉터
   - 글로벌 예외 처리
   - 요청/응답 변환
   - 로깅 및 모니터링

4. 데코레이터 패턴
   - 라우트 정의
   - 파라미터 변환
   - 검증 로직

### 아키텍처 구성
```typescript
// 모듈 예시
@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    SharedModule,
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}

// 컨트롤러 예시
@Controller('v1/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  async findAll(): Promise<User[]> {
    return this.userService.findAll();
  }
}

// 서비스 예시
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }
}
```

## 결과
### 긍정적
- 모듈형 아키텍처 기본 지원
- TypeScript 최적화
- 강력한 DI 시스템
- 풍부한 생태계
- 표준화된 구조
- 확장성 우수
- 테스트 용이성
- OpenAPI/Swagger 통합

### 부정적
- 학습 곡선 존재
- 보일러플레이트 코드 증가
- 메모리 사용량 증가
- 초기 설정 복잡도

## 대안
1. Express.js + TypeScript
2. Koa.js + TypeScript
3. Fastify
4. Hapi.js

## 관련 결정
- ADR 2: 모듈형 모놀리스 아키텍처 채택
- ADR 3: TypeScript 사용
- ADR 6: TypeORM 사용

## 구현 가이드라인
1. 모듈 구조
   - 도메인별 모듈 분리
   - 공유 모듈 활용
   - 순환 의존성 방지

2. 예외 처리
   - 글로벌 예외 필터 사용
   - 도메인별 예외 클래스 정의
   - HTTP 예외 표준화

3. 설정 관리
   - ConfigModule 활용
   - 환경별 설정 분리
   - 설정 검증

4. 테스트
   - Jest 통합 활용
   - E2E 테스트 지원
   - 테스트 모듈 구성

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |