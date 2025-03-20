# Access Code 도메인 구현 가이드

## 1. 도메인 구조

### 1.1 디렉토리 구조
```
src/domains/access-code/
├── access-code.module.ts           # 모듈 정의
├── constants/                      # 상수 정의
│   ├── cache-keys.constant.ts
│   ├── injection-tokens.constant.ts
│   └── privacy-config.constant.ts  # 개인정보 보호 설정
├── domain/                         # 도메인 계층
│   ├── entity/                    # 엔티티
│   │   ├── access-code.entity.ts
│   │   ├── access-code.factory.ts
│   │   ├── privacy-consent.entity.ts  # 개인정보 동의 엔티티
│   │   └── types/
│   ├── value-object/             # 값 객체
│   │   ├── code-status.vo.ts
│   │   ├── time-machine-options.vo.ts
│   │   ├── treatment-period.vo.ts
│   │   ├── personal-data.vo.ts    # 개인정보 값 객체
│   │   └── data-mask.vo.ts        # 데이터 마스킹 값 객체
│   ├── event/                    # 도메인 이벤트
│   │   ├── access-code-created.event.ts
│   │   ├── access-code-used.event.ts
│   │   ├── access-code-expired.event.ts
│   │   ├── privacy-consent-changed.event.ts  # 동의 변경 이벤트
│   │   └── handlers/
│   └── error/                    # 도메인 예외
│       ├── access-code.error.ts
│       ├── privacy.error.ts       # 개인정보 관련 에러
│       └── error-codes.enum.ts
├── application/                    # 응용 서비스 계층
│   ├── command/                  # 명령 처리
│   │   ├── create-access-code.handler.ts
│   │   ├── use-access-code.handler.ts
│   │   ├── update-privacy-consent.handler.ts  # 동의 관리
│   │   └── delete-personal-data.handler.ts    # 개인정보 삭제
│   ├── query/                    # 조회 처리
│   │   ├── find-access-code.handler.ts
│   │   └── get-personal-data.handler.ts      # 개인정보 조회
│   └── event/                    # 이벤트 처리
│       └── handlers/
├── interface/                      # 인터페이스 계층
│   ├── controller/               # REST API
│   │   ├── access-code.controller.ts
│   │   ├── admin.controller.ts    # 관리자용 API
│   │   └── privacy.controller.ts  # 개인정보 관련 API
│   ├── validator/                # 유효성 검증
│   │   ├── access-code.validator.ts
│   │   └── privacy-consent.validator.ts  # 동의 검증
│   └── middleware/               # 미들웨어
│       ├── access-code.middleware.ts
│       └── privacy.middleware.ts  # 개인정보 보호 미들웨어
├── infrastructure/                 # 인프라스트럭처 계층
│   ├── persistence/              # 영속성
│   │   ├── repository/
│   │   │   ├── access-code.repository.ts
│   │   │   └── privacy-consent.repository.ts
│   │   └── cache/
│   │       └── access-code.cache.ts
│   ├── security/                 # 보안
│   │   ├── encryption/
│   │   │   └── personal-data.encryption.ts
│   │   └── masking/
│   │       └── data-masking.service.ts
│   ├── messaging/                # 메시징
│   │   └── email/
│   │       └── email.service.ts
│   └── external/                 # 외부 서비스
│       └── time-machine/
│           └── time-machine.service.ts
└── dto/                           # DTO 정의
    ├── request/
    │   ├── create-access-code.dto.ts
    │   ├── validate-access-code.dto.ts
    │   └── privacy-consent.dto.ts
    └── response/
        ├── access-code.response.dto.ts
        └── personal-data.response.dto.ts
```

### 1.2 계층별 책임

#### 도메인 계층 (domain/)
- 비즈니스 핵심 로직 포함
- 엔티티, 값 객체, 도메인 이벤트 정의
- 외부 의존성 없는 순수한 도메인 로직

#### 응용 서비스 계층 (application/)
- 유스케이스 구현
- 트랜잭션 관리
- 도메인 객체 조율
- CQRS 패턴 적용 (Command/Query 분리)

#### 인터페이스 계층 (interface/)
- HTTP 요청/응답 처리
- 입력 유효성 검증
- 권한 검사
- API 버전 관리

#### 인프라스트럭처 계층 (infrastructure/)
- 데이터베이스 연동
- 캐시 처리
- 외부 서비스 통합
- 메시징 처리

### 1.3 모듈 설정
```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([AccessCode]),
    CacheModule.register(),
    EventEmitterModule.forRoot()
  ],
  controllers: [
    AccessCodeController,
    AdminController
  ],
  providers: [
    // 응용 서비스
    CreateAccessCodeHandler,
    UseAccessCodeHandler,
    FindAccessCodeHandler,
    
    // 인프라스트럭처 서비스
    {
      provide: 'IAccessCodeRepository',
      useClass: AccessCodeRepository
    },
    AccessCodeCache,
    EmailService,
    TimeMachineService,
    
    // 기타 프로바이더
    AccessCodeErrorFilter,
    AccessCodeValidator
  ],
  exports: [
    'IAccessCodeRepository',
    AccessCodeCache,
    TimeMachineService
  ]
})
export class AccessCodeModule {}
```

## 2. 엔티티 정의

### 2.1 AccessCode 엔티티
```typescript
@Entity()
export class AccessCode extends AggregateRoot {
  @PrimaryGeneratedColumn('uuid')
  id: string;                    // 고유 식별자 (UUID)

  @Column({ length: 16 })
  @Index({ unique: true })       // 성능 최적화를 위한 인덱스
  code: string;                  // 16자리 인증 코드

  @Column({ type: 'enum' })
  type: AccessCodeType;          // 코드 유형

  @Column()
  @Index()                       // 조회 성능 향상
  creatorUserId: string;         // 발급자 ID

  @Column()
  accountId: string;             // 계정 ID

  @Column({ nullable: true })
  groupId?: string;              // 그룹 ID

  @Column({ nullable: true })
  siteId?: string;               // 사이트 ID

  @Column({ nullable: true })
  departmentId?: string;         // 부서 ID

  @Column(() => TreatmentPeriod) // 값 객체로 분리
  treatmentPeriod: TreatmentPeriod;

  @Column({ type: 'enum', nullable: true })
  gender?: Gender;               // 성별

  @Column()
  @Index()                       // 만료 처리를 위한 인덱스
  expiresAt: Date;              // 만료 시간

  @Column({ nullable: true })
  @Index()                       // 이메일 검색을 위한 인덱스
  email?: string;                // 이메일

  @Column({ nullable: true })
  emailRegisteredAt?: Date;      // 이메일 등록 시간

  @Column({ nullable: true })
  @Index()                       // 사용자 조회를 위한 인덱스
  userId?: string;               // 사용자 ID

  @Column({ nullable: true })
  userCycleId?: string;          // 사용자 주기 ID

  @Column({ nullable: true })
  userCreatedAt?: Date;          // 사용자 생성 시간

  @CreateDateColumn()
  createdAt: Date;              // 생성 시간

  @UpdateDateColumn()
  updatedAt: Date;              // 수정 시간

  @Column({ nullable: true })
  registrationChannelId?: string; // 등록 채널 ID

  @Column({ nullable: true })
  randomizationCode?: string;     // 무작위 배정 코드

  @Column({ type: 'enum', nullable: true })
  deliveryMethod?: DeliveryMethod; // 전달 방법

  @Column({ nullable: true })
  sentTo?: string;               // 전송 대상

  @Column({ type: 'enum' })
  @Index()                       // 상태 기반 조회를 위한 인덱스
  status: CodeStatus;            // 코드 상태

  // 비즈니스 메서드
  isExpired(timeMachine: TimeMachineService): boolean {
    const currentTime = timeMachine.getCurrentTime();
    return currentTime > this.expiresAt;
  }

  canBeUsed(timeMachine: TimeMachineService): boolean {
    return !this.isExpired(timeMachine) && this.status === CodeStatus.UNUSED;
  }

  use(userId: string, timeMachine: TimeMachineService): void {
    if (!this.canBeUsed(timeMachine)) {
      throw new AccessCodeError(ErrorCode.CODE_CANNOT_BE_USED);
    }
    this.userId = userId;
    this.status = CodeStatus.USED;
    this.userCreatedAt = timeMachine.getCurrentTime();

    // 도메인 이벤트 발행
    this.apply(new AccessCodeUsedEvent(this, userId, timeMachine.getCurrentTime()));
  }

  markAsExpired(timeMachine: TimeMachineService): void {
    this.status = CodeStatus.EXPIRED;
    this.apply(new AccessCodeExpiredEvent(this, timeMachine.getCurrentTime()));
  }

  // GDPR 관련 메서드
  anonymize(): void {
    this.email = null;
    this.sentTo = null;
    // 기타 개인정보 필드 익명화
  }
}
```

### 2.2 열거형 정의
```typescript
export enum AccessCodeType {
  TREATMENT = 'TREATMENT',
  TRIAL = 'CLINICAL_TRIAL',
  DEMO = 'DEMO'
}

export enum Gender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER'
}

export enum DeliveryMethod {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  DIRECT = 'DIRECT'
}

export enum CodeStatus {
  UNUSED = 'UNUSED',
  USED = 'USED',
  EXPIRED = 'EXPIRED'
}
```

### 2.3 값 객체 정의
```typescript
@ValueObject()
export class TreatmentPeriod {
  @Column()
  days: number;

  @Column()
  startDate: Date;

  constructor(days: number, startDate: Date) {
    if (days <= 0) {
      throw new AccessCodeError(ErrorCode.INVALID_TREATMENT_PERIOD);
    }
    this.days = days;
    this.startDate = startDate;
  }

  getEndDate(timeMachine: TimeMachineService): Date {
    return timeMachine.addDays(this.startDate, this.days);
  }
}

@ValueObject()
export class TimeMachineOptions {
  constructor(
    public readonly useTimeMachine: boolean,
    public readonly testTime?: Date
  ) {
    if (useTimeMachine && !testTime) {
      throw new AccessCodeError(ErrorCode.INVALID_TIME_MACHINE_OPTIONS);
    }
  }

  static createDefault(): TimeMachineOptions {
    return new TimeMachineOptions(false);
  }

  static createTest(testTime: Date): TimeMachineOptions {
    return new TimeMachineOptions(true, testTime);
  }
}
```

## 3. 개인정보 보호 구현

### 3.1 개인정보 처리 정책
```typescript
// privacy-config.constant.ts
export const PRIVACY_CONFIG = {
  retention: {
    accessCode: '30d',    // 액세스 코드 보관 기간
    personalData: '30d',  // 개인정보 보관 기간
    consentHistory: '5y'  // 동의 이력 보관 기간
  },
  encryption: {
    algorithm: 'AES-256-GCM',
    keyRotationPeriod: '30d'
  },
  masking: {
    email: {
      pattern: /(^[^@]{3})[^@]*(@.*$)/,
      replacement: '$1***$2'
    },
    phone: {
      pattern: /(\d{3})-?(\d{3,4})-?(\d{4})/,
      replacement: '$1-****-$3'
    }
  }
};
```

### 3.2 개인정보 값 객체
```typescript
// personal-data.vo.ts
@ValueObject()
export class PersonalData {
  constructor(
    private readonly value: string,
    private readonly type: PersonalDataType
  ) {
    this.validate();
    this.encrypt();
  }

  private readonly encryptionService: PersonalDataEncryption;

  private validate(): void {
    switch (this.type) {
      case PersonalDataType.EMAIL:
        if (!isValidEmail(this.value)) {
          throw new InvalidPersonalDataError('Invalid email format');
        }
        break;
      // 다른 타입에 대한 검증
    }
  }

  private encrypt(): void {
    this.encryptedValue = this.encryptionService.encrypt(this.value);
  }

  public getValue(): string {
    return this.encryptionService.decrypt(this.encryptedValue);
  }

  public getMaskedValue(): string {
    return DataMaskingService.mask(this.value, this.type);
  }
}
```

### 3.3 개인정보 동의 엔티티
```typescript
// privacy-consent.entity.ts
@Entity()
export class PrivacyConsent extends AggregateRoot {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column('jsonb')
  consents: {
    dataProcessing: boolean;      // 필수 동의
    emailMarketing: boolean;      // 선택 동의
    thirdPartySharing: boolean;   // 선택 동의
  };

  @Column('jsonb')
  consentHistory: {
    timestamp: Date;
    action: 'GRANT' | 'REVOKE';
    consentType: string;
    value: boolean;
  }[];

  @Column()
  validUntil: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  updateConsent(
    type: keyof typeof this.consents,
    value: boolean,
    timeMachine: TimeMachineService
  ): void {
    // 필수 동의 철회 방지
    if (type === 'dataProcessing' && !value) {
      throw new PrivacyError(ErrorCode.REQUIRED_CONSENT_REVOCATION);
    }

    this.consents[type] = value;
    this.consentHistory.push({
      timestamp: timeMachine.getCurrentTime(),
      action: value ? 'GRANT' : 'REVOKE',
      consentType: type,
      value
    });

    // 이벤트 발행
    this.apply(new PrivacyConsentChangedEvent(this));
  }

  hasRequiredConsents(): boolean {
    return this.consents.dataProcessing === true;
  }

  canProcessMarketingEmails(): boolean {
    return this.consents.emailMarketing === true;
  }
}
```

### 3.4 개인정보 보호 컨트롤러
```typescript
// privacy.controller.ts
@Controller('v1/access-codes')
export class PrivacyController {
  constructor(
    private readonly privacyService: PrivacyService,
    private readonly accessCodeService: AccessCodeService
  ) {}

  @Get('personal-data/:userId')
  @UseGuards(AuthGuard, PrivacyGuard)
  async getPersonalData(
    @Param('userId') userId: string
  ): Promise<PersonalDataResponseDto> {
    const data = await this.privacyService.getPersonalData(userId);
    return {
      status: 200,
      data: {
        personalData: data.getMaskedData(),
        consents: data.getConsents()
      }
    };
  }

  @Delete('personal-data/:userId')
  @UseGuards(AuthGuard, PrivacyGuard)
  async deletePersonalData(
    @Param('userId') userId: string
  ): Promise<void> {
    await this.privacyService.deletePersonalData(userId);
  }

  @Put('consent/:userId')
  @UseGuards(AuthGuard)
  async updateConsent(
    @Param('userId') userId: string,
    @Body() dto: UpdateConsentDto
  ): Promise<ConsentResponseDto> {
    const result = await this.privacyService.updateConsent(userId, dto);
    return {
      status: 200,
      data: {
        consents: result.consents,
        updatedAt: result.updatedAt
      }
    };
  }

  @Get('personal-data/:userId/logs')
  @UseGuards(AuthGuard, PrivacyGuard)
  async getProcessingLogs(
    @Param('userId') userId: string
  ): Promise<ProcessingLogsResponseDto> {
    const logs = await this.privacyService.getProcessingLogs(userId);
    return {
      status: 200,
      data: {
        logs
      }
    };
  }
}
```

### 3.5 개인정보 보호 미들웨어
```typescript
// privacy.middleware.ts
@Injectable()
export class PrivacyMiddleware implements NestMiddleware {
  constructor(
    private readonly privacyService: PrivacyService,
    private readonly logger: Logger
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    // 개인정보 처리 로그 기록
    await this.privacyService.logAccess({
      userId: req.params.userId,
      action: req.method,
      path: req.path,
      timestamp: new Date(),
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // 개인정보 처리 동의 확인
    if (this.requiresConsent(req)) {
      const hasConsent = await this.privacyService.checkConsent(
        req.params.userId,
        this.getRequiredConsentType(req)
      );

      if (!hasConsent) {
        throw new PrivacyError(ErrorCode.CONSENT_REQUIRED);
      }
    }

    next();
  }

  private requiresConsent(req: Request): boolean {
    // 동의가 필요한 엔드포인트 확인 로직
    return true;
  }

  private getRequiredConsentType(req: Request): string {
    // 필요한 동의 유형 결정 로직
    return 'dataProcessing';
  }
}
```

### 3.6 개인정보 암호화 서비스
```typescript
// personal-data.encryption.ts
@Injectable()
export class PersonalDataEncryption {
  constructor(
    @Inject('ENCRYPTION_KEY')
    private readonly encryptionKey: string,
    private readonly configService: ConfigService
  ) {}

  encrypt(data: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );

    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, encrypted, tag]).toString('base64');
  }

  decrypt(encryptedData: string): string {
    const buffer = Buffer.from(encryptedData, 'base64');
    const iv = buffer.slice(0, 12);
    const tag = buffer.slice(-16);
    const encrypted = buffer.slice(12, -16);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );

    decipher.setAuthTag(tag);

    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString('utf8');
  }
}
```

### 3.7 데이터 마스킹 서비스
```typescript
// data-masking.service.ts
@Injectable()
export class DataMaskingService {
  private static readonly MASKING_PATTERNS = {
    email: /(^[^@]{3})[^@]*(@.*$)/,
    phone: /(\d{3})-?(\d{3,4})-?(\d{4})/,
    name: /^(.)(.+)(.)$/u
  };

  private static readonly MASKING_REPLACEMENTS = {
    email: '$1***$2',
    phone: '$1-****-$3',
    name: '$1*$3'
  };

  static mask(value: string, type: string): string {
    const pattern = this.MASKING_PATTERNS[type];
    const replacement = this.MASKING_REPLACEMENTS[type];

    if (!pattern || !replacement) {
      throw new Error(`Unsupported masking type: ${type}`);
    }

    return value.replace(pattern, replacement);
  }
}
```

## 4. 모니터링 및 감사

### 4.1 개인정보 처리 로그
```typescript
// privacy-log.entity.ts
@Entity()
export class PrivacyLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  action: string;

  @Column()
  category: string;

  @Column()
  detail: string;

  @Column()
  timestamp: Date;

  @Column()
  ip: string;

  @Column()
  userAgent: string;

  @Column({ nullable: true })
  processor: string;
}
```

### 4.2 모니터링 메트릭
```typescript
// privacy-metrics.service.ts
@Injectable()
export class PrivacyMetricsService {
  constructor(
    private readonly metricsRegistry: MetricsRegistry
  ) {
    this.initializeMetrics();
  }

  private initializeMetrics(): void {
    // 개인정보 접근 카운터
    this.personalDataAccessCounter = new Counter({
      name: 'personal_data_access_total',
      help: 'Total number of personal data access',
      labelNames: ['action', 'status']
    });

    // 동의 변경 카운터
    this.consentChangeCounter = new Counter({
      name: 'consent_changes_total',
      help: 'Total number of consent changes',
      labelNames: ['type', 'action']
    });

    // 데이터 삭제 요청 카운터
    this.dataDeletionCounter = new Counter({
      name: 'data_deletion_requests_total',
      help: 'Total number of data deletion requests',
      labelNames: ['status']
    });

    // 개인정보 처리 시간 히스토그램
    this.processingDurationHistogram = new Histogram({
      name: 'personal_data_processing_duration_seconds',
      help: 'Duration of personal data processing operations',
      labelNames: ['operation']
    });
  }

  recordAccess(action: string, status: string): void {
    this.personalDataAccessCounter.inc({ action, status });
  }

  recordConsentChange(type: string, action: string): void {
    this.consentChangeCounter.inc({ type, action });
  }

  recordDeletion(status: string): void {
    this.dataDeletionCounter.inc({ status });
  }

  recordProcessingDuration(operation: string, duration: number): void {
    this.processingDurationHistogram.observe({ operation }, duration);
  }
}
```

## 5. 변경 이력

### 버전 1.1 (2024-03-22)
- GDPR 컴플라이언스 구현 가이드 추가
- 개인정보 보호 관련 컴포넌트 추가
- 보안 강화 및 모니터링 기능 추가
- 데이터 마스킹 및 암호화 구현 추가

### 버전 1.0 (2024-03-15)
- 초기 구현 가이드 작성 