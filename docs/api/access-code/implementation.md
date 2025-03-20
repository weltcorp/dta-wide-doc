# Access Code API 구현 가이드

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 요구사항](./requirements.md)
- [API 테스트 명세](./test-spec.md)

## 1. 구현 개요
Access Code API는 일회용 접근 코드의 생성, 검증, 관리를 위한 API입니다. 이 문서는 API의 구현 세부사항과 가이드라인을 제공합니다.

### 1.1 아키텍처 구조
```typescript
src/
  ├── controllers/         # API 엔드포인트 정의
  ├── services/           # 비즈니스 로직
  ├── repositories/       # 데이터 접근 계층
  ├── entities/          # 데이터 모델
  ├── dtos/             # 데이터 전송 객체
  └── common/           # 공통 유틸리티
```

### 1.2 주요 컴포넌트
- AccessCodeController: API 엔드포인트 처리
- AccessCodeService: 비즈니스 로직 처리
- AccessCodeRepository: 데이터베이스 연동
- TimeMachineService: 시간 관리
- EmailService: 이메일 발송

## 2. 데이터 모델

### 2.1 엔티티 정의
```typescript
@Entity()
export class AccessCode {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column({
    type: 'enum',
    enum: AccessCodeType,
    default: AccessCodeType.TREATMENT
  })
  type: AccessCodeType;

  @Column({
    type: 'enum',
    enum: AccessCodeStatus,
    default: AccessCodeStatus.UNUSED
  })
  status: AccessCodeStatus;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ nullable: true })
  userId: string;

  @Column({ nullable: true })
  deviceId: string;

  @Column()
  creatorId: string;

  @Column({ nullable: true })
  accountId: string;

  @Column()
  treatmentPeriod: number;

  @Column({ type: 'timestamp' })
  createdAt: Date;

  @Column({ type: 'timestamp' })
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  usedAt: Date;

  @Index()
  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;
}
```

### 2.2 DTO 정의
```typescript
export class CreateAccessCodeDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty({ enum: AccessCodeScopes })
  @IsEnum(AccessCodeScopes)
  @IsOptional()
  scope?: AccessCodeScopes;

  @ApiProperty()
  @IsNumber()
  @Min(1)
  maxUses: number;

  @ApiProperty()
  @IsDate()
  expiresAt: Date;
}
```

## 3. 권한 관리

### 3.1 권한 정의
```typescript
export enum AccessCodePermissions {
  CREATE_CODE = 'access-code:create',
  READ_CODE = 'access-code:read',
  VERIFY_CODE = 'access-code:verify',
  REVOKE_CODE = 'access-code:revoke',
  MANAGE_POLICY = 'access-code:manage-policy',
}

export enum AccessCodeScopes {
  GLOBAL = 'access-code:global',
  ORGANIZATION = 'access-code:org',
  TEAM = 'access-code:team',
}
```

### 3.2 권한 가드
```typescript
@Injectable()
export class AccessCodePermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly iamService: IamService,
    private readonly auditService: AuditService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<string[]>('permissions', context.getHandler());
    if (!requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    switch (user.type) {
      case 'SYSTEM_ADMIN':
        await this.auditService.logAccess(user, 'ACCESS_CODE_ADMIN_ACCESS', request.path);
        return true;

      case 'IAM_ADMIN':
        const hasPermission = await this.validateIamAdminAccess(user, requiredPermissions, request);
        await this.auditService.logAccess(user, 'ACCESS_CODE_IAM_ACCESS', request.path);
        return hasPermission;

      case 'SERVICE_ACCOUNT':
        return this.validateServiceAccountAccess(user, requiredPermissions);

      case 'REGULAR_USER':
        return this.validateRegularUserAccess(user, requiredPermissions, request);

      default:
        throw new ForbiddenException('Unknown user type');
    }
  }
}
```

## 4. 비즈니스 로직 구현

### 4.1 코드 생성
```typescript
@Injectable()
export class AccessCodeService {
  constructor(
    @InjectRepository(AccessCode)
    private readonly accessCodeRepository: Repository<AccessCode>,
    private readonly timeMachineService: TimeMachineService,
    private readonly emailService: EmailService,
    private readonly eventEmitter: EventEmitter2,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache
  ) {}

  async createCode(dto: CreateAccessCodeDto): Promise<AccessCode> {
    const currentTime = await this.timeMachineService.getCurrentTime();
    const code = await this.generateUniqueCode();
    const expiresAt = addDays(currentTime, dto.usagePeriod);

    const accessCode = this.accessCodeRepository.create({
      code,
      type: dto.type,
      creatorId: dto.creatorId,
      accountId: dto.accountId,
      treatmentPeriod: dto.treatmentPeriod,
      expiresAt,
      createdAt: currentTime,
      updatedAt: currentTime,
      metadata: {
        registrationChannel: dto.registrationChannel,
        randomizationCode: dto.randomizationCode,
        privacyConsent: dto.privacyConsent
      }
    });

    const savedCode = await this.accessCodeRepository.save(accessCode);
    
    if (dto.email && dto.deliveryMethod === DeliveryMethod.EMAIL) {
      await this.emailService.sendAccessCode(dto.email, code);
    }

    this.eventEmitter.emit('access-code.created', savedCode);
    
    return savedCode;
  }
}
```

### 4.2 코드 검증
```typescript
async validateCode(code: string, deviceId: string): Promise<ValidationResult> {
  const cachedResult = await this.cacheManager.get(`validation:${code}`);
  if (cachedResult) {
    return cachedResult as ValidationResult;
  }

  const accessCode = await this.accessCodeRepository.findOne({
    where: { code }
  });

  if (!accessCode) {
    throw new ErrorResponseDto(
      ErrorCode.INVALID_CODE,
      'Code not found'
    );
  }

  const currentTime = await this.timeMachineService.getCurrentTime();

  if (accessCode.status !== AccessCodeStatus.UNUSED) {
    throw new ErrorResponseDto(
      ErrorCode.CODE_ALREADY_USED,
      'Code has already been used'
    );
  }

  if (currentTime > accessCode.expiresAt) {
    throw new ErrorResponseDto(
      ErrorCode.CODE_EXPIRED,
      'Code has expired'
    );
  }

  const result = {
    isValid: true,
    codeInfo: {
      id: accessCode.id,
      treatmentPeriod: accessCode.treatmentPeriod,
      expiresAt: accessCode.expiresAt
    }
  };

  await this.cacheManager.set(
    `validation:${code}`,
    result,
    { ttl: 300 }
  );

  return result;
}
```

## 5. 성능 최적화

### 5.1 캐싱 전략
```typescript
@Module({
  imports: [
    CacheModule.registerAsync({
      useFactory: () => ({
        store: redisStore,
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
        ttl: 300
      })
    })
  ]
})
```

### 5.2 데이터베이스 최적화
```typescript
@Entity()
@Index(['status', 'expiresAt'])
@Index(['userId', 'status'])
export class AccessCode {
  // ... 엔티티 정의
}
```

## 6. 에러 처리

### 6.1 에러 코드
```typescript
export enum ErrorCode {
  // 컨트롤러 계층 (1001-1099)
  INVALID_INPUT = 1001,
  UNAUTHORIZED = 1002,
  FORBIDDEN = 1003,

  // 서비스 계층 (1101-1199)
  INVALID_CODE = 1101,
  CODE_ALREADY_USED = 1102,
  CODE_EXPIRED = 1103,

  // 리포지토리 계층 (1201-1299)
  DATABASE_ERROR = 1201,
  DUPLICATE_CODE = 1202
}
```

### 6.2 에러 응답
```typescript
export class ErrorResponseDto {
  constructor(
    public code: ErrorCode,
    public message: string,
    public detail?: string
  ) {}

  static fromError(error: Error): ErrorResponseDto {
    if (error instanceof ErrorResponseDto) {
      return error;
    }

    return new ErrorResponseDto(
      ErrorCode.DATABASE_ERROR,
      'Internal server error',
      error.message
    );
  }
}
```

## 7. 모니터링

### 7.1 로깅
```typescript
const logger = new Logger('AccessCodeService');

logger.error('Failed to create access code', {
  error: error.message,
  dto: maskSensitiveData(dto)
});

logger.info('Access code created', {
  codeId: accessCode.id,
  type: accessCode.type
});
```

### 7.2 메트릭스
```typescript
@Injectable()
export class MetricsService {
  private readonly counter = new Counter({
    name: 'access_code_operations_total',
    help: 'Total number of access code operations',
    labelNames: ['operation', 'status']
  });

  private readonly histogram = new Histogram({
    name: 'access_code_operation_duration_seconds',
    help: 'Duration of access code operations',
    labelNames: ['operation']
  });
}
```

## 8. 테스트

### 8.1 단위 테스트
```typescript
describe('AccessCodeService', () => {
  let service: AccessCodeService;
  let timeMachineService: MockTimeMachineService;
  
  beforeEach(async () => {
    // ... 테스트 설정 ...
  });
  
  it('should verify code is not expired', async () => {
    const testTime = new Date('2024-03-20T09:00:00Z');
    timeMachineService.getCurrentTime.mockResolvedValue(testTime);
    // ... 테스트 로직 ...
  });
});
```

## 9. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-19 | System Team | 최초 작성 |
