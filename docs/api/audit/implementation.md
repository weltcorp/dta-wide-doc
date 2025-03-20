# Audit API 구현 가이드

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 요구사항](./requirements.md)
- [API 테스트 명세](./test-spec.md)

## 개요
Audit API 구현을 위한 가이드 문서입니다. API 엔드포인트 구현, 미들웨어 설정, 에러 처리 방법을 설명합니다.

## API 구현 예제

### 컨트롤러 구현
```typescript
@Controller("v1/audit")
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Post("logs")
  async createAuditLog(@Body() dto: CreateAuditLogDto): Promise<AuditLogResponseDto> {
    return this.auditService.createAuditLog(dto);
  }

  @Get("logs")
  async getAuditLogs(@Query() query: GetAuditLogsDto): Promise<AuditLogResponseDto[]> {
    return this.auditService.getAuditLogs(query);
  }

  @Get("logs/:logId")
  async getAuditLog(@Param("logId") logId: string): Promise<AuditLogResponseDto> {
    return this.auditService.getAuditLog(logId);
  }

  @Get("logs/session/:sessionId")
  async getSessionAuditLogs(@Param("sessionId") sessionId: string): Promise<AuditLogResponseDto[]> {
    return this.auditService.getSessionAuditLogs(sessionId);
  }

  @Post("policies")
  async createAuditPolicy(@Body() dto: CreateAuditPolicyDto): Promise<AuditPolicyResponseDto> {
    return this.auditService.createAuditPolicy(dto);
  }

  @Get("policies")
  async getAuditPolicies(): Promise<AuditPolicyResponseDto[]> {
    return this.auditService.getAuditPolicies();
  }

  @Get("policies/:policyId")
  async getAuditPolicy(@Param("policyId") policyId: string): Promise<AuditPolicyResponseDto> {
    return this.auditService.getAuditPolicy(policyId);
  }

  @Put("policies/:policyId")
  async updateAuditPolicy(
    @Param("policyId") policyId: string,
    @Body() dto: UpdateAuditPolicyDto
  ): Promise<AuditPolicyResponseDto> {
    return this.auditService.updateAuditPolicy(policyId, dto);
  }

  @Delete("policies/:policyId")
  async deleteAuditPolicy(@Param("policyId") policyId: string): Promise<void> {
    return this.auditService.deleteAuditPolicy(policyId);
  }

  @Post("policies/:policyId/activate")
  async activateAuditPolicy(@Param("policyId") policyId: string): Promise<AuditPolicyResponseDto> {
    return this.auditService.activateAuditPolicy(policyId);
  }

  @Post("policies/:policyId/deactivate")
  async deactivateAuditPolicy(@Param("policyId") policyId: string): Promise<AuditPolicyResponseDto> {
    return this.auditService.deactivateAuditPolicy(policyId);
  }
}
```

### 미들웨어 설정
```typescript
// 권한 검증 미들웨어
@Injectable()
export class AuditPermissionGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    if (!user) {
      throw new UnauthorizedException();
    }

    // IAM 관련 감사 로그 접근 권한 검증
    if (request.path.startsWith("/v1/audit/logs") && request.query.eventType?.startsWith("IAM_")) {
      return user.role === "IAM_ADMIN" || user.role === "SUPER_ADMIN";
    }

    // 감사 로그 생성은 서비스 계정만 가능
    if (request.method === "POST" && request.path === "/v1/audit/logs") {
      return user.type === "SERVICE_ACCOUNT";
    }

    // 감사 로그 조회는 관리자만 가능
    if (request.path.startsWith("/v1/audit/logs")) {
      return user.role === "ADMIN" || user.role === "IAM_ADMIN" || user.role === "SUPER_ADMIN";
    }

    // 감사 정책 관리는 상위 관리자만 가능
    if (request.path.startsWith("/v1/audit/policies")) {
      return user.role === "SUPER_ADMIN";
    }

    return false;
  }
}
```

### 에러 핸들링
```typescript
@Catch(HttpException)
export class AuditExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const error = exception.getResponse() as string | ErrorResponse;

    // IAM 관련 에러 코드
    const iamErrorCodes = {
      IAM_PERMISSION_DENIED: 3001,
      IAM_RESOURCE_NOT_FOUND: 3002,
      IAM_INVALID_SCOPE: 3003,
      IAM_DUPLICATE_RESOURCE: 3004,
      IAM_INVALID_ASSIGNMENT: 3005,
    };

    response.status(status).json({
      status,
      code: error.code || this.getErrorCode(error) || "INTERNAL_SERVER_ERROR",
      message: error.message || "Internal server error",
      detail: error.detail
    });
  }

  private getErrorCode(error: any): string {
    if (error.message?.includes("IAM")) {
      if (error.message.includes("permissions")) return "IAM_PERMISSION_DENIED";
      if (error.message.includes("not found")) return "IAM_RESOURCE_NOT_FOUND";
      if (error.message.includes("scope")) return "IAM_INVALID_SCOPE";
      if (error.message.includes("duplicate")) return "IAM_DUPLICATE_RESOURCE";
      if (error.message.includes("assignment")) return "IAM_INVALID_ASSIGNMENT";
    }
    return null;
  }
}
```

## API 테스트 방법
> 상세 테스트 케이스 및 시나리오는 [테스트 명세 문서](./test-spec.md)를 참조하세요.

### 단위 테스트
```typescript
describe("AuditController", () => {
  let controller: AuditController;
  let service: AuditService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [AuditController],
      providers: [
        {
          provide: AuditService,
          useValue: {
            createAuditLog: jest.fn(),
            getAuditLogs: jest.fn(),
            getAuditLog: jest.fn(),
            getSessionAuditLogs: jest.fn(),
            createAuditPolicy: jest.fn(),
            getAuditPolicies: jest.fn(),
            getAuditPolicy: jest.fn(),
            updateAuditPolicy: jest.fn(),
            deleteAuditPolicy: jest.fn(),
            activateAuditPolicy: jest.fn(),
            deactivateAuditPolicy: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get(AuditController);
    service = module.get(AuditService);
  });

  describe("createAuditLog", () => {
    it("should create audit log successfully", async () => {
      const dto = {
        eventType: "USER_LOGIN",
        source: "AUTH_SERVICE",
        sessionId: "session_123",
        userId: "user_123",
        metadata: {
          ipAddress: "192.168.1.1",
          userAgent: "Mozilla/5.0"
        }
      };
      const expected = {
        id: "log_123",
        ...dto,
        timestamp: new Date(),
      };

      jest.spyOn(service, "createAuditLog").mockResolvedValue(expected);
      const result = await controller.createAuditLog(dto);
      expect(result).toEqual(expected);
    });
  });
});

describe("Audit API (e2e)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AuditModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it("/v1/audit/logs (POST)", () => {
    return request(app.getHttpServer())
      .post("/v1/audit/logs")
      .send({
        eventType: "USER_LOGIN",
        source: "AUTH_SERVICE",
        sessionId: "session_123",
        userId: "user_123",
        metadata: {
          ipAddress: "192.168.1.1",
          userAgent: "Mozilla/5.0"
        }
      })
      .expect(201)
      .expect(res => {
        expect(res.body.data).toHaveProperty("id");
        expect(res.body.data).toHaveProperty("timestamp");
      });
  });

  afterAll(async () => {
    await app.close();
  });
});
```

## 구현 시 고려사항

### 보안
1. 모든 API 엔드포인트는 HTTPS 사용
2. 감사 로그는 불변성 보장 (수정/삭제 불가)
3. 접근 권한 엄격히 관리
   - 로그 생성: 서비스 계정만 가능
   - 로그 조회: 관리자만 가능
   - 정책 관리: 상위 관리자만 가능

### 성능
1. 로그 저장 최적화
   - 비동기 처리
   - 배치 처리
   - 인덱싱 전략
2. 조회 성능 최적화
   - 페이지네이션
   - 캐싱
   - 쿼리 최적화

### 모니터링
1. 로그 생성/조회 성능 모니터링
2. 저장소 사용량 모니터링
3. 정책 변경 이력 모니터링

## DTO 구현

### 감사 로그 DTO
```typescript
export class CreateAuditLogDto {
  @ApiProperty({ description: "감사 이벤트 유형" })
  @IsString()
  @IsNotEmpty()
  eventType: string;

  @ApiProperty({ description: "이벤트 소스" })
  @IsString()
  @IsNotEmpty()
  source: string;

  @ApiProperty({ description: "세션 ID" })
  @IsString()
  @IsNotEmpty()
  sessionId: string;

  @ApiProperty({ description: "사용자 ID" })
  @IsString()
  @IsNotEmpty()
  userId: string;

  @ApiProperty({ description: "IAM 작업 대상 리소스 ID" })
  @IsString()
  @IsOptional()
  iamResourceId?: string;

  @ApiProperty({ description: "IAM 작업 범위" })
  @IsString()
  @IsOptional()
  iamScope?: string;

  @ApiProperty({ description: "IAM 작업 상세 정보" })
  @IsObject()
  @IsOptional()
  iamActionDetails?: Record<string, any>;

  @ApiProperty({ description: "추가 메타데이터" })
  @IsObject()
  @IsOptional()
  metadata?: Record<string, any>;
}

export class AuditLogResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  eventType: string;

  @ApiProperty()
  source: string;

  @ApiProperty()
  sessionId: string;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  iamResourceId?: string;

  @ApiProperty()
  iamScope?: string;

  @ApiProperty()
  iamActionDetails?: Record<string, any>;

  @ApiProperty()
  timestamp: Date;

  @ApiProperty()
  metadata?: Record<string, any>;
}

export class GetAuditLogsDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  eventType?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  source?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  userId?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsNumber()
  @Min(1)
  page?: number;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number;
}
```

### 감사 정책 DTO
```typescript
export class CreateAuditPolicyDto {
  @ApiProperty({ description: "정책 이름" })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: "정책 설명" })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ description: "감사할 이벤트 유형 목록" })
  @IsArray()
  @IsString({ each: true })
  eventTypes: string[];

  @ApiProperty({ description: "감사할 소스 목록" })
  @IsArray()
  @IsString({ each: true })
  sources: string[];

  @ApiProperty({ description: "활성화 여부" })
  @IsBoolean()
  @IsOptional()
  enabled?: boolean;

  @ApiProperty({ description: "로그 보관 기간(일)" })
  @IsNumber()
  @Min(1)
  retentionPeriod: number;
}

export class UpdateAuditPolicyDto {
  @ApiProperty({ description: "정책 이름" })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({ description: "정책 설명" })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ description: "감사할 이벤트 유형 목록" })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  eventTypes?: string[];

  @ApiProperty({ description: "감사할 소스 목록" })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  sources?: string[];

  @ApiProperty({ description: "로그 보관 기간(일)" })
  @IsNumber()
  @Min(1)
  @IsOptional()
  retentionPeriod?: number;
}

export class AuditPolicyResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  description?: string;

  @ApiProperty()
  eventTypes: string[];

  @ApiProperty()
  sources: string[];

  @ApiProperty()
  enabled: boolean;

  @ApiProperty()
  retentionPeriod: number;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}
```

## 서비스 구현

### 감사 로그 서비스
```typescript
@Injectable()
export class AuditService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
    @InjectRepository(AuditPolicy)
    private readonly auditPolicyRepository: Repository<AuditPolicy>,
    private readonly eventEmitter: EventEmitter2,
    private readonly configService: ConfigService,
    private readonly logger: Logger
  ) {}

  async createAuditLog(dto: CreateAuditLogDto): Promise<AuditLogResponseDto> {
    try {
      // IAM 이벤트 검증
      if (dto.eventType.startsWith("IAM_")) {
        await this.validateIAMEvent(dto);
      }

      // 활성화된 감사 정책 확인
      const policy = await this.getActivePolicy(dto.eventType, dto.source);
      if (!policy) {
        this.logger.warn(`No active audit policy for event: ${dto.eventType}, source: ${dto.source}`);
        return;
      }

      // 감사 로그 생성
      const log = this.auditLogRepository.create({
        ...dto,
        timestamp: new Date(),
      });

      const savedLog = await this.auditLogRepository.save(log);

      // 이벤트 발행
      this.eventEmitter.emit("audit.log.created", savedLog);

      return this.mapToDto(savedLog);
    } catch (error) {
      this.logger.error(`Failed to create audit log: ${error.message}`, error.stack);
      throw new InternalServerErrorException("Failed to create audit log");
    }
  }

  async getAuditLogs(query: GetAuditLogsDto): Promise<AuditLogResponseDto[]> {
    try {
      const queryBuilder = this.auditLogRepository.createQueryBuilder("log");

      // IAM 이벤트 필터링 로직
      if (query.eventType?.startsWith("IAM_")) {
        await this.validateIAMAccess(query);
        if (query.iamResourceId) {
          queryBuilder.andWhere("log.iamResourceId = :iamResourceId", { iamResourceId: query.iamResourceId });
        }
        if (query.iamScope) {
          queryBuilder.andWhere("log.iamScope = :iamScope", { iamScope: query.iamScope });
        }
      }

      // 기존 필터 적용
      if (query.eventType) {
        queryBuilder.andWhere("log.eventType = :eventType", { eventType: query.eventType });
      }
      if (query.source) {
        queryBuilder.andWhere("log.source = :source", { source: query.source });
      }
      if (query.userId) {
        queryBuilder.andWhere("log.userId = :userId", { userId: query.userId });
      }
      if (query.startDate) {
        queryBuilder.andWhere("log.timestamp >= :startDate", { startDate: query.startDate });
      }
      if (query.endDate) {
        queryBuilder.andWhere("log.timestamp <= :endDate", { endDate: query.endDate });
      }

      // 페이지네이션
      const page = query.page || 1;
      const limit = query.limit || 20;
      queryBuilder
        .orderBy("log.timestamp", "DESC")
        .skip((page - 1) * limit)
        .take(limit);

      const logs = await queryBuilder.getMany();
      return logs.map(log => this.mapToDto(log));
    } catch (error) {
      this.logger.error(`Failed to get audit logs: ${error.message}`, error.stack);
      throw new InternalServerErrorException("Failed to get audit logs");
    }
  }

  private async validateIAMEvent(dto: CreateAuditLogDto): Promise<void> {
    if (!dto.iamResourceId) {
      throw new BadRequestException("IAM resource ID is required for IAM events");
    }
    if (!dto.iamScope) {
      throw new BadRequestException("IAM scope is required for IAM events");
    }
    if (!dto.iamActionDetails) {
      throw new BadRequestException("IAM action details are required for IAM events");
    }
  }

  private async validateIAMAccess(query: GetAuditLogsDto): Promise<void> {
    const user = this.request.user;
    if (!user || !["IAM_ADMIN", "SUPER_ADMIN"].includes(user.role)) {
      throw new ForbiddenException("Insufficient permissions to access IAM audit logs");
    }
  }

  private async getActivePolicy(eventType: string, source: string): Promise<AuditPolicy | null> {
    return this.auditPolicyRepository.findOne({
      where: {
        enabled: true,
        eventTypes: ArrayContains([eventType]),
        sources: ArrayContains([source]),
      },
    });
  }

  private mapToDto(log: AuditLog): AuditLogResponseDto {
    return {
      id: log.id,
      eventType: log.eventType,
      source: log.source,
      sessionId: log.sessionId,
      userId: log.userId,
      iamResourceId: log.iamResourceId,
      iamScope: log.iamScope,
      iamActionDetails: log.iamActionDetails,
      timestamp: log.timestamp,
      metadata: log.metadata,
    };
  }
}
```

### 감사 정책 서비스
```typescript
@Injectable()
export class AuditPolicyService {
  constructor(
    @InjectRepository(AuditPolicy)
    private readonly policyRepository: Repository<AuditPolicy>,
    private readonly eventEmitter: EventEmitter2,
    private readonly logger: Logger
  ) {}

  async createAuditPolicy(dto: CreateAuditPolicyDto): Promise<AuditPolicyResponseDto> {
    try {
      const policy = this.policyRepository.create({
        ...dto,
        enabled: dto.enabled ?? false,
      });

      const savedPolicy = await this.policyRepository.save(policy);
      this.eventEmitter.emit("audit.policy.created", savedPolicy);

      return this.mapToDto(savedPolicy);
    } catch (error) {
      this.logger.error(`Failed to create audit policy: ${error.message}`, error.stack);
      throw new InternalServerErrorException("Failed to create audit policy");
    }
  }

  async updateAuditPolicy(
    policyId: string,
    dto: UpdateAuditPolicyDto
  ): Promise<AuditPolicyResponseDto> {
    try {
      const policy = await this.policyRepository.findOne(policyId);
      if (!policy) {
        throw new NotFoundException("Audit policy not found");
      }

      Object.assign(policy, dto);
      const updatedPolicy = await this.policyRepository.save(policy);
      this.eventEmitter.emit("audit.policy.updated", updatedPolicy);

      return this.mapToDto(updatedPolicy);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Failed to update audit policy: ${error.message}`, error.stack);
      throw new InternalServerErrorException("Failed to update audit policy");
    }
  }

  private mapToDto(policy: AuditPolicy): AuditPolicyResponseDto {
    return {
      id: policy.id,
      name: policy.name,
      description: policy.description,
      eventTypes: policy.eventTypes,
      sources: policy.sources,
      enabled: policy.enabled,
      retentionPeriod: policy.retentionPeriod,
      createdAt: policy.createdAt,
      updatedAt: policy.updatedAt,
    };
  }
}
```

## 데이터베이스 스키마

### 감사 로그 테이블
```sql
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_type VARCHAR(100) NOT NULL,
  source VARCHAR(100) NOT NULL,
  session_id VARCHAR(100) NOT NULL,
  user_id VARCHAR(100) NOT NULL,
  iam_resource_id VARCHAR(100),
  iam_scope VARCHAR(100),
  iam_action_details JSONB,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_source ON audit_logs(source);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_session_id ON audit_logs(session_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_iam_resource ON audit_logs(iam_resource_id);
CREATE INDEX idx_audit_logs_iam_scope ON audit_logs(iam_scope);
```

### 감사 정책 테이블
```sql
CREATE TABLE audit_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  description TEXT,
  event_types TEXT[] NOT NULL,
  sources TEXT[] NOT NULL,
  enabled BOOLEAN DEFAULT false,
  retention_period INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스
CREATE INDEX idx_audit_policies_name ON audit_policies(name);
CREATE INDEX idx_audit_policies_enabled ON audit_policies(enabled);
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | IAM 관련 기능 추가: 권한 검증, 이벤트 로깅, 에러 처리 |
