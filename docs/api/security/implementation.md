# Security API 구현 가이드

## 개요
Security API의 구현 방법과 예시 코드를 제공합니다.

## 프로젝트 구조
```
src/
├── security/
│   ├── controllers/
│   │   ├── policy.controller.ts
│   │   ├── event.controller.ts
│   │   └── audit.controller.ts
│   ├── services/
│   │   ├── policy.service.ts
│   │   ├── event.service.ts
│   │   └── audit.service.ts
│   ├── dtos/
│   │   ├── policy.dto.ts
│   │   ├── event.dto.ts
│   │   └── audit.dto.ts
│   ├── entities/
│   │   ├── policy.entity.ts
│   │   ├── event.entity.ts
│   │   └── audit.entity.ts
│   └── interfaces/
│       ├── policy.interface.ts
│       ├── event.interface.ts
│       └── audit.interface.ts
```

## 구현 예시

### 1. 엔티티 정의

#### SecurityPolicy 엔티티
```typescript
import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('security_policies')
export class SecurityPolicy {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'enum', enum: SecurityPolicyType })
  type: SecurityPolicyType;

  @Column()
  name: string;

  @Column()
  value: string;

  @Column()
  description: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

#### SecurityEvent 엔티티
```typescript
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('security_events')
export class SecurityEvent {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'enum', enum: SecurityEventType })
  type: SecurityEventType;

  @Column({ type: 'enum', enum: SecurityEventSeverity })
  severity: SecurityEventSeverity;

  @Column()
  source: string;

  @Column()
  description: string;

  @Column({ type: 'jsonb' })
  metadata: Record<string, any>;

  @Column({ type: 'timestamp' })
  timestamp: Date;
}
```

### 2. DTO 정의

#### CreateSecurityPolicyDto
```typescript
import { IsEnum, IsString, IsNotEmpty, IsBoolean } from 'class-validator';

export class CreateSecurityPolicyDto {
  @IsEnum(SecurityPolicyType)
  type: SecurityPolicyType;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsNotEmpty()
  value: string;

  @IsString()
  description: string;

  @IsBoolean()
  isActive: boolean;
}
```

#### CreateSecurityEventDto
```typescript
import { IsEnum, IsString, IsNotEmpty, IsObject } from 'class-validator';

export class CreateSecurityEventDto {
  @IsEnum(SecurityEventType)
  type: SecurityEventType;

  @IsEnum(SecurityEventSeverity)
  severity: SecurityEventSeverity;

  @IsString()
  @IsNotEmpty()
  source: string;

  @IsString()
  @IsNotEmpty()
  description: string;

  @IsObject()
  metadata: Record<string, any>;
}
```

### 3. 서비스 구현

#### SecurityPolicyService
```typescript
@Injectable()
export class SecurityPolicyService {
  constructor(
    @InjectRepository(SecurityPolicy)
    private policyRepository: Repository<SecurityPolicy>,
    private cacheManager: Cache,
  ) {}

  async createPolicy(dto: CreateSecurityPolicyDto): Promise<SecurityPolicy> {
    const policy = this.policyRepository.create(dto);
    await this.policyRepository.save(policy);
    await this.invalidateCache(policy.type);
    return policy;
  }

  async getPolicy(type: SecurityPolicyType): Promise<SecurityPolicy> {
    const cacheKey = `security_policy:${type}`;
    const cached = await this.cacheManager.get<SecurityPolicy>(cacheKey);

    if (cached) {
      return cached;
    }

    const policy = await this.policyRepository.findOne({
      where: { type, isActive: true },
    });

    if (policy) {
      await this.cacheManager.set(cacheKey, policy, { ttl: 3600 });
    }

    return policy;
  }

  private async invalidateCache(type: SecurityPolicyType): Promise<void> {
    const cacheKey = `security_policy:${type}`;
    await this.cacheManager.del(cacheKey);
  }
}
```

#### SecurityEventService
```typescript
@Injectable()
export class SecurityEventService {
  constructor(
    @InjectRepository(SecurityEvent)
    private eventRepository: Repository<SecurityEvent>,
    private readonly logger: Logger,
  ) {}

  async createEvent(dto: CreateSecurityEventDto): Promise<SecurityEvent> {
    const event = this.eventRepository.create({
      ...dto,
      timestamp: new Date(),
    });

    await this.eventRepository.save(event);
    
    if (event.severity >= SecurityEventSeverity.HIGH) {
      await this.notifySecurityTeam(event);
    }

    return event;
  }

  private async notifySecurityTeam(event: SecurityEvent): Promise<void> {
    try {
      // 알림 로직 구현
      this.logger.warn(`Security event: ${event.type} - ${event.description}`);
    } catch (error) {
      this.logger.error('Failed to notify security team', error);
    }
  }
}
```

### 4. 컨트롤러 구현

#### SecurityPolicyController
```typescript
@Controller('v1/security/policies')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SecurityPolicyController {
  constructor(private readonly policyService: SecurityPolicyService) {}

  @Post()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: '보안 정책 생성' })
  async createPolicy(
    @Body() dto: CreateSecurityPolicyDto,
  ): Promise<SecurityPolicy> {
    return this.policyService.createPolicy(dto);
  }

  @Get(':type')
  @ApiOperation({ summary: '보안 정책 조회' })
  async getPolicy(
    @Param('type') type: SecurityPolicyType,
  ): Promise<SecurityPolicy> {
    return this.policyService.getPolicy(type);
  }
}
```

#### SecurityEventController
```typescript
@Controller('v1/security/events')
@UseGuards(JwtAuthGuard)
export class SecurityEventController {
  constructor(private readonly eventService: SecurityEventService) {}

  @Post()
  @ApiOperation({ summary: '보안 이벤트 생성' })
  async createEvent(
    @Body() dto: CreateSecurityEventDto,
  ): Promise<SecurityEvent> {
    return this.eventService.createEvent(dto);
  }

  @Get()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: '보안 이벤트 목록 조회' })
  async getEvents(
    @Query() query: GetEventsQueryDto,
  ): Promise<PaginatedResponse<SecurityEvent>> {
    return this.eventService.getEvents(query);
  }
}
```

### 5. 미들웨어 구현

#### SecurityAuditMiddleware
```typescript
@Injectable()
export class SecurityAuditMiddleware implements NestMiddleware {
  constructor(private readonly auditService: AuditService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    res.on('finish', () => {
      const endTime = Date.now();
      const duration = endTime - startTime;

      this.auditService.createAuditLog({
        userId: req.user?.id,
        action: req.method,
        resourceType: this.getResourceType(req.path),
        resourceId: this.getResourceId(req.path),
        metadata: {
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          duration,
          statusCode: res.statusCode,
        },
      });
    });

    next();
  }

  private getResourceType(path: string): string {
    const parts = path.split('/');
    return parts[2] || 'unknown';
  }

  private getResourceId(path: string): string {
    const parts = path.split('/');
    return parts[3] || 'unknown';
  }
}
```

### 6. 예외 처리

#### SecurityExceptionFilter
```typescript
@Catch(SecurityException)
export class SecurityExceptionFilter implements ExceptionFilter {
  catch(exception: SecurityException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    response.status(status).json({
      status,
      code: exception.code,
      message: exception.message,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
```

### 7. 캐시 설정

```typescript
@Module({
  imports: [
    CacheModule.registerAsync({
      useFactory: () => ({
        store: redisStore,
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
        ttl: 3600,
        max: 100,
      }),
    }),
  ],
})
export class SecurityModule {}
```

### 8. 테스트 구현

#### SecurityPolicyService 테스트
```typescript
describe('SecurityPolicyService', () => {
  let service: SecurityPolicyService;
  let repository: Repository<SecurityPolicy>;
  let cacheManager: Cache;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecurityPolicyService,
        {
          provide: getRepositoryToken(SecurityPolicy),
          useClass: Repository,
        },
        {
          provide: CACHE_MANAGER,
          useValue: {
            get: jest.fn(),
            set: jest.fn(),
            del: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<SecurityPolicyService>(SecurityPolicyService);
    repository = module.get<Repository<SecurityPolicy>>(
      getRepositoryToken(SecurityPolicy),
    );
    cacheManager = module.get<Cache>(CACHE_MANAGER);
  });

  it('should create a policy', async () => {
    const dto = {
      type: SecurityPolicyType.PASSWORD,
      name: 'Password Policy',
      value: 'min_length:8',
      description: 'Minimum password length',
      isActive: true,
    };

    const policy = new SecurityPolicy();
    Object.assign(policy, dto);

    jest.spyOn(repository, 'create').mockReturnValue(policy);
    jest.spyOn(repository, 'save').mockResolvedValue(policy);
    jest.spyOn(cacheManager, 'del').mockResolvedValue(undefined);

    const result = await service.createPolicy(dto);
    expect(result).toEqual(policy);
  });
});
```

## 배포 고려사항

### 1. 환경 변수 설정
```typescript
export const config = {
  database: {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
  },
  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10),
    password: process.env.REDIS_PASSWORD,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN,
  },
  monitoring: {
    enabled: process.env.MONITORING_ENABLED === 'true',
    endpoint: process.env.MONITORING_ENDPOINT,
  },
};
```

### 2. 로깅 설정
```typescript
const logger = new Logger('SecurityModule');

logger.log('Security policy updated', {
  type: policy.type,
  name: policy.name,
  updatedBy: user.id,
});

logger.error('Failed to process security event', {
  eventId: event.id,
  error: error.message,
  stack: error.stack,
});
```

### 3. 모니터링 설정
```typescript
@Injectable()
export class SecurityMetricsService {
  private readonly counter: Counter;
  private readonly histogram: Histogram;

  constructor() {
    this.counter = new Counter({
      name: 'security_events_total',
      help: 'Total number of security events',
      labelNames: ['type', 'severity'],
    });

    this.histogram = new Histogram({
      name: 'security_policy_check_duration_seconds',
      help: 'Duration of security policy checks',
      labelNames: ['type'],
    });
  }

  recordEvent(event: SecurityEvent): void {
    this.counter.inc({ type: event.type, severity: event.severity });
  }

  measurePolicyCheck(type: SecurityPolicyType, duration: number): void {
    this.histogram.observe({ type }, duration);
  }
}
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 1.0.0 | 2024-03-21 | System Team | 최초 작성 | 