# IAM API 구현 가이드

## 관련 문서
- [API 개요](./overview.md)
- [API 요구사항](./requirements.md)
- [API 엔드포인트](./endpoints.md)

## 1. 컨트롤러 구현

### 권한 관리 컨트롤러
```typescript
@Controller('v1/iam/permissions')
export class PermissionsController {
  constructor(
    private readonly permissionsService: PermissionsService,
    private readonly auditService: AuditService
  ) {}

  @Post()
  @ApiOperation({ summary: '권한 생성' })
  @ApiResponse({ status: 201, type: PermissionResponseDto })
  async create(
    @Body() dto: CreatePermissionDto,
    @RequestUser() user: User
  ): Promise<PermissionResponseDto> {
    const permission = await this.permissionsService.create(dto);
    await this.auditService.log('permission.created', {
      actor: user.id,
      resource: permission.id,
      action: 'create',
      details: dto
    });
    return permission;
  }
}
```

### 역할 관리 컨트롤러
```typescript
@Controller('v1/iam/roles')
export class RolesController {
  constructor(
    private readonly rolesService: RolesService,
    private readonly auditService: AuditService
  ) {}

  @Post('users/:userId/roles')
  @ApiOperation({ summary: '역할 할당' })
  @ApiResponse({ status: 200, type: RoleAssignmentResponseDto })
  async assignRoles(
    @Param('userId') userId: string,
    @Body() dto: AssignRolesDto,
    @RequestUser() user: User
  ): Promise<RoleAssignmentResponseDto> {
    const assignment = await this.rolesService.assignRoles(userId, dto);
    await this.auditService.log('role.assigned', {
      actor: user.id,
      resource: userId,
      action: 'assign',
      details: dto
    });
    return assignment;
  }
}
```

## 2. 서비스 구현

### 권한 서비스
```typescript
@Injectable()
export class PermissionsService {
  constructor(
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
    private readonly cacheService: CacheService,
    private readonly eventEmitter: EventEmitter2
  ) {}

  async create(dto: CreatePermissionDto): Promise<Permission> {
    const permission = await this.permissionRepository.save(
      this.permissionRepository.create(dto)
    );

    await this.cacheService.invalidate(`permissions:${permission.id}`);
    await this.eventEmitter.emit('permission.created', permission);

    return permission;
  }

  async validate(
    userId: string,
    action: string,
    resource: string,
    context: any
  ): Promise<boolean> {
    const cacheKey = `permissions:${userId}:${action}:${resource}`;
    const cached = await this.cacheService.get(cacheKey);
    if (cached !== undefined) return cached;

    const result = await this.evaluatePermissions(userId, action, resource, context);
    await this.cacheService.set(cacheKey, result, 300); // 5분 캐시

    return result;
  }
}
```

### 정책 평가 서비스
```typescript
@Injectable()
export class PolicyEvaluationService {
  constructor(
    @InjectRepository(Policy)
    private readonly policyRepository: Repository<Policy>,
    private readonly conditionEvaluator: ConditionEvaluator
  ) {}

  async evaluate(
    policies: Policy[],
    context: PolicyContext
  ): Promise<PolicyEvaluationResult> {
    const sortedPolicies = this.sortPoliciesByPriority(policies);
    
    for (const policy of sortedPolicies) {
      const matches = await this.conditionEvaluator.evaluate(
        policy.conditions,
        context
      );
      
      if (matches) {
        return {
          allowed: policy.type === 'allow',
          reason: policy.type === 'allow' ? 'POLICY_ALLOW' : 'POLICY_DENY',
          policy: policy.id
        };
      }
    }

    return {
      allowed: false,
      reason: 'NO_MATCHING_POLICY',
      policy: null
    };
  }
}
```

## 3. 캐싱 전략

### 캐시 키 구조
```typescript
const cacheKeys = {
  permission: (id: string) => `permissions:${id}`,
  userPermissions: (userId: string) => `user:${userId}:permissions`,
  rolePermissions: (roleId: string) => `role:${roleId}:permissions`,
  policyEvaluation: (userId: string, action: string, resource: string) =>
    `policy:${userId}:${action}:${resource}`
};
```

### 캐시 무효화 전략
```typescript
@Injectable()
export class CacheInvalidationService {
  constructor(
    private readonly cacheService: CacheService,
    private readonly eventEmitter: EventEmitter2
  ) {
    this.subscribeToEvents();
  }

  private subscribeToEvents() {
    this.eventEmitter.on('permission.updated', async (permission: Permission) => {
      await this.invalidatePermissionCache(permission.id);
    });

    this.eventEmitter.on('role.updated', async (role: Role) => {
      await this.invalidateRoleCache(role.id);
    });
  }

  async invalidatePermissionCache(permissionId: string) {
    const patterns = [
      `permissions:${permissionId}`,
      'user:*:permissions',
      'role:*:permissions'
    ];
    await Promise.all(patterns.map(pattern => this.cacheService.deletePattern(pattern)));
  }
}
```

## 4. 성능 최적화

### 데이터베이스 인덱스
```sql
-- permissions 테이블
CREATE INDEX idx_permissions_name ON permissions (name);
CREATE INDEX idx_permissions_scope ON permissions (scope);

-- roles 테이블
CREATE INDEX idx_roles_name ON roles (name);
CREATE INDEX idx_roles_parent ON roles (parent_role_id);

-- role_assignments 테이블
CREATE INDEX idx_role_assignments_user ON role_assignments (user_id);
CREATE INDEX idx_role_assignments_role ON role_assignments (role_id);
CREATE INDEX idx_role_assignments_expires ON role_assignments (expires_at);
```

### 벌크 연산 최적화
```typescript
@Injectable()
export class RoleAssignmentService {
  async bulkAssign(
    assignments: RoleAssignment[]
  ): Promise<BulkAssignmentResult> {
    const chunks = this.chunkArray(assignments, 1000);
    const results = await Promise.all(
      chunks.map(chunk => this.assignChunk(chunk))
    );
    
    return this.aggregateResults(results);
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}
```

## 5. 모니터링

### 메트릭스 수집
```typescript
@Injectable()
export class IamMetricsService {
  constructor(private readonly metricsRegistry: MetricsRegistry) {
    this.initializeMetrics();
  }

  private initializeMetrics() {
    this.permissionEvaluationCounter = this.metricsRegistry.counter({
      name: 'iam_permission_evaluations_total',
      help: '권한 평가 총 횟수',
      labelNames: ['result']
    });

    this.policyEvaluationDuration = this.metricsRegistry.histogram({
      name: 'iam_policy_evaluation_duration_seconds',
      help: '정책 평가 소요 시간',
      buckets: [0.1, 0.5, 1, 2, 5]
    });
  }

  recordPermissionEvaluation(allowed: boolean) {
    this.permissionEvaluationCounter
      .labels(allowed ? 'allowed' : 'denied')
      .inc();
  }
}
```

### 알림 설정
```typescript
@Injectable()
export class IamAlertService {
  constructor(
    private readonly alertManager: AlertManager,
    private readonly configService: ConfigService
  ) {
    this.setupAlerts();
  }

  private setupAlerts() {
    this.alertManager.addRule({
      name: 'high_permission_denial_rate',
      condition: 'rate(iam_permission_evaluations_total{result="denied"}[5m]) > 0.1',
      severity: 'warning',
      summary: '권한 거부율이 높습니다',
      description: '최근 5분간 권한 거부율이 10%를 초과했습니다'
    });
  }
}
```

## 6. 에러 처리

### 에러 타입 정의
```typescript
export class IamError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'IamError';
  }
}

export class PermissionError extends IamError {
  constructor(message: string, details?: any) {
    super('PERMISSION_ERROR', message, details);
  }
}

export class RoleError extends IamError {
  constructor(message: string, details?: any) {
    super('ROLE_ERROR', message, details);
  }
}
```

### 글로벌 에러 핸들러
```typescript
@Catch()
export class IamExceptionFilter implements ExceptionFilter {
  catch(exception: Error, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    if (exception instanceof IamError) {
      response.status(400).json({
        status: 400,
        code: exception.code,
        message: exception.message,
        details: exception.details
      });
    } else {
      response.status(500).json({
        status: 500,
        code: 'INTERNAL_ERROR',
        message: '내부 서버 오류가 발생했습니다'
      });
    }
  }
}
```

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|---|-----|-----|
| 1.0.0 | 2024-03-21 | IAM Team | 최초 작성 | 

## 1. 사용자 유형별 권한 검증

### 권한 검증 데코레이터
```typescript
export enum UserType {
  SYSTEM_ADMIN = 'SYSTEM_ADMIN',
  IAM_ADMIN = 'IAM_ADMIN',
  SERVICE_ACCOUNT = 'SERVICE_ACCOUNT',
  REGULAR_USER = 'REGULAR_USER'
}

export function RequirePermission(options: {
  allowedTypes: UserType[];
  requireTwoFactor?: boolean;
  requireAuditLog?: boolean;
}) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const user = args.find(arg => arg instanceof User);
      
      if (!options.allowedTypes.includes(user.type)) {
        throw new ForbiddenException('접근 권한이 없습니다.');
      }

      if (options.requireTwoFactor && !user.hasTwoFactorEnabled) {
        throw new ForbiddenException('2단계 인증이 필요합니다.');
      }

      const result = await originalMethod.apply(this, args);

      if (options.requireAuditLog) {
        await this.auditService.log({
          actor: user.id,
          action: propertyKey,
          resource: result.id,
          userType: user.type
        });
      }

      return result;
    };
  };
}
```

### 사용자 유형별 권한 검증 예시
```typescript
@Controller('v1/iam/permissions')
export class PermissionsController {
  @Post()
  @RequirePermission({
    allowedTypes: [UserType.SYSTEM_ADMIN, UserType.IAM_ADMIN],
    requireAuditLog: true
  })
  async create(
    @Body() dto: CreatePermissionDto,
    @RequestUser() user: User
  ): Promise<PermissionResponseDto> {
    return this.permissionsService.create(dto);
  }

  @Delete(':id')
  @RequirePermission({
    allowedTypes: [UserType.SYSTEM_ADMIN],
    requireTwoFactor: true,
    requireAuditLog: true
  })
  async delete(
    @Param('id') id: string,
    @RequestUser() user: User
  ): Promise<void> {
    return this.permissionsService.delete(id);
  }
}
```

### Rate Limit 구현
```typescript
@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(private readonly rateLimiterService: RateLimiterService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    const limits = {
      [UserType.SERVICE_ACCOUNT]: {
        points: 1000,
        duration: 60
      },
      [UserType.REGULAR_USER]: {
        points: 100,
        duration: 60
      }
    };

    const limit = limits[user.type];
    if (!limit) return true;

    const result = await this.rateLimiterService.checkLimit(
      user.id,
      limit.points,
      limit.duration
    );

    if (!result.allowed) {
      throw new TooManyRequestsException();
    }

    return true;
  }
}
```

### 범위 기반 접근 제어
```typescript
@Injectable()
export class ScopeBasedAccessService {
  async validateAccess(
    user: User,
    resource: string,
    action: string
  ): Promise<boolean> {
    switch (user.type) {
      case UserType.SYSTEM_ADMIN:
        return true;

      case UserType.IAM_ADMIN:
        return this.validateIamAdminAccess(user, resource, action);

      case UserType.SERVICE_ACCOUNT:
        return this.validateServiceAccountAccess(user, resource, action);

      case UserType.REGULAR_USER:
        return this.validateRegularUserAccess(user, resource, action);

      default:
        return false;
    }
  }

  private async validateIamAdminAccess(
    user: User,
    resource: string,
    action: string
  ): Promise<boolean> {
    // IAM 관리자는 삭제 작업 불가
    if (action === 'delete') return false;

    // 할당된 범위 내의 리소스만 접근 가능
    return this.isResourceInScope(resource, user.scope);
  }

  private async validateServiceAccountAccess(
    user: User,
    resource: string,
    action: string
  ): Promise<boolean> {
    // 서비스 계정은 조회 작업만 가능
    if (action !== 'read') return false;

    // 할당된 범위 내의 리소스만 접근 가능
    return this.isResourceInScope(resource, user.scope);
  }

  private async validateRegularUserAccess(
    user: User,
    resource: string,
    action: string
  ): Promise<boolean> {
    // 일반 사용자는 자신의 리소스만 접근 가능
    return resource.startsWith(`users/${user.id}`);
  }
}
``` 