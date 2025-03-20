# Auth API 구현 가이드

## 관련 문서
- [API 개요](./overview.md)
- [API 요구사항](./requirements.md)
- [API 엔드포인트](./endpoints.md)
- [API 테스트 명세](./test-spec.md)

## 1. 개요
이 문서는 Auth API의 구현 세부사항과 가이드라인을 제공합니다.

## 2. 컨트롤러 구현

### 2.1 인증 컨트롤러
```typescript
@Controller('v1/auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly timeMachine: TimeMachineService,
  ) {}

  @Post('login')
  @ApiOperation({ summary: '사용자 로그인' })
  @ApiResponse({ status: 200, type: LoginResponseDto })
  async login(
    @Body() dto: LoginRequestDto,
    @Headers('device-id') deviceId: string,
  ): Promise<LoginResponseDto> {
    return this.authService.login(dto, deviceId);
  }

  @Post('token/refresh')
  @ApiOperation({ summary: '토큰 갱신' })
  @ApiResponse({ status: 200, type: TokenResponseDto })
  async refreshToken(
    @Body() dto: RefreshTokenRequestDto,
  ): Promise<TokenResponseDto> {
    return this.authService.refreshToken(dto);
  }
}
```

### 2.2 약관 컨트롤러
```typescript
@Controller('v1/consents')
export class ConsentController {
  @Post()
  @ApiOperation({ summary: '약관 동의' })
  @ApiResponse({ status: 201, type: ConsentResponseDto })
  async createConsent(
    @Body() dto: CreateConsentDto,
    @User() user: UserDto,
  ): Promise<ConsentResponseDto> {
    return this.consentService.createConsent(dto, user);
  }
}
```

## 3. 서비스 구현

### 3.1 인증 서비스
```typescript
@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly tokenService: TokenService,
    private readonly cacheService: CacheService,
  ) {}

  async login(dto: LoginRequestDto, deviceId: string): Promise<LoginResponseDto> {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.validatePassword(dto.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.tokenService.generateTokens(user, deviceId);
    await this.cacheService.setUserSession(user.id, deviceId, tokens);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: UserDto.fromEntity(user),
    };
  }
}
```

### 3.2 토큰 서비스
```typescript
@Injectable()
export class TokenService {
  async generateTokens(
    user: User,
    deviceId: string,
  ): Promise<TokenPair> {
    const payload: TokenPayload = {
      sub: user.id,
      deviceId,
      type: user.type,
      permissions: user.permissions,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '30m',
    });

    const refreshToken = await this.jwtService.signAsync(
      { ...payload, tokenType: 'refresh' },
      { expiresIn: '14d' },
    );

    return { accessToken, refreshToken };
  }
}
```

## 4. 미들웨어 구현

### 4.1 인증 가드
```typescript
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly tokenService: TokenService,
    private readonly cacheService: CacheService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.tokenService.verifyToken(token);
      const isValid = await this.cacheService.validateSession(
        payload.sub,
        payload.deviceId,
      );

      if (!isValid) {
        throw new UnauthorizedException('Session expired');
      }

      request.user = payload;
      return true;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}
```

### 4.2 권한 가드
```typescript
@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return this.matchRoles(requiredRoles, user.roles);
  }
}
```

### 4.3 IAM 권한 관리
```typescript
@Injectable()
export class IamPermissionGuard implements CanActivate {
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

    // 사용자 유형별 권한 검증
    switch (user.type) {
      case 'SYSTEM_ADMIN':
        await this.auditService.logAccess(user, 'SYSTEM_ADMIN_ACCESS', request.path);
        return true; // 모든 권한 허용
        
      case 'IAM_ADMIN':
        const hasPermission = await this.validateIamAdminAccess(user, requiredPermissions, request);
        await this.auditService.logAccess(user, 'IAM_ADMIN_ACCESS', request.path);
        return hasPermission;
        
      case 'SERVICE_ACCOUNT':
        return this.validateServiceAccountAccess(user, requiredPermissions);
        
      case 'REGULAR_USER':
        return this.validateRegularUserAccess(user, requiredPermissions, request);
        
      default:
        throw new ForbiddenException('Unknown user type');
    }
  }

  private async validateIamAdminAccess(
    user: UserEntity,
    permissions: string[],
    request: Request,
  ): Promise<boolean> {
    // IAM Admin은 삭제 작업 불가
    if (permissions.includes('delete')) {
      return false;
    }

    // 할당된 범위 내의 작업만 가능
    const resourceScope = await this.iamService.getResourceScope(request.path);
    return this.iamService.isInScope(user.scope, resourceScope);
  }

  private validateServiceAccountAccess(
    user: UserEntity,
    permissions: string[],
  ): boolean {
    // Service Account는 읽기/검증 작업만 가능
    return permissions.every(p => ['read', 'validate'].includes(p));
  }

  private validateRegularUserAccess(
    user: UserEntity,
    permissions: string[],
    request: Request,
  ): boolean {
    // 자신의 리소스에 대한 작업만 가능
    const resourceUserId = request.params.userId || request.body.userId;
    return resourceUserId === user.id;
  }
}
```

### 4.4 IAM 서비스 구현
```typescript
@Injectable()
export class IamService {
  constructor(
    private readonly scopeRepository: ScopeRepository,
    private readonly cacheService: CacheService,
  ) {}

  async getResourceScope(path: string): Promise<string[]> {
    // 리소스 경로에서 스코프 추출
    const parts = path.split('/');
    const resourceType = parts[1]; // 예: users, roles, permissions
    const resourceId = parts[2];

    const cacheKey = `scope:${resourceType}:${resourceId}`;
    let scope = await this.cacheService.get<string[]>(cacheKey);

    if (!scope) {
      scope = await this.scopeRepository.findByResource(resourceType, resourceId);
      await this.cacheService.set(cacheKey, scope, { ttl: 3600 });
    }

    return scope;
  }

  isInScope(userScope: string[], resourceScope: string[]): boolean {
    // 사용자의 스코프가 리소스의 스코프를 포함하는지 확인
    return resourceScope.every(scope => userScope.includes(scope));
  }

  async assignScope(
    adminId: string,
    targetUserId: string,
    scope: string[],
  ): Promise<void> {
    // IAM Admin의 스코프 확인
    const adminScope = await this.scopeRepository.findByUserId(adminId);
    
    // Admin이 할당하려는 스코프가 자신의 스코프 내에 있는지 확인
    if (!scope.every(s => adminScope.includes(s))) {
      throw new ForbiddenException('Cannot assign scope outside your scope');
    }

    // 스코프 할당
    await this.scopeRepository.assignToUser(targetUserId, scope);
    
    // 캐시 무효화
    await this.cacheService.del(`user_scope:${targetUserId}`);
  }
}
```

### 4.5 스코프 기반 접근 제어
```typescript
@Controller('v1/auth/iam')
export class IamController {
  constructor(private readonly iamService: IamService) {}

  @Post('scope/assign')
  @UseGuards(IamPermissionGuard)
  @SetPermissions(['assign:scope'])
  async assignScope(
    @User() admin: UserEntity,
    @Body() dto: AssignScopeDto,
  ): Promise<void> {
    await this.iamService.assignScope(
      admin.id,
      dto.userId,
      dto.scope,
    );
  }

  @Get('users/:userId/scope')
  @UseGuards(IamPermissionGuard)
  @SetPermissions(['read:scope'])
  async getUserScope(
    @Param('userId') userId: string,
  ): Promise<string[]> {
    return this.iamService.getUserScope(userId);
  }
}

export class AssignScopeDto {
  @ApiProperty()
  @IsString()
  userId: string;

  @ApiProperty({ type: [String] })
  @IsArray()
  @IsString({ each: true })
  scope: string[];
}
```

### 4.6 감사 로깅
```typescript
@Injectable()
export class AuditService {
  constructor(
    private readonly auditLogRepository: AuditLogRepository,
    private readonly timeMachine: TimeMachineService,
  ) {}

  async logAccess(
    user: UserEntity,
    action: string,
    resource: string,
  ): Promise<void> {
    const now = await this.timeMachine.getCurrentDate();
    
    await this.auditLogRepository.create({
      userId: user.id,
      userType: user.type,
      action,
      resource,
      timestamp: now,
      metadata: {
        scope: user.scope,
        ip: user.ip,
        userAgent: user.userAgent,
      },
    });
  }
}
```

## 5. DTO 정의

### 5.1 인증 관련 DTO
```typescript
export class LoginRequestDto {
  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsString()
  @MinLength(8)
  password: string;
}

export class LoginResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty()
  refreshToken: string;

  @ApiProperty({ type: UserDto })
  user: UserDto;
}
```

### 5.2 약관 관련 DTO
```typescript
export class CreateConsentDto {
  @ApiProperty({ enum: ConsentType })
  @IsEnum(ConsentType)
  type: ConsentType;

  @ApiProperty()
  @IsString()
  version: string;

  @ApiProperty()
  @IsBoolean()
  agreed: boolean;
}
```

## 6. 캐싱 전략

### 6.1 토큰 캐싱
```typescript
@Injectable()
export class TokenCacheService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async setUserSession(
    userId: string,
    deviceId: string,
    tokens: TokenPair,
  ): Promise<void> {
    const key = `session:${userId}:${deviceId}`;
    await this.cacheManager.set(key, tokens, { ttl: 60 * 60 * 24 * 14 });
  }
}
```

### 6.2 약관 캐싱
```typescript
@Injectable()
export class ConsentCacheService {
  async getCachedConsents(version: string): Promise<ConsentDto[]> {
    const key = `consents:${version}`;
    let consents = await this.cacheManager.get<ConsentDto[]>(key);
    
    if (!consents) {
      consents = await this.consentRepository.findByVersion(version);
      await this.cacheManager.set(key, consents, { ttl: 3600 });
    }

    return consents;
  }
}
```

## 7. 에러 처리

### 7.1 예외 필터
```typescript
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const error = exception.getResponse() as string | object;

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: ctx.getRequest<Request>().url,
      error: typeof error === 'string' ? { message: error } : error,
    });
  }
}
```

### 7.2 비즈니스 예외
```typescript
export class AuthenticationException extends HttpException {
  constructor(message: string) {
    super(
      {
        status: HttpStatus.UNAUTHORIZED,
        code: 'AUTHENTICATION_FAILED',
        message,
      },
      HttpStatus.UNAUTHORIZED,
    );
  }
}
```

## 8. 모니터링

### 8.1 로깅 인터셉터
```typescript
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const now = Date.now();

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        const delay = Date.now() - now;
        
        Logger.log(
          `${method} ${url} ${response.statusCode} ${delay}ms`,
          'RequestLogging',
        );
      }),
    );
  }
}
```

### 8.2 메트릭스 수집
```typescript
@Injectable()
export class MetricsService {
  private readonly counter = new Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'path', 'status'],
  });

  recordRequest(method: string, path: string, status: number): void {
    this.counter.inc({ method, path, status });
  }
}
```

## 9. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-15 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-16 | bok@weltcorp.com | 권한 관리 구현 추가 |
| 0.3.0 | 2025-03-17 | bok@weltcorp.com | 캐싱 전략 추가 |
| 0.4.0 | 2025-03-19 | bok@weltcorp.com | 모니터링 구현 추가 |
| 0.5.0 | 2025-03-19 | bok@weltcorp.com | IAM 권한 관리 구현 추가 |