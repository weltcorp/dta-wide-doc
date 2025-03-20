# Auth 도메인 구현 가이드

## 개요
이 문서는 Auth 도메인의 구현에 대한 세부 가이드라인을 제공합니다. 토큰 관리, 키 관리, 컨센트 토큰 관리, 앱 인증 관리 등 주요 기능의 구현 방법을 설명합니다.

## 1. 토큰 관리 구현

### 1.1 Access Token 발급/검증

#### 구현 예제
```typescript
@Injectable()
export class TokenService {
  constructor(
    private readonly jwkService: JWKService,
    private readonly redisService: RedisService,
    private readonly timeMachineService: TimeMachineService
  ) {}

  async createAccessToken(userId: string, scopes: string[]): Promise<string> {
    const key = await this.jwkService.getActiveKey();
    const now = await this.timeMachineService.getCurrentTimestamp();
    
    const payload = {
      iss: 'auth.weltcorp.com',
      sub: userId,
      aud: ['api.weltcorp.com'],
      exp: now + (30 * 60 * 1000), // 30분 유효
      iat: now,
      jti: uuidv4(),
      type: 'ACCESS',
      scope: scopes
    };
    
    const token = jwt.sign(payload, key.privateKey, {
      algorithm: 'RS256',
      header: {
        kid: key.id,
        typ: 'JWT'
      }
    });
    
    // 토큰 메타데이터 캐싱
    await this.redisService.set(
      `token:access:${payload.jti}`,
      JSON.stringify({
        userId,
        exp: payload.exp,
        revoked: false
      }),
      60 * 30 // 30분 캐시
    );
    
    return token;
  }

  async verifyAccessToken(token: string): Promise<TokenPayload> {
    try {
      // 토큰 디코딩
      const decoded = jwt.decode(token, { complete: true }) as any;
      if (!decoded) throw new Error('Invalid token format');
      
      // 키 조회
      const key = await this.jwkService.getKey(decoded.header.kid);
      if (!key) throw new Error('Invalid key ID');
      
      // 서명 검증
      const payload = jwt.verify(token, key.publicKey, {
        algorithms: ['RS256']
      }) as TokenPayload;
      
      // 타입 검증
      if (payload.type !== 'ACCESS') throw new Error('Invalid token type');
      
      // Redis 검증 (폐기 여부)
      const cached = await this.redisService.get(`token:access:${payload.jti}`);
      if (!cached) throw new Error('Token not found in cache');
      
      const meta = JSON.parse(cached);
      if (meta.revoked) throw new Error('Token has been revoked');
      
      return payload;
    } catch (error) {
      throw new UnauthorizedException('Token validation failed');
    }
  }
}
```

### 1.2 Refresh Token 발급/갱신

```typescript
async createRefreshToken(userId: string): Promise<string> {
  const key = await this.jwkService.getActiveKey();
  const now = await this.timeMachineService.getCurrentTimestamp();
  const sessionId = uuidv4();
  
  const payload = {
    iss: 'auth.weltcorp.com',
    sub: userId,
    exp: now + (14 * 24 * 60 * 60 * 1000), // 14일 유효
    iat: now,
    jti: uuidv4(),
    type: 'REFRESH',
    sessionId
  };
  
  const token = jwt.sign(payload, key.privateKey, {
    algorithm: 'RS256',
    header: {
      kid: key.id,
      typ: 'JWT'
    }
  });
  
  // 세션 정보 저장
  await this.redisService.set(
    `session:${sessionId}`,
    JSON.stringify({
      userId,
      tokenId: payload.jti,
      exp: payload.exp,
      issuedAt: payload.iat,
      used: false
    }),
    60 * 60 * 24 * 14 // 14일 캐시
  );
  
  return token;
}

async refreshToken(refreshToken: string): Promise<{accessToken: string, refreshToken: string}> {
  // 토큰 검증
  const payload = await this.verifyRefreshToken(refreshToken);
  
  // 세션 정보 조회
  const sessionKey = `session:${payload.sessionId}`;
  const sessionData = await this.redisService.get(sessionKey);
  if (!sessionData) throw new UnauthorizedException('Invalid session');
  
  const session = JSON.parse(sessionData);
  
  // 토큰 재사용 검증
  if (session.used) throw new UnauthorizedException('Token has been used');
  
  // 세션 사용 표시
  await this.redisService.set(
    sessionKey,
    JSON.stringify({
      ...session,
      used: true
    }),
    60 * 60 * 24 * 14 // 14일 캐시
  );
  
  // 새 토큰 발급
  const userId = payload.sub;
  const scopes = await this.getUserScopes(userId);
  
  const newAccessToken = await this.createAccessToken(userId, scopes);
  const newRefreshToken = await this.createRefreshToken(userId);
  
  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  };
}
```

### 1.3 토큰 폐기 및 블랙리스트

```typescript
async revokeToken(tokenId: string, reason: string): Promise<void> {
  // 액세스 토큰 폐기
  const accessTokenKey = `token:access:${tokenId}`;
  const accessTokenData = await this.redisService.get(accessTokenKey);
  
  if (accessTokenData) {
    const data = JSON.parse(accessTokenData);
    await this.redisService.set(
      accessTokenKey,
      JSON.stringify({
        ...data,
        revoked: true,
        revokedAt: await this.timeMachineService.getCurrentTimestamp(),
        reason
      }),
      60 * 30 // 30분 유지
    );
  }
  
  // 세션 폐기 (리프레시 토큰)
  const sessionKey = `session:${tokenId}`;
  const sessionData = await this.redisService.get(sessionKey);
  
  if (sessionData) {
    const data = JSON.parse(sessionData);
    await this.redisService.set(
      sessionKey,
      JSON.stringify({
        ...data,
        revoked: true,
        revokedAt: await this.timeMachineService.getCurrentTimestamp(),
        reason
      }),
      60 * 60 * 24 * 14 // 14일 유지
    );
  }
}
```

### 1.4 App Token 발급/검증

```typescript
async createAppToken(deviceId: string, permissions: string[]): Promise<string> {
  const key = await this.jwkService.getActiveKey();
  const now = await this.timeMachineService.getCurrentTimestamp();
  
  const payload = {
    sub: 'app-client',
    jti: uuidv4(),
    deviceId: await this.encryptionService.encrypt(deviceId),
    permissions,
    iat: now,
    exp: now + (24 * 60 * 60 * 1000) // 24시간 유효
  };
  
  const token = jwt.sign(payload, key.privateKey, {
    algorithm: 'RS256',
    header: {
      kid: key.id,
      typ: 'JWT'
    }
  });
  
  // 앱 토큰 메타데이터 저장
  await this.redisService.set(
    `token:app:${payload.jti}`,
    JSON.stringify({
      deviceId,
      exp: payload.exp,
      revoked: false
    }),
    60 * 60 * 24 // 24시간 캐시
  );
  
  return token;
}
```

## 2. 키 관리 구현

### 2.1 JWK 생성 및 관리

```typescript
@Injectable()
export class JWKService {
  constructor(
    @InjectRepository(JWKEntity)
    private readonly jwkRepository: Repository<JWKEntity>,
    private readonly configService: ConfigService
  ) {}

  async generateKey(): Promise<JWKEntity> {
    // RSA 키 생성
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    const keyId = uuidv4();
    
    // 키 저장
    const jwk = new JWKEntity();
    jwk.id = keyId;
    jwk.publicKey = publicKey;
    jwk.privateKey = privateKey;
    jwk.algorithm = 'RS256';
    jwk.status = 'ACTIVE';
    jwk.createdAt = new Date();
    jwk.expiresAt = new Date(Date.now() + (90 * 24 * 60 * 60 * 1000)); // 90일 후 만료
    
    return this.jwkRepository.save(jwk);
  }

  async getActiveKey(): Promise<JWKEntity> {
    const key = await this.jwkRepository.findOne({
      where: { status: 'ACTIVE' },
      order: { createdAt: 'DESC' }
    });
    
    if (!key) {
      throw new Error('No active key found');
    }
    
    return key;
  }

  async getKey(keyId: string): Promise<JWKEntity> {
    const key = await this.jwkRepository.findOne({
      where: { id: keyId }
    });
    
    if (!key) {
      throw new Error(`Key with ID ${keyId} not found`);
    }
    
    return key;
  }
}
```

### 2.2 키 로테이션

```typescript
@Injectable()
export class KeyRotationService {
  constructor(
    private readonly jwkService: JWKService,
    @InjectRepository(JWKEntity)
    private readonly jwkRepository: Repository<JWKEntity>
  ) {}

  @Cron('0 0 1 * *') // 매월 1일 00:00에 실행
  async rotateKeys(): Promise<void> {
    console.log('Starting key rotation');
    
    try {
      // 1. 새 키 생성
      const newKey = await this.jwkService.generateKey();
      console.log(`Generated new key: ${newKey.id}`);
      
      // 2. 기존 활성 키 상태 업데이트
      const activeKeys = await this.jwkRepository.find({
        where: { status: 'ACTIVE' }
      });
      
      for (const key of activeKeys) {
        if (key.id !== newKey.id) {
          key.status = 'DEPRECATED';
          await this.jwkRepository.save(key);
          console.log(`Marked key ${key.id} as DEPRECATED`);
        }
      }
      
      // 3. 오래된 만료 키 삭제
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
      
      await this.jwkRepository.delete({
        status: 'DEPRECATED',
        expiresAt: LessThan(oneYearAgo)
      });
      
      console.log('Key rotation completed successfully');
    } catch (error) {
      console.error('Key rotation failed', error);
    }
  }
}
```

## 3. 컨센트 토큰 관리 구현

### 3.1 동의 기반 권한 위임

```typescript
@Injectable()
export class ConsentService {
  constructor(
    private readonly jwkService: JWKService,
    private readonly encryptionService: EncryptionService,
    private readonly redisService: RedisService,
    @InjectRepository(ConsentTokenEntity)
    private readonly consentRepository: Repository<ConsentTokenEntity>,
    private readonly timeMachineService: TimeMachineService
  ) {}

  async createConsentToken(
    userId: string,
    scopes: string[],
    expiration: number
  ): Promise<string> {
    const key = await this.jwkService.getActiveKey();
    const now = await this.timeMachineService.getCurrentTimestamp();
    const tokenId = uuidv4();
    
    // 컨센트 토큰 페이로드
    const payload = {
      sub: userId,
      scopes,
      iat: now,
      exp: now + expiration,
      jti: tokenId
    };
    
    // 페이로드 암호화
    const encryptedPayload = await this.encryptionService.encrypt(
      JSON.stringify(payload)
    );
    
    // 컨센트 토큰 엔티티 저장
    const consentToken = new ConsentTokenEntity();
    consentToken.id = tokenId;
    consentToken.userId = userId;
    consentToken.scopes = scopes;
    consentToken.issuedAt = new Date(now);
    consentToken.expiresAt = new Date(now + expiration);
    consentToken.status = 'ACTIVE';
    
    await this.consentRepository.save(consentToken);
    
    // 암호화된 페이로드에 서명
    const token = jwt.sign(
      { data: encryptedPayload },
      key.privateKey,
      {
        algorithm: 'RS256',
        header: {
          kid: key.id,
          typ: 'JWT'
        }
      }
    );
    
    return token;
  }

  async verifyConsentToken(token: string): Promise<ConsentTokenPayload> {
    try {
      // 토큰 디코딩
      const decoded = jwt.decode(token, { complete: true }) as any;
      if (!decoded) throw new Error('Invalid token format');
      
      // 키 조회
      const key = await this.jwkService.getKey(decoded.header.kid);
      if (!key) throw new Error('Invalid key ID');
      
      // 서명 검증
      const verified = jwt.verify(token, key.publicKey, {
        algorithms: ['RS256']
      }) as any;
      
      // 암호화된 페이로드 복호화
      const decryptedPayload = await this.encryptionService.decrypt(verified.data);
      const payload = JSON.parse(decryptedPayload) as ConsentTokenPayload;
      
      // 토큰 상태 확인
      const consentToken = await this.consentRepository.findOne({
        where: { id: payload.jti }
      });
      
      if (!consentToken || consentToken.status !== 'ACTIVE') {
        throw new Error('Token is not active');
      }
      
      // 만료 시간 확인
      const now = await this.timeMachineService.getCurrentTimestamp();
      if (payload.exp < now) {
        throw new Error('Token has expired');
      }
      
      return payload;
    } catch (error) {
      throw new UnauthorizedException('Consent token validation failed');
    }
  }
}
```

### 3.2 범위 기반 접근 제어

```typescript
@Injectable()
export class ScopeGuard implements CanActivate {
  constructor(private readonly consentService: ConsentService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException();
    }
    
    try {
      // 토큰 검증
      const payload = await this.consentService.verifyConsentToken(token);
      
      // 필요한 스코프 조회
      const requiredScopes = this.getRequiredScopes(context);
      
      // 스코프 검증
      if (!this.hasRequiredScopes(payload.scopes, requiredScopes)) {
        throw new ForbiddenException('Insufficient permissions');
      }
      
      // 요청 객체에 페이로드 추가
      request.user = {
        userId: payload.sub,
        scopes: payload.scopes
      };
      
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const authHeader = request.headers.authorization;
    if (!authHeader) return undefined;
    
    const [type, token] = authHeader.split(' ');
    return type === 'Bearer' ? token : undefined;
  }

  private getRequiredScopes(context: ExecutionContext): string[] {
    const handler = context.getHandler();
    const scopes = Reflect.getMetadata('scopes', handler);
    return scopes || [];
  }

  private hasRequiredScopes(userScopes: string[], requiredScopes: string[]): boolean {
    return requiredScopes.every(scope => userScopes.includes(scope));
  }
}

// 사용 예시
@Controller('api/resource')
export class ResourceController {
  @Get()
  @SetMetadata('scopes', ['read:resource'])
  @UseGuards(ScopeGuard)
  getResource() {
    return { message: 'Protected resource' };
  }
}
```

## 4. 앱 인증 관리 구현

### 4.1 디바이스 ID 기반 인증

```typescript
@Injectable()
export class DeviceAuthService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly encryptionService: EncryptionService,
    @InjectRepository(DeviceEntity)
    private readonly deviceRepository: Repository<DeviceEntity>
  ) {}

  async registerDevice(deviceId: string, appVersion: string): Promise<string> {
    // 디바이스 ID 검증
    if (!this.isValidDeviceId(deviceId)) {
      throw new BadRequestException('Invalid device ID');
    }
    
    // 디바이스 정보 저장/업데이트
    let device = await this.deviceRepository.findOne({
      where: { deviceId: await this.encryptionService.hash(deviceId) }
    });
    
    if (!device) {
      device = new DeviceEntity();
      device.deviceId = await this.encryptionService.hash(deviceId);
      device.createdAt = new Date();
    }
    
    device.lastSeen = new Date();
    device.appVersion = appVersion;
    
    await this.deviceRepository.save(device);
    
    // 앱 토큰 발급
    const permissions = ['read:terms', 'create:user', 'create:verification'];
    return this.tokenService.createAppToken(deviceId, permissions);
  }

  async authenticateDevice(token: string): Promise<DeviceInfo> {
    const payload = await this.tokenService.verifyAppToken(token);
    
    // 디바이스 정보 조회
    const deviceId = await this.encryptionService.decrypt(payload.deviceId);
    const device = await this.deviceRepository.findOne({
      where: { deviceId: await this.encryptionService.hash(deviceId) }
    });
    
    if (!device) {
      throw new UnauthorizedException('Device not found');
    }
    
    // 마지막 활동 시간 업데이트
    device.lastSeen = new Date();
    await this.deviceRepository.save(device);
    
    return {
      deviceId,
      permissions: payload.permissions,
      appVersion: device.appVersion
    };
  }

  private isValidDeviceId(deviceId: string): boolean {
    // 디바이스 ID 형식 검증 로직
    return /^[a-zA-Z0-9-]{36}$/.test(deviceId);
  }
}
```

### 4.2 앱 권한 관리

```typescript
@Injectable()
export class AppPermissionService {
  constructor(
    @InjectRepository(AppPermissionEntity)
    private readonly permissionRepository: Repository<AppPermissionEntity>
  ) {}

  async getAppPermissions(appVersion: string): Promise<string[]> {
    // 앱 버전별 기본 권한 조회
    const permissions = await this.permissionRepository.find({
      where: { appVersion }
    });
    
    if (permissions.length === 0) {
      // 기본 권한 설정
      return ['read:terms', 'create:user', 'create:verification'];
    }
    
    return permissions.map(p => p.permission);
  }

  async updateAppPermissions(appVersion: string, permissions: string[]): Promise<void> {
    // 트랜잭션으로 권한 업데이트
    await this.permissionRepository.manager.transaction(async manager => {
      // 기존 권한 삭제
      await manager.delete(AppPermissionEntity, { appVersion });
      
      // 새 권한 추가
      for (const permission of permissions) {
        const entity = new AppPermissionEntity();
        entity.appVersion = appVersion;
        entity.permission = permission;
        await manager.save(entity);
      }
    });
  }
}
```

## 5. 에러 처리

```typescript
// 커스텀 에러 정의
export class TokenError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'TokenError';
  }
}

// 에러 처리 필터
@Catch(TokenError)
export class TokenErrorFilter implements ExceptionFilter {
  catch(exception: TokenError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    let statusCode = 500;
    
    // 에러 코드에 따른 HTTP 상태 코드 매핑
    switch (exception.code) {
      case 'TOKEN_EXPIRED':
        statusCode = 401;
        break;
      case 'TOKEN_INVALID':
        statusCode = 401;
        break;
      case 'INSUFFICIENT_SCOPE':
        statusCode = 403;
        break;
      case 'TOKEN_NOT_FOUND':
        statusCode = 404;
        break;
      case 'INVALID_REQUEST':
        statusCode = 400;
        break;
    }
    
    response.status(statusCode).json({
      status: statusCode,
      code: exception.code,
      message: exception.message,
      detail: exception.details
    });
  }
}
```

## 6. 로깅 및 모니터링

```typescript
@Injectable()
export class AuthLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('AuthService');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, headers, ip } = request;
    
    const userAgent = headers['user-agent'] || 'unknown';
    
    // 요청 로깅
    this.logger.log(`Request ${method} ${url} from ${ip} - UA: ${userAgent}`);
    
    const startTime = Date.now();
    
    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          // 응답 로깅
          this.logger.log(`Response ${method} ${url} - ${duration}ms`);
          
          // 지표 기록
          this.recordMetrics(method, url, duration, 200);
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          // 에러 로깅
          this.logger.error(
            `Error ${method} ${url} - ${error.message}`,
            error.stack
          );
          
          // 에러 지표 기록
          this.recordMetrics(
            method,
            url,
            duration,
            error.status || 500
          );
        }
      })
    );
  }

  private recordMetrics(
    method: string,
    url: string,
    duration: number,
    statusCode: number
  ): void {
    // 프로메테우스 등의 모니터링 시스템에 지표 기록
    // 구현은 monitoring.md 문서 참조
  }
}
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-18 | bok@weltcorp.com | 최초 작성 | 