# 보안 기술 명세서

## 1. 암호화 구현

### 1.1 비밀번호 해싱
```typescript
@Injectable()
export class PasswordHasher {
  private readonly SALT_ROUNDS = 12;

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async needsRehash(hash: string): Promise<boolean> {
    const info = await bcrypt.getRounds(hash);
    return info < this.SALT_ROUNDS;
  }
}
```

### 1.2 토큰 암호화
```typescript
@Injectable()
export class TokenEncryption {
  constructor(
    private readonly configService: ConfigService,
  ) {}

  async encrypt(payload: TokenPayload): Promise<string> {
    const key = await this.getEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(payload), 'utf8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
  }

  async decrypt(token: string): Promise<TokenPayload> {
    const key = await this.getEncryptionKey();
    const data = Buffer.from(token, 'base64');

    const iv = data.slice(0, 16);
    const authTag = data.slice(16, 32);
    const encryptedData = data.slice(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);

    return JSON.parse(decrypted.toString('utf8'));
  }
}
```

### 1.3 키 관리
```typescript
@Injectable()
export class KeyManager {
  constructor(
    private readonly keyRepository: KeyRepository,
    private readonly vaultService: VaultService,
  ) {}

  async generateKeyPair(): Promise<KeyPair> {
    const { publicKey, privateKey } = await generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    const kid = crypto.randomBytes(16).toString('hex');
    const encryptedPrivateKey = await this.vaultService.encrypt(privateKey);

    await this.keyRepository.save({
      kid,
      publicKey,
      encryptedPrivateKey,
      algorithm: 'RS256',
      status: 'active',
      createdAt: new Date(),
    });

    return { kid, publicKey, privateKey };
  }

  async rotateKeys(): Promise<void> {
    const activeKey = await this.keyRepository.findActive();
    if (this.shouldRotate(activeKey)) {
      await this.generateKeyPair();
      await this.deactivateKey(activeKey.kid);
    }
  }
}
```

## 2. 인증 보안

### 2.1 로그인 보안
```typescript
@Injectable()
export class LoginSecurity {
  constructor(
    private readonly securityPolicyService: SecurityPolicyService,
    private readonly rateLimiter: RateLimiter,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async validateLoginAttempt(
    email: string,
    ip: string
  ): Promise<ValidationResult> {
    // 1. IP 기반 속도 제한 확인
    const ipLimitExceeded = await this.rateLimiter.checkLimit(
      `login:ip:${ip}`,
      10,
      '1h'
    );
    if (ipLimitExceeded) {
      throw new TooManyRequestsException('IP rate limit exceeded');
    }

    // 2. 계정 기반 속도 제한 확인
    const accountLimitExceeded = await this.rateLimiter.checkLimit(
      `login:email:${email}`,
      5,
      '15m'
    );
    if (accountLimitExceeded) {
      throw new TooManyRequestsException('Account rate limit exceeded');
    }

    // 3. 의심스러운 IP 확인
    const isSuspiciousIp = await this.checkSuspiciousIp(ip);
    if (isSuspiciousIp) {
      this.eventEmitter.emit('security.suspicious_ip', { ip, email });
      return { requireMfa: true };
    }

    return { requireMfa: false };
  }

  async handleFailedLogin(
    email: string,
    ip: string
  ): Promise<void> {
    await Promise.all([
      this.rateLimiter.increment(`login:ip:${ip}`),
      this.rateLimiter.increment(`login:email:${email}`),
    ]);
  }
}
```

### 2.2 세션 보안
```typescript
@Injectable()
export class SessionSecurity {
  constructor(
    private readonly deviceFingerprintService: DeviceFingerprintService,
    private readonly geoIpService: GeoIpService,
  ) {}

  async validateSession(
    session: Session,
    context: RequestContext
  ): Promise<ValidationResult> {
    // 1. 디바이스 지문 검증
    const deviceMatch = await this.validateDeviceFingerprint(
      session.deviceInfo,
      context.deviceInfo
    );
    if (!deviceMatch) {
      throw new UnauthorizedException('Invalid device fingerprint');
    }

    // 2. IP 위치 검증
    const locationValid = await this.validateLocation(
      session.ipAddress,
      context.ip
    );
    if (!locationValid) {
      throw new UnauthorizedException('Suspicious location change');
    }

    // 3. 세션 수명 검증
    if (this.isSessionExpired(session)) {
      throw new UnauthorizedException('Session expired');
    }

    return { valid: true };
  }

  private async validateDeviceFingerprint(
    storedInfo: DeviceInfo,
    currentInfo: DeviceInfo
  ): Promise<boolean> {
    return this.deviceFingerprintService.compare(storedInfo, currentInfo);
  }
}
```

### 2.3 토큰 보안
```typescript
@Injectable()
export class TokenSecurity {
  constructor(
    private readonly keyManager: KeyManager,
    private readonly tokenBlacklist: TokenBlacklist,
  ) {}

  async signToken(payload: TokenPayload): Promise<string> {
    const activeKey = await this.keyManager.getActiveKey();
    return jwt.sign(payload, activeKey.privateKey, {
      algorithm: 'RS256',
      keyid: activeKey.kid,
      expiresIn: '1h',
    });
  }

  async verifyToken(token: string): Promise<TokenPayload> {
    // 1. 토큰 블랙리스트 확인
    const isBlacklisted = await this.tokenBlacklist.check(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // 2. 서명 검증
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw new UnauthorizedException('Invalid token format');
    }

    const key = await this.keyManager.getKey(decoded.header.kid);
    if (!key) {
      throw new UnauthorizedException('Invalid key identifier');
    }

    try {
      return jwt.verify(token, key.publicKey, {
        algorithms: ['RS256'],
      }) as TokenPayload;
    } catch (error) {
      throw new UnauthorizedException('Token verification failed');
    }
  }
}
```

## 3. 권한 보안

### 3.1 RBAC 구현
```typescript
@Injectable()
export class RbacService {
  constructor(
    private readonly roleHierarchyService: RoleHierarchyService,
    private readonly permissionRepository: PermissionRepository,
  ) {}

  async hasPermission(
    user: User,
    resource: string,
    action: string
  ): Promise<boolean> {
    // 1. 사용자 역할 확인
    const roles = await this.roleHierarchyService.getEffectiveRoles(user.roles);

    // 2. 역할별 권한 확인
    const permissions = await this.permissionRepository.findByRoles(roles);

    // 3. 권한 매칭
    return permissions.some(permission =>
      permission.resource === resource &&
      permission.action === action
    );
  }

  async validateRoleAssignment(
    role: Role,
    targetUser: User
  ): Promise<boolean> {
    // 1. 순환 참조 확인
    const hierarchy = await this.roleHierarchyService.getHierarchy();
    if (this.hasCircularDependency(role, targetUser, hierarchy)) {
      return false;
    }

    // 2. 권한 상속 규칙 확인
    return this.validateInheritanceRules(role, targetUser);
  }
}
```

### 3.2 권한 검증 미들웨어
```typescript
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly rbacService: RbacService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. 메타데이터에서 필요한 권한 조회
    const requiredPermissions = this.reflector.get<Permission[]>(
      'permissions',
      context.getHandler(),
    );

    if (!requiredPermissions) {
      return true;
    }

    // 2. 요청에서 사용자 정보 추출
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      return false;
    }

    // 3. 권한 검증
    return requiredPermissions.every(permission =>
      this.rbacService.hasPermission(
        user,
        permission.resource,
        permission.action,
      )
    );
  }
}
```

## 4. 데이터 보안

### 4.1 민감 정보 처리
```typescript
@Injectable()
export class SensitiveDataHandler {
  constructor(
    private readonly encryptionService: EncryptionService,
  ) {}

  async maskSensitiveData(data: any): Promise<any> {
    const sensitiveFields = ['password', 'ssn', 'creditCard'];
    
    return this.traverse(data, (key, value) => {
      if (sensitiveFields.includes(key)) {
        return this.mask(value);
      }
      return value;
    });
  }

  async encryptSensitiveData(data: any): Promise<any> {
    const sensitiveFields = ['ssn', 'creditCard'];
    
    return this.traverse(data, async (key, value) => {
      if (sensitiveFields.includes(key)) {
        return this.encryptionService.encrypt(value);
      }
      return value;
    });
  }

  private mask(value: string): string {
    if (!value) return value;
    const length = value.length;
    return '*'.repeat(Math.max(length - 4, 0)) + value.slice(-4);
  }
}
```

### 4.2 감사 로깅
```typescript
@Injectable()
export class SecurityAuditLogger {
  constructor(
    private readonly logger: Logger,
    private readonly sensitiveDataHandler: SensitiveDataHandler,
  ) {}

  async logSecurityEvent(
    event: string,
    data: any,
    user?: User
  ): Promise<void> {
    // 1. 민감 정보 마스킹
    const sanitizedData = await this.sensitiveDataHandler.maskSensitiveData(data);

    // 2. 로그 기록
    this.logger.log({
      event,
      data: sanitizedData,
      user: user ? {
        id: user.id,
        email: user.email,
      } : undefined,
      timestamp: new Date(),
      ip: this.getClientIp(),
    });
  }

  async logSecurityViolation(
    violation: string,
    data: any,
    user?: User
  ): Promise<void> {
    // 1. 민감 정보 마스킹
    const sanitizedData = await this.sensitiveDataHandler.maskSensitiveData(data);

    // 2. 위반 사항 기록
    this.logger.warn({
      violation,
      data: sanitizedData,
      user: user ? {
        id: user.id,
        email: user.email,
      } : undefined,
      timestamp: new Date(),
      ip: this.getClientIp(),
    });
  }
}
```

## 5. 보안 모니터링

### 5.1 보안 메트릭
```typescript
@Injectable()
export class SecurityMetrics {
  constructor(
    private readonly metricsService: MetricsService,
  ) {}

  recordLoginAttempt(success: boolean, reason?: string): void {
    this.metricsService.incrementCounter(
      'security_login_attempts_total',
      {
        success: String(success),
        reason: reason || 'none',
      }
    );
  }

  recordSecurityViolation(type: string): void {
    this.metricsService.incrementCounter(
      'security_violations_total',
      { type }
    );
  }

  recordTokenValidation(success: boolean): void {
    this.metricsService.incrementCounter(
      'security_token_validations_total',
      { success: String(success) }
    );
  }
}
```

### 5.2 보안 알림
```typescript
@Injectable()
export class SecurityAlertService {
  constructor(
    private readonly notificationService: NotificationService,
    private readonly securityMetrics: SecurityMetrics,
  ) {}

  async alertSecurityViolation(
    violation: SecurityViolation
  ): Promise<void> {
    // 1. 메트릭 기록
    this.securityMetrics.recordSecurityViolation(violation.type);

    // 2. 알림 발송
    await this.notificationService.sendAlert({
      level: 'critical',
      title: `Security Violation: ${violation.type}`,
      message: violation.message,
      metadata: {
        ip: violation.ip,
        userId: violation.userId,
        timestamp: new Date(),
      },
    });
  }

  async alertSuspiciousActivity(
    activity: SuspiciousActivity
  ): Promise<void> {
    // 1. 메트릭 기록
    this.securityMetrics.recordSuspiciousActivity(activity.type);

    // 2. 알림 발송
    await this.notificationService.sendAlert({
      level: 'warning',
      title: `Suspicious Activity: ${activity.type}`,
      message: activity.message,
      metadata: {
        ip: activity.ip,
        userId: activity.userId,
        timestamp: new Date(),
      },
    });
  }
}
```

## 6. 데이터 보안 규정 준수

### 6.1 데이터 호스팅 위치
- DiGA 및 GDPR 규제 준수를 위한 독일 리전 사용
  - PostgreSQL 데이터베이스: europe-west3(프랑크푸르트) 리전 설정
    - 사용자 인증 정보, 키 관리 데이터, 동의 이력 등 저장
    - 백업 및 복제본도 동일 리전 내에서만 유지
  - Redis(Memorystore): europe-west3 리전 인스턴스 사용
    - 토큰 블랙리스트, 세션 정보, 일시적 캐싱 데이터 저장
    - 개인식별정보 포함 가능성이 있어 독일 리전 필수
  - 데이터 처리 작업의 지역적 제한
    - 인증 및 인가 처리는 독일 리전 내에서만 수행
    - 국경 간 데이터 이전 방지 메커니즘 구현
- 리전 구성 검증
  - 인프라 배포 시 리전 설정 자동 검증
  - 정기적인 규정 준수 감사 수행
  - 규정 위반 시 즉시 시정 조치 및 보고

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | DiGA 및 GDPR 규제 준수를 위한 데이터 호스팅 위치 관련 내용 추가 |