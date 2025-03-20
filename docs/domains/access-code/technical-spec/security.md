# 접근 코드 보안 및 암호화 기술 명세

## 1. 암호화 전략

### 1.1 코드 암호화
```typescript
class CodeEncryption {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  private readonly ivLength = 12;
  private readonly tagLength = 16;
  
  constructor(
    private readonly encryptionKey: Buffer,
    private readonly keyRotationPeriod: number = 30 * 24 * 60 * 60 // 30일
  ) {}
  
  async encrypt(code: string): Promise<EncryptedCode> {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(code, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      version: 1
    };
  }
  
  async decrypt(encryptedCode: EncryptedCode): Promise<string> {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.encryptionKey,
      Buffer.from(encryptedCode.iv, 'base64')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedCode.tag, 'base64'));
    
    return Buffer.concat([
      decipher.update(Buffer.from(encryptedCode.encrypted, 'base64')),
      decipher.final()
    ]).toString('utf8');
  }
}
```

### 1.2 키 관리
```typescript
interface EncryptionKey {
  id: string;
  key: Buffer;
  createdAt: Date;
  expiresAt: Date;
  status: 'ACTIVE' | 'ROTATING' | 'EXPIRED';
}

class KeyManager {
  private readonly vault: KeyVaultService;
  
  async rotateKey(): Promise<void> {
    const newKey = await this.generateKey();
    await this.vault.storeKey(newKey);
    await this.markKeyForRotation(this.currentKey.id);
    await this.reEncryptCodes(this.currentKey.id, newKey.id);
  }
  
  private async generateKey(): Promise<EncryptionKey> {
    return {
      id: uuidv4(),
      key: crypto.randomBytes(32),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000), // 60일
      status: 'ACTIVE'
    };
  }
}
```

## 2. 접근 제어

### 2.1 인증 미들웨어
```typescript
@Injectable()
class AccessCodeAuthGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService
  ) {}
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException();
    }
    
    try {
      const payload = await this.authService.verifyToken(token);
      request.user = await this.userService.findById(payload.sub);
      return this.hasRequiredPermissions(request.user, request.method);
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}
```

### 2.2 권한 검증
```typescript
class PermissionChecker {
  private readonly requiredPermissions = {
    generateCode: ['access-code:generate'],
    validateCode: ['access-code:validate'],
    revokeCode: ['access-code:revoke'],
    viewHistory: ['access-code:history:view']
  };
  
  hasPermission(user: User, action: string): boolean {
    const required = this.requiredPermissions[action];
    return required.every(permission => user.permissions.includes(permission));
  }
}
```

## 3. 입력 검증

### 3.1 DTO 검증
```typescript
class GenerateCodeDto {
  @IsString()
  @Length(1, 100)
  userId: string;
  
  @IsEnum(CodeType)
  type: CodeType;
  
  @IsInt()
  @Min(1)
  @Max(100)
  maxUsageCount: number;
  
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

class ValidateCodeDto {
  @IsString()
  @Matches(/^[A-Z2-9]{6,12}$/)
  code: string;
  
  @IsString()
  @Length(1, 100)
  userId: string;
}
```

### 3.2 요청 검증 파이프
```typescript
@Injectable()
class CodeValidationPipe implements PipeTransform {
  async transform(value: any, metadata: ArgumentMetadata) {
    if (!this.toValidate(metadata)) {
      return value;
    }
    
    const errors = await validate(value);
    if (errors.length > 0) {
      throw new BadRequestException({
        message: 'Validation failed',
        errors: this.formatErrors(errors)
      });
    }
    
    return value;
  }
}
```

## 4. 보안 모니터링

### 4.1 보안 이벤트 로깅
```typescript
interface SecurityEvent {
  eventType: 'AUTH_FAILURE' | 'INVALID_CODE' | 'BRUTE_FORCE_ATTEMPT' | 'KEY_ROTATION';
  timestamp: Date;
  userId?: string;
  ipAddress: string;
  userAgent?: string;
  details: Record<string, unknown>;
}

class SecurityLogger {
  async logEvent(event: SecurityEvent): Promise<void> {
    await this.logService.log('security', {
      ...event,
      environment: process.env.NODE_ENV,
      service: 'access-code'
    });
  }
}
```

### 4.2 이상 탐지
```typescript
class AnomalyDetector {
  private readonly THRESHOLDS = {
    FAILED_ATTEMPTS_PER_IP: 10,
    FAILED_ATTEMPTS_PER_USER: 5,
    FAILED_ATTEMPTS_PER_CODE: 5,
    SUSPICIOUS_IP_THRESHOLD: 100
  };
  
  async detectAnomalies(): Promise<void> {
    await Promise.all([
      this.checkFailedAttempts(),
      this.checkSuspiciousIPs(),
      this.checkUnusualPatterns()
    ]);
  }
}
```

## 5. 데이터 보호

### 5.1 민감 데이터 처리
```typescript
class SensitiveDataHandler {
  private readonly sensitiveFields = ['ipAddress', 'userAgent', 'deviceInfo'];
  
  maskSensitiveData(data: Record<string, any>): Record<string, any> {
    const masked = { ...data };
    for (const field of this.sensitiveFields) {
      if (masked[field]) {
        masked[field] = this.mask(masked[field]);
      }
    }
    return masked;
  }
  
  private mask(value: string): string {
    if (typeof value !== 'string') return value;
    return value.substring(0, 3) + '***' + value.slice(-3);
  }
}
```

### 5.2 데이터 보존 정책
```typescript
class DataRetentionPolicy {
  private readonly retentionPeriods = {
    accessCodes: 90 * 24 * 60 * 60, // 90일
    usageHistory: 365 * 24 * 60 * 60, // 1년
    securityEvents: 730 * 24 * 60 * 60 // 2년
  };
  
  @Cron('0 0 * * *') // 매일 자정
  async cleanupExpiredData(): Promise<void> {
    const now = new Date();
    
    await Promise.all([
      this.cleanupCodes(now),
      this.cleanupHistory(now),
      this.cleanupEvents(now)
    ]);
  }
}
```

## 6. 데이터 보안 규정 준수

### 6.1 데이터 호스팅 위치
- DiGA 및 GDPR 규제 준수를 위한 독일 리전 사용
  - PostgreSQL 데이터베이스: europe-west3(프랑크푸르트) 리전 설정
    - 액세스 코드 데이터, 코드 사용 이력, 코드 할당 정보 등 저장
    - 개인식별정보와 연결될 수 있는 데이터에 대한 보호 강화
    - 백업 및 복제본도 동일 리전 내에서만 유지
  - Redis(Memorystore): europe-west3 리전 인스턴스 사용
    - 액세스 코드 캐싱, 만료 관리 등에 활용
    - 임시 데이터지만 개인정보 연관성 고려하여 독일 리전 필수
  - 데이터 처리 작업의 지역적 제한
    - 코드 생성 및 검증 처리는 독일 리전 내에서만 수행
    - 국경 간 데이터 이전 방지 메커니즘 구현
- 리전 구성 검증
  - 인프라 배포 시 리전 설정 자동 검증
  - 정기적인 규정 준수 감사 수행
  - 규정 위반 시 즉시 시정 조치 및 보고

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |