# 시간 관리 기술 명세서

## 1. TimeMachine 서비스 구조

### 1.1 TimeMachine 서비스 인터페이스
```typescript
@Injectable()
export class TimeMachineService {
  constructor(
    private readonly configService: ConfigService,
    private readonly redisService: RedisService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async getCurrentDate(): Promise<Date> {
    // 구현 세부사항
  }

  async getCurrentTimestamp(): Promise<number> {
    // 구현 세부사항
  }

  async setCurrentTime(timestamp: number): Promise<void> {
    // 구현 세부사항
  }

  async resetTime(): Promise<void> {
    // 구현 세부사항
  }
}
```

### 1.2 시간 관리 DTO
```typescript
export class TimeOffsetDto {
  @ApiProperty()
  @IsNumber()
  offsetMilliseconds: number;

  @ApiProperty()
  @IsString()
  @IsOptional()
  reason?: string;
}

export class CurrentTimeDto {
  @ApiProperty()
  timestamp: number;

  @ApiProperty()
  isoString: string;

  @ApiProperty()
  offset: number;
}
```

## 2. 시간 관리 구현

### 2.1 현재 시간 조회
```typescript
@Injectable()
export class TimeMachineService {
  private readonly REDIS_KEY = 'time-machine:offset';

  async getCurrentDate(): Promise<Date> {
    const offset = await this.getTimeOffset();
    return new Date(Date.now() + offset);
  }

  async getCurrentTimestamp(): Promise<number> {
    const offset = await this.getTimeOffset();
    return Date.now() + offset;
  }

  private async getTimeOffset(): Promise<number> {
    const offset = await this.redisService.get<number>(this.REDIS_KEY);
    return offset || 0;
  }
}
```

### 2.2 시간 조작
```typescript
@Injectable()
export class TimeMachineService {
  async setCurrentTime(timestamp: number): Promise<void> {
    const now = Date.now();
    const offset = timestamp - now;

    await this.redisService.set(this.REDIS_KEY, offset);

    this.eventEmitter.emit('time-machine.time-changed', {
      timestamp,
      offset,
      previousOffset: await this.getTimeOffset(),
    });
  }

  async resetTime(): Promise<void> {
    await this.redisService.del(this.REDIS_KEY);

    this.eventEmitter.emit('time-machine.time-reset', {
      timestamp: Date.now(),
    });
  }
}
```

## 3. 토큰 만료 시간 관리

### 3.1 토큰 만료 시간 계산
```typescript
@Injectable()
export class TokenExpirationService {
  constructor(
    private readonly timeMachineService: TimeMachineService,
  ) {}

  async calculateExpirationTime(durationMinutes: number): Promise<Date> {
    const now = await this.timeMachineService.getCurrentDate();
    return new Date(now.getTime() + durationMinutes * 60 * 1000);
  }

  async isTokenExpired(expirationTime: Date): Promise<boolean> {
    const now = await this.timeMachineService.getCurrentDate();
    return now >= expirationTime;
  }
}
```

### 3.2 토큰 갱신 관리
```typescript
@Injectable()
export class TokenRefreshManager {
  constructor(
    private readonly timeMachineService: TimeMachineService,
    private readonly tokenExpirationService: TokenExpirationService,
  ) {}

  async shouldRefreshToken(token: AuthToken): Promise<boolean> {
    const now = await this.timeMachineService.getCurrentDate();
    const expirationTime = new Date(token.expiresAt);
    
    // 만료 30분 전부터 갱신 허용
    const refreshWindow = 30 * 60 * 1000;
    return (expirationTime.getTime() - now.getTime()) <= refreshWindow;
  }

  async updateTokenExpiration(token: AuthToken): Promise<AuthToken> {
    const newExpiration = await this.tokenExpirationService
      .calculateExpirationTime(60); // 60분 유효

    return {
      ...token,
      expiresAt: newExpiration.toISOString(),
    };
  }
}
```

## 4. 세션 시간 관리

### 4.1 세션 만료 시간 관리
```typescript
@Injectable()
export class SessionTimeManager {
  constructor(
    private readonly timeMachineService: TimeMachineService,
  ) {}

  async calculateSessionExpiration(
    sessionDurationMinutes: number
  ): Promise<Date> {
    const now = await this.timeMachineService.getCurrentDate();
    return new Date(now.getTime() + sessionDurationMinutes * 60 * 1000);
  }

  async isSessionExpired(session: Session): Promise<boolean> {
    const now = await this.timeMachineService.getCurrentDate();
    return now >= new Date(session.expiresAt);
  }

  async extendSessionExpiration(
    session: Session,
    extensionMinutes: number
  ): Promise<Session> {
    const newExpiration = await this.calculateSessionExpiration(
      extensionMinutes
    );

    return {
      ...session,
      expiresAt: newExpiration.toISOString(),
    };
  }
}
```

### 4.2 세션 정리 작업
```typescript
@Injectable()
export class SessionCleanupService {
  constructor(
    private readonly timeMachineService: TimeMachineService,
    private readonly sessionRepository: SessionRepository,
  ) {}

  @Cron('0 */5 * * * *') // 5분마다 실행
  async cleanupExpiredSessions(): Promise<void> {
    const now = await this.timeMachineService.getCurrentDate();

    const expiredSessions = await this.sessionRepository
      .findExpiredSessions(now);

    for (const session of expiredSessions) {
      await this.sessionRepository.terminateSession(
        session.id,
        'EXPIRED'
      );
    }
  }
}
```

## 5. 보안 정책 시간 관리

### 5.1 비밀번호 만료 관리
```typescript
@Injectable()
export class PasswordExpirationManager {
  constructor(
    private readonly timeMachineService: TimeMachineService,
  ) {}

  async isPasswordExpired(
    passwordChangedAt: Date,
    expirationDays: number
  ): Promise<boolean> {
    const now = await this.timeMachineService.getCurrentDate();
    const expirationDate = new Date(passwordChangedAt);
    expirationDate.setDate(expirationDate.getDate() + expirationDays);

    return now >= expirationDate;
  }

  async calculateNextPasswordExpiration(
    expirationDays: number
  ): Promise<Date> {
    const now = await this.timeMachineService.getCurrentDate();
    const expirationDate = new Date(now);
    expirationDate.setDate(expirationDate.getDate() + expirationDays);

    return expirationDate;
  }
}
```

### 5.2 계정 잠금 관리
```typescript
@Injectable()
export class AccountLockManager {
  constructor(
    private readonly timeMachineService: TimeMachineService,
  ) {}

  async calculateLockExpiration(
    lockDurationMinutes: number
  ): Promise<Date> {
    const now = await this.timeMachineService.getCurrentDate();
    return new Date(now.getTime() + lockDurationMinutes * 60 * 1000);
  }

  async isAccountLocked(
    lockoutUntil: Date | null
  ): Promise<boolean> {
    if (!lockoutUntil) {
      return false;
    }

    const now = await this.timeMachineService.getCurrentDate();
    return now < lockoutUntil;
  }
}
```

## 6. 모니터링 및 로깅

### 6.1 시간 변경 로깅
```typescript
@Injectable()
export class TimeMachineLogger {
  constructor(
    private readonly logger: Logger,
  ) {}

  logTimeChange(
    oldTimestamp: number,
    newTimestamp: number,
    reason?: string
  ): void {
    this.logger.log({
      event: 'TIME_MACHINE_CHANGE',
      oldTimestamp,
      newTimestamp,
      offset: newTimestamp - oldTimestamp,
      reason,
      realTimestamp: Date.now(),
    });
  }
}
```

### 6.2 시간 관련 메트릭
```typescript
@Injectable()
export class TimeMachineMetrics {
  constructor(
    private readonly metricsService: MetricsService,
  ) {}

  recordTimeOffset(offsetMs: number): void {
    this.metricsService.setGauge(
      'time_machine_offset_ms',
      offsetMs
    );
  }

  recordTimeChange(): void {
    this.metricsService.incrementCounter(
      'time_machine_changes_total'
    );
  }
}
```

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |