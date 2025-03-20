# 모니터링 기술 명세서

## 1. 메트릭 수집

### 1.1 인증 메트릭
```typescript
@Injectable()
export class AuthMetricsCollector {
  constructor(
    private readonly metricsService: MetricsService,
  ) {}

  // 로그인 시도 메트릭
  recordLoginAttempt(success: boolean, provider: string): void {
    this.metricsService.incrementCounter(
      'auth_login_attempts_total',
      { success: String(success), provider }
    );
  }

  // 로그인 처리 시간
  recordLoginDuration(durationMs: number, provider: string): void {
    this.metricsService.recordHistogram(
      'auth_login_duration_ms',
      durationMs,
      { provider }
    );
  }

  // 활성 세션 수
  recordActiveSessions(count: number): void {
    this.metricsService.setGauge(
      'auth_active_sessions',
      count
    );
  }

  // 토큰 검증 메트릭
  recordTokenValidation(success: boolean, type: string): void {
    this.metricsService.incrementCounter(
      'auth_token_validations_total',
      { success: String(success), type }
    );
  }
}
```

### 1.2 권한 메트릭
```typescript
@Injectable()
export class AuthorizationMetricsCollector {
  constructor(
    private readonly metricsService: MetricsService,
  ) {}

  // 권한 검사 메트릭
  recordPermissionCheck(
    resource: string,
    action: string,
    allowed: boolean
  ): void {
    this.metricsService.incrementCounter(
      'auth_permission_checks_total',
      { resource, action, allowed: String(allowed) }
    );
  }

  // 역할 할당 메트릭
  recordRoleAssignment(success: boolean): void {
    this.metricsService.incrementCounter(
      'auth_role_assignments_total',
      { success: String(success) }
    );
  }

  // 캐시 히트율
  recordCacheHitRate(hit: boolean): void {
    this.metricsService.incrementCounter(
      'auth_cache_operations_total',
      { type: hit ? 'hit' : 'miss' }
    );
  }
}
```

### 1.3 보안 메트릭
```typescript
@Injectable()
export class SecurityMetricsCollector {
  constructor(
    private readonly metricsService: MetricsService,
  ) {}

  // 로그인 실패 메트릭
  recordFailedLogin(reason: string): void {
    this.metricsService.incrementCounter(
      'auth_failed_logins_total',
      { reason }
    );
  }

  // 계정 잠금 메트릭
  recordAccountLock(reason: string): void {
    this.metricsService.incrementCounter(
      'auth_account_locks_total',
      { reason }
    );
  }

  // 의심스러운 활동 메트릭
  recordSuspiciousActivity(type: string): void {
    this.metricsService.incrementCounter(
      'auth_suspicious_activities_total',
      { type }
    );
  }
}
```

## 2. 로깅 구현

> **참고**: 모든 로깅은 [공통 로깅 표준](/docs/infrastructure/logging-standards.md)을 준수해야 합니다. 여기서는 인증 시스템과 관련된 주요 로깅 이벤트만 정의합니다.

### 2.1 주요 로깅 이벤트
```typescript
// 로그인 성공
logger.info({
  event: 'LOGIN_SUCCESS',
  user_id: string,
  metadata: {
    ip_address: string,
    user_agent: string,
    auth_method: string,
    service_id: 'auth'
  }
});

// 로그인 실패
logger.warn({
  event: 'LOGIN_FAILED',
  user_id: string,
  error: {
    code: string,
    message: string
  },
  metadata: {
    ip_address: string,
    user_agent: string,
    auth_method: string,
    attempt_count: number,
    service_id: 'auth'
  }
});

// 토큰 생성
logger.info({
  event: 'TOKEN_CREATED',
  user_id: string,
  token_id: string,
  token_type: 'ACCESS' | 'REFRESH' | 'ID',
  metadata: {
    expires_at: string,
    scopes: string[],
    service_id: 'auth'
  }
});

// 토큰 검증
logger.debug({
  event: 'TOKEN_VALIDATED',
  token_id: string,
  valid: boolean,
  metadata: {
    ip_address: string,
    service_id: 'auth'
  }
});

// 보안 이벤트
logger.warn({
  event: 'SECURITY_EVENT',
  user_id: string,
  security_event_type: string,
  metadata: {
    ip_address: string,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    service_id: 'auth'
  }
});
```

### 2.2 로깅 서비스 구현
```typescript
@Injectable()
export class AuthLoggerService {
  constructor(
    private readonly logger: LoggerService,
    private readonly auditService: AuditService
  ) {}

  logLoginSuccess(userId: string, metadata: Record<string, any>): void {
    // 공통 로깅 표준에 따라 로깅
    this.logger.info({
      event: 'LOGIN_SUCCESS',
      user_id: userId,
      metadata: {
        ...metadata,
        service_id: 'auth'
      }
    });
    
    // 감사 서비스로 이벤트 전송
    this.auditService.log({
      domain: 'AUTH',
      component: 'Authentication',
      action: 'LOGIN',
      actor_id: userId,
      resource_id: userId,
      metadata
    });
  }
  
  logSecurityEvent(userId: string, eventType: string, metadata: Record<string, any>): void {
    // 공통 로깅 표준에 따라 로깅
    this.logger.warn({
      event: 'SECURITY_EVENT',
      user_id: userId,
      security_event_type: eventType,
      metadata: {
        ...metadata,
        service_id: 'auth'
      }
    });
    
    // 감사 서비스로 이벤트 전송
    this.auditService.log({
      domain: 'AUTH',
      component: 'Security',
      action: eventType,
      actor_id: userId,
      resource_id: userId,
      metadata: {
        ...metadata,
        severity: metadata.severity || 'MEDIUM'
      }
    });
  }
}
```

## 3. 알림 구현

### 3.1 알림 규칙
```typescript
interface AlertRule {
  name: string;
  condition: string;
  threshold: number;
  duration: string;
  severity: 'info' | 'warning' | 'critical';
}

const authAlertRules: AlertRule[] = [
  {
    name: 'high_login_failure_rate',
    condition: 'auth_failed_logins_total / auth_login_attempts_total > 0.1',
    threshold: 0.1,
    duration: '5m',
    severity: 'warning',
  },
  {
    name: 'high_error_rate',
    condition: 'rate(auth_errors_total[5m]) > 10',
    threshold: 10,
    duration: '5m',
    severity: 'critical',
  },
  {
    name: 'low_cache_hit_rate',
    condition: 'auth_cache_hit_rate < 0.8',
    threshold: 0.8,
    duration: '10m',
    severity: 'warning',
  },
];
```

### 3.2 알림 관리자
```typescript
@Injectable()
export class AlertManager {
  constructor(
    private readonly notificationService: NotificationService,
    private readonly metricsService: MetricsService,
  ) {}

  async checkAlertRules(): Promise<void> {
    for (const rule of authAlertRules) {
      const isTriggered = await this.evaluateRule(rule);
      if (isTriggered) {
        await this.sendAlert(rule);
      }
    }
  }

  private async evaluateRule(rule: AlertRule): Promise<boolean> {
    const value = await this.metricsService.evaluateQuery(rule.condition);
    return value > rule.threshold;
  }

  private async sendAlert(rule: AlertRule): Promise<void> {
    await this.notificationService.sendAlert({
      title: `Auth Alert: ${rule.name}`,
      message: `Alert rule "${rule.name}" has been triggered`,
      severity: rule.severity,
      timestamp: new Date(),
    });
  }
}
```

## 4. 대시보드 구성

### 4.1 메트릭 대시보드
```typescript
interface DashboardPanel {
  title: string;
  type: 'graph' | 'counter' | 'gauge' | 'table';
  metrics: string[];
  timeRange: string;
  refresh: string;
}

const authDashboardPanels: DashboardPanel[] = [
  {
    title: 'Login Success Rate',
    type: 'graph',
    metrics: [
      'rate(auth_login_attempts_total{success="true"}[5m])',
      'rate(auth_login_attempts_total{success="false"}[5m])',
    ],
    timeRange: '6h',
    refresh: '1m',
  },
  {
    title: 'Active Sessions',
    type: 'gauge',
    metrics: ['auth_active_sessions'],
    timeRange: 'now',
    refresh: '1m',
  },
  {
    title: 'Permission Checks',
    type: 'graph',
    metrics: [
      'rate(auth_permission_checks_total{allowed="true"}[5m])',
      'rate(auth_permission_checks_total{allowed="false"}[5m])',
    ],
    timeRange: '6h',
    refresh: '1m',
  },
];
```

### 4.2 로그 대시보드
```typescript
interface LogPanel {
  title: string;
  query: string;
  fields: string[];
  timeRange: string;
  refresh: string;
}

const authLogPanels: LogPanel[] = [
  {
    title: 'Authentication Errors',
    query: 'level:error AND service:auth',
    fields: ['timestamp', 'event', 'userId', 'error.message'],
    timeRange: '24h',
    refresh: '1m',
  },
  {
    title: 'Security Events',
    query: 'level:warn AND service:auth',
    fields: ['timestamp', 'event', 'userId', 'details'],
    timeRange: '24h',
    refresh: '1m',
  },
  {
    title: 'Failed Logins',
    query: 'event:LOGIN_FAILED',
    fields: ['timestamp', 'userId', 'ip', 'reason'],
    timeRange: '24h',
    refresh: '1m',
  },
];
```

## 5. 헬스 체크

### 5.1 헬스 체크 엔드포인트
```typescript
@Injectable()
export class AuthHealthCheck {
  constructor(
    private readonly sessionService: SessionService,
    private readonly cacheManager: CacheManager,
    private readonly tokenService: TokenService,
  ) {}

  @HealthCheck()
  async check(): Promise<HealthCheckResult> {
    const checks = await Promise.all([
      this.checkDatabase(),
      this.checkCache(),
      this.checkTokenService(),
    ]);

    return {
      status: checks.every(check => check.status === 'up') ? 'up' : 'down',
      checks: checks.reduce((acc, check) => ({
        ...acc,
        [check.name]: check,
      }), {}),
      timestamp: new Date(),
    };
  }

  private async checkDatabase(): Promise<HealthIndicatorResult> {
    try {
      await this.sessionService.ping();
      return {
        name: 'database',
        status: 'up',
      };
    } catch (error) {
      return {
        name: 'database',
        status: 'down',
        error: error.message,
      };
    }
  }
}
```

### 5.2 자동 복구
```typescript
@Injectable()
export class AuthSelfHealing {
  constructor(
    private readonly healthCheck: AuthHealthCheck,
    private readonly alertManager: AlertManager,
  ) {}

  @Cron('*/5 * * * *')
  async performHealthCheck(): Promise<void> {
    const health = await this.healthCheck.check();
    
    if (health.status === 'down') {
      await this.handleUnhealthyState(health);
    }
  }

  private async handleUnhealthyState(
    health: HealthCheckResult
  ): Promise<void> {
    const failedChecks = Object.entries(health.checks)
      .filter(([, check]) => check.status === 'down');

    for (const [name, check] of failedChecks) {
      await this.attemptRecovery(name, check);
    }
  }

  private async attemptRecovery(
    name: string,
    check: HealthIndicatorResult
  ): Promise<void> {
    switch (name) {
      case 'cache':
        await this.recoverCache();
        break;
      case 'database':
        await this.recoverDatabase();
        break;
      default:
        await this.alertManager.sendAlert({
          title: `Auth Recovery Failed: ${name}`,
          message: `Unable to automatically recover ${name}`,
          severity: 'critical',
        });
    }
  }
}
```

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |