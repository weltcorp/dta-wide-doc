# 접근 코드 모니터링 기술 명세

## 1. 메트릭 수집

### 1.1 비즈니스 메트릭
```typescript
class BusinessMetrics {
  private readonly metrics = {
    codesGenerated: new Counter('access_codes_generated_total', {
      help: '생성된 접근 코드의 총 수',
      labelNames: ['type', 'policy']
    }),
    
    codesValidated: new Counter('access_codes_validated_total', {
      help: '검증된 접근 코드의 총 수',
      labelNames: ['type', 'status']
    }),
    
    codesExpired: new Counter('access_codes_expired_total', {
      help: '만료된 접근 코드의 총 수',
      labelNames: ['type', 'reason']
    }),
    
    codeUsage: new Histogram('access_code_usage_count', {
      help: '접근 코드 사용 횟수 분포',
      labelNames: ['type'],
      buckets: [1, 2, 5, 10, 20, 50, 100]
    }),
    
    codeLifetime: new Histogram('access_code_lifetime_seconds', {
      help: '접근 코드 수명 분포',
      labelNames: ['type'],
      buckets: [300, 900, 1800, 3600, 7200, 14400, 28800, 86400]
    })
  };
  
  recordCodeGeneration(type: CodeType, policy: string): void {
    this.metrics.codesGenerated.inc({ type, policy });
  }
  
  recordCodeValidation(type: CodeType, status: CodeStatus): void {
    this.metrics.codesValidated.inc({ type, status });
  }
  
  recordCodeExpiration(type: CodeType, reason: string): void {
    this.metrics.codesExpired.inc({ type, reason });
  }
  
  recordCodeUsage(type: CodeType, usageCount: number): void {
    this.metrics.codeUsage.observe({ type }, usageCount);
  }
  
  recordCodeLifetime(type: CodeType, lifetimeSeconds: number): void {
    this.metrics.codeLifetime.observe({ type }, lifetimeSeconds);
  }
}
```

### 1.2 성능 메트릭
```typescript
class PerformanceMetrics {
  private readonly metrics = {
    requestDuration: new Histogram('access_code_request_duration_seconds', {
      help: 'API 요청 처리 시간',
      labelNames: ['operation', 'status'],
      buckets: [0.1, 0.3, 0.5, 1, 2, 5]
    }),
    
    databaseOperations: new Histogram('access_code_db_operation_duration_seconds', {
      help: '데이터베이스 작업 처리 시간',
      labelNames: ['operation'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1]
    }),
    
    cacheOperations: new Histogram('access_code_cache_operation_duration_seconds', {
      help: '캐시 작업 처리 시간',
      labelNames: ['operation', 'status'],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1]
    }),
    
    concurrentRequests: new Gauge('access_code_concurrent_requests', {
      help: '현재 처리 중인 동시 요청 수',
      labelNames: ['operation']
    })
  };
  
  recordRequestDuration(operation: string, status: number, duration: number): void {
    this.metrics.requestDuration.observe({ operation, status }, duration);
  }
  
  recordDatabaseOperation(operation: string, duration: number): void {
    this.metrics.databaseOperations.observe({ operation }, duration);
  }
  
  recordCacheOperation(
    operation: string,
    status: 'hit' | 'miss',
    duration: number
  ): void {
    this.metrics.cacheOperations.observe({ operation, status }, duration);
  }
  
  incrementConcurrentRequests(operation: string): void {
    this.metrics.concurrentRequests.inc({ operation });
  }
  
  decrementConcurrentRequests(operation: string): void {
    this.metrics.concurrentRequests.dec({ operation });
  }
}
```

## 2. 로깅

> **참고**: 모든 로깅은 [공통 로깅 표준](/docs/infrastructure/logging-standards.md)을 준수해야 합니다. 여기서는 액세스 코드와 관련된 주요 로깅 이벤트만 정의합니다.

### 2.1 주요 로깅 이벤트
```typescript
// 액세스 코드 생성
logger.info({
  event: 'ACCESS_CODE_GENERATED',
  code_id: string,
  user_id: string,
  type: string,
  metadata: {
    policy_id: string,
    expiration: string, // ISO 날짜 형식
    max_usage: number
  }
});

// 액세스 코드 검증
logger.info({
  event: 'ACCESS_CODE_VALIDATED',
  code_id: string,
  user_id: string,
  result: 'success' | 'failure',
  metadata: {
    reason: string, // 실패 사유 (실패 시)
    usage_count: number,
    remaining_usage: number,
    client_ip: string
  }
});

// 액세스 코드 만료
logger.info({
  event: 'ACCESS_CODE_EXPIRED',
  code_id: string,
  user_id: string,
  reason: 'time_limit' | 'usage_limit' | 'manual',
  metadata: {
    total_usage: number,
    max_usage: number
  }
});

// 액세스 코드 오류
logger.error({
  event: 'ACCESS_CODE_ERROR',
  code_id: string,
  operation: string,
  error: {
    message: string,
    code: string,
    stack: string
  },
  metadata: {
    user_id: string,
    client_ip: string
  }
});
```

### 2.2 로깅 구현
```typescript
@Injectable()
class AccessCodeLoggerService {
  constructor(
    private readonly logger: LoggerService,
    private readonly auditService: AuditService
  ) {}

  logCodeGeneration(codeId: string, userId: string, type: string, metadata: any): void {
    // 공통 로깅 표준에 따라 로깅
    this.logger.info({
      event: 'ACCESS_CODE_GENERATED',
      code_id: codeId,
      user_id: userId,
      type,
      metadata
    });
    
    // 감사 서비스로 이벤트 전송
    this.auditService.log({
      domain: 'ACCESS_CODE',
      component: 'CodeManagement',
      action: 'GENERATE',
      actor_id: userId,
      resource_id: codeId,
      metadata
    });
  }
}
```

## 3. 알림

### 3.1 알림 규칙
```typescript
interface AlertRule {
  name: string;
  description: string;
  condition: (metrics: any) => boolean;
  severity: 'info' | 'warning' | 'critical';
  cooldown: number;
}

const alertRules: AlertRule[] = [
  {
    name: 'high-error-rate',
    description: '높은 오류율 감지',
    condition: (metrics) => metrics.errorRate > 0.05,
    severity: 'critical',
    cooldown: 300 // 5분
  },
  {
    name: 'high-latency',
    description: '높은 지연 시간 감지',
    condition: (metrics) => metrics.p95Latency > 2000,
    severity: 'warning',
    cooldown: 600 // 10분
  },
  {
    name: 'cache-miss-rate',
    description: '높은 캐시 미스율 감지',
    condition: (metrics) => metrics.cacheMissRate > 0.3,
    severity: 'warning',
    cooldown: 900 // 15분
  }
];
```

### 3.2 알림 관리자
```typescript
class AlertManager {
  private readonly alertHistory = new Map<string, Date>();
  
  async checkAlerts(): Promise<void> {
    const metrics = await this.collectMetrics();
    
    for (const rule of alertRules) {
      if (this.shouldCheckRule(rule)) {
        if (rule.condition(metrics)) {
          await this.sendAlert(rule, metrics);
          this.updateAlertHistory(rule);
        }
      }
    }
  }
  
  private shouldCheckRule(rule: AlertRule): boolean {
    const lastAlert = this.alertHistory.get(rule.name);
    if (!lastAlert) return true;
    
    const cooldownExpired = Date.now() - lastAlert.getTime() > rule.cooldown * 1000;
    return cooldownExpired;
  }
  
  private async sendAlert(rule: AlertRule, metrics: any): Promise<void> {
    const alert = {
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      timestamp: new Date().toISOString(),
      metrics: this.formatMetrics(metrics)
    };
    
    await this.notificationService.sendAlert(alert);
  }
}
```

## 4. 대시보드

### 4.1 메트릭 대시보드
```typescript
interface DashboardPanel {
  title: string;
  type: 'graph' | 'gauge' | 'table';
  metrics: string[];
  timeRange: {
    from: string;
    to: string;
  };
  refresh: number;
}

const dashboardPanels: DashboardPanel[] = [
  {
    title: '접근 코드 생성 및 사용',
    type: 'graph',
    metrics: [
      'access_codes_generated_total',
      'access_codes_validated_total',
      'access_codes_expired_total'
    ],
    timeRange: {
      from: 'now-24h',
      to: 'now'
    },
    refresh: 60 // 1분
  },
  {
    title: '성능 메트릭',
    type: 'graph',
    metrics: [
      'access_code_request_duration_seconds',
      'access_code_db_operation_duration_seconds',
      'access_code_cache_operation_duration_seconds'
    ],
    timeRange: {
      from: 'now-1h',
      to: 'now'
    },
    refresh: 30 // 30초
  }
];
```

### 4.2 로그 대시보드
```typescript
interface LogDashboard {
  panels: {
    title: string;
    query: string;
    visualization: 'table' | 'chart';
    fields: string[];
  }[];
}

const logDashboard: LogDashboard = {
  panels: [
    {
      title: '오류 로그',
      query: 'level:error AND service:access-code',
      visualization: 'table',
      fields: ['timestamp', 'operation', 'error.code', 'error.message']
    },
    {
      title: '코드 사용 패턴',
      query: 'operation:validate AND service:access-code',
      visualization: 'chart',
      fields: ['timestamp', 'userId', 'metadata.userAgent']
    }
  ]
};
```

## 5. 건강 검사

### 5.1 헬스체크 엔드포인트
```typescript
@Controller('health')
class HealthController {
  @Get()
  async check(): Promise<HealthCheckResult> {
    const checks = await Promise.all([
      this.checkDatabase(),
      this.checkCache(),
      this.checkNotificationService()
    ]);
    
    return {
      status: checks.every(check => check.status === 'up') ? 'up' : 'down',
      checks,
      timestamp: new Date().toISOString()
    };
  }
  
  @Get('liveness')
  async checkLiveness(): Promise<HealthCheckResult> {
    return {
      status: 'up',
      timestamp: new Date().toISOString()
    };
  }
  
  @Get('readiness')
  async checkReadiness(): Promise<HealthCheckResult> {
    const dependencies = await this.checkDependencies();
    return {
      status: dependencies.every(dep => dep.status === 'up') ? 'up' : 'down',
      dependencies,
      timestamp: new Date().toISOString()
    };
  }
}
```

### 5.2 자동 복구
```typescript
class SelfHealing {
  @Cron('*/5 * * * *') // 5분마다
  async performHealthCheck(): Promise<void> {
    const issues = await this.detectIssues();
    
    for (const issue of issues) {
      if (this.canAutoRecover(issue)) {
        await this.attemptRecovery(issue);
      } else {
        await this.escalateIssue(issue);
      }
    }
  }
  
  private async detectIssues(): Promise<Issue[]> {
    return [
      ...(await this.checkHighErrorRate()),
      ...(await this.checkHighLatency()),
      ...(await this.checkResourceUsage())
    ];
  }
  
  private canAutoRecover(issue: Issue): boolean {
    return issue.type in this.recoveryStrategies &&
      issue.severity !== 'critical';
  }
  
  private async attemptRecovery(issue: Issue): Promise<void> {
    const strategy = this.recoveryStrategies[issue.type];
    await strategy.execute(issue);
    await this.recordRecoveryAttempt(issue);
  }
}
```

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |