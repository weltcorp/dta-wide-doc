# 공통 로깅 명세

## 1. 개요
본 문서는 시스템 전반에 걸쳐 일관된 로깅을 구현하기 위한 표준과 가이드라인을 제공합니다. 모든 도메인은 이 로깅 형식을 준수하여 로그를 생성하고 관리해야 합니다.

## 2. 로그 레벨 정의

### 2.1 표준 로그 레벨
- **ERROR**: 시스템 오류, 데이터 정합성 오류, 심각한 보안 위반, 서비스 중단이 필요한
 경우
- **WARN**: 비즈니스 규칙 위반, 중복 작업 시도, 권한 검증 실패, 성능 저하
- **INFO**: 정상적인 작업(생성, 수정, 조회), 상태 변경, 사용자 로그인/로그아웃
- **DEBUG**: 상세 실행 정보, 캐시 동작, 권한 검증 세부 과정, 개발 및 디버깅용 상세 정보
- **TRACE**: 매우 상세한 진단 정보, 데이터 흐름 추적, 성능 프로파일링

### 2.2 로그 레벨 사용 지침
- 프로덕션 환경: ERROR, WARN, INFO 레벨만 활성화
- 스테이징 환경: ERROR, WARN, INFO, DEBUG 레벨 활성화
- 개발 환경: 모든 레벨 활성화
- 성능 테스트: 필요시 TRACE 레벨 선택적 활성화

## 3. 표준 로그 포맷

### 3.1 기본 로그 구조
```typescript
interface StandardLog {
  // 필수 필드
  timestamp: string;          // ISO 8601 형식 (YYYY-MM-DDTHH:mm:ss.sssZ)
  level: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  service: string;            // 서비스/도메인 이름 (예: 'user', 'auth', 'cycle')
  event: string;              // 이벤트 유형 (예: 'USER_CREATED', 'LOGIN_FAILED')
  message: string;            // 로그 메시지
  
  // 조건부 필수 필드
  user_id?: string;           // 사용자 ID (인증된 요청의 경우 필수)
  
  // 선택적 필드
  correlation_id?: string;    // 요청 추적을 위한 고유 식별자
  request_id?: string;        // 단일 요청 식별자
  trace_id?: string;          // 분산 추적을 위한 식별자
  span_id?: string;           // 분산 추적 스팬 식별자
  resource_id?: string;       // 리소스 식별자 (예: cycle_id, access_code_id)
  resource_type?: string;     // 리소스 유형 (예: 'cycle', 'access_code')
  site_id?: string;           // 사이트 식별자
  
  // 에러 정보 (에러 발생 시)
  error?: {
    code: string;             // 에러 코드
    message: string;          // 에러 메시지
    stack?: string;           // 스택 트레이스 (개발/스테이징 환경만)
    original?: any;           // 원본 에러 객체 (민감 정보 제외)
  };
  
  // 보안 관련 정보 (보안 이벤트의 경우)
  security?: {
    role?: string;            // 사용자 역할
    permission?: string;      // 관련 권한
    action?: string;          // 수행 작업
    resource?: string;        // 대상 리소스
    result?: string;          // 권한 검증 결과
    ip_address?: string;      // 요청 IP 주소
    user_agent?: string;      // 사용자 에이전트
  };
  
  // 성능 측정 (성능 모니터링의 경우)
  performance?: {
    duration_ms?: number;     // 작업 소요 시간 (밀리초)
    db_query_count?: number;  // 데이터베이스 쿼리 수
    cache_hit?: boolean;      // 캐시 히트 여부
    memory_usage_mb?: number; // 메모리 사용량 (MB)
  };
  
  // 추가 메타데이터
  metadata?: Record<string, any>; // 추가 정보 (구조화된 객체)
}
```

### 3.2 포맷 사용 예시
```typescript
// 사용자 로그인 성공
logger.info({
  event: 'USER_LOGIN',
  message: '사용자 로그인 성공',
  user_id: 'user123',
  correlation_id: 'corr-456',
  security: {
    role: 'USER',
    ip_address: '192.168.1.1',
    user_agent: 'Mozilla/5.0'
  },
  performance: {
    duration_ms: 120
  }
});

// 주기 상태 변경
logger.info({
  event: 'CYCLE_STATUS_CHANGED',
  message: '주기 상태가 변경되었습니다',
  user_id: 'user123',
  resource_id: 'cycle456',
  resource_type: 'cycle',
  site_id: 'site789',
  metadata: {
    from_status: 'PENDING',
    to_status: 'ACTIVE',
    reason: 'user_request'
  }
});

// 권한 검증 실패
logger.warn({
  event: 'PERMISSION_CHECK_FAILED',
  message: '사용자가 주기 상태 변경 권한이 없습니다',
  user_id: 'user123',
  resource_id: 'cycle456',
  resource_type: 'cycle',
  site_id: 'site789',
  security: {
    role: 'USER',
    permission: 'CYCLE_CHANGE_STATUS',
    action: 'update',
    resource: 'cycle',
    result: 'denied'
  }
});

// 시스템 오류
logger.error({
  event: 'DATABASE_CONNECTION_ERROR',
  message: '데이터베이스 연결 실패',
  correlation_id: 'corr-789',
  error: {
    code: 'DB_CONN_ERROR',
    message: '데이터베이스 연결 시간 초과',
    stack: error.stack
  },
  performance: {
    duration_ms: 5000
  }
});
```

## 4. 로깅 구현 가이드라인

### 4.1 로깅 미들웨어
각 도메인은 다음과 같은 기능을 제공하는 로깅 미들웨어를 구현해야 합니다:

```typescript
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(
    private readonly logger: LoggerService,
    private readonly configService: ConfigService
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, headers, body, user } = request;
    const userAgent = headers['user-agent'] || 'unknown';
    const ip = request.ip || 'unknown';
    const correlationId = headers['x-correlation-id'] || uuidv4();
    
    // 요청 로그
    this.logger.log({
      level: 'info',
      event: 'API_REQUEST',
      message: `${method} ${url}`,
      correlation_id: correlationId,
      user_id: user?.id,
      security: {
        ip_address: ip,
        user_agent: userAgent
      },
      metadata: {
        method,
        url,
        body: this.sanitizeBody(body)
      }
    });
    
    const startTime = Date.now();
    
    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          
          // 응답 로그
          this.logger.log({
            level: 'info',
            event: 'API_RESPONSE',
            message: `${method} ${url} - ${duration}ms`,
            correlation_id: correlationId,
            user_id: user?.id,
            performance: {
              duration_ms: duration
            },
            metadata: {
              status: 200,
              response: this.sanitizeResponse(data)
            }
          });
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          
          // 에러 로그
          this.logger.log({
            level: 'error',
            event: 'API_ERROR',
            message: `Error processing ${method} ${url}: ${error.message}`,
            correlation_id: correlationId,
            user_id: user?.id,
            error: {
              code: error.code || 'INTERNAL_ERROR',
              message: error.message,
              stack: this.shouldIncludeStack() ? error.stack : undefined
            },
            performance: {
              duration_ms: duration
            },
            metadata: {
              status: error.status || 500
            }
          });
        }
      })
    );
  }
  
  private sanitizeBody(body: any): any {
    if (!body) return undefined;
    
    // 민감 정보 제거
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'creditCard'];
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '***REDACTED***';
      }
    });
    
    return sanitized;
  }
  
  private sanitizeResponse(data: any): any {
    if (!data || typeof data !== 'object') return data;
    
    // 응답 크기 제한
    const maxResponseSize = this.configService.get('logging.maxResponseSize', 1024);
    const serialized = JSON.stringify(data);
    
    if (serialized.length > maxResponseSize) {
      return {
        _truncated: true,
        _size: serialized.length,
        _preview: serialized.substring(0, 100) + '...'
      };
    }
    
    return data;
  }
  
  private shouldIncludeStack(): boolean {
    const env = this.configService.get('app.environment', 'development');
    return env !== 'production';
  }
}
```

### 4.2 로그 중앙화
모든 도메인의 로그는 다음과 같은 방식으로 중앙화되어야 합니다:

1. 각 도메인 서비스에서 생성된 로그는 표준 포맷으로 JSON 형태로 출력
2. 로그 수집기(예: Fluentd, Filebeat)가 로그 파일 수집
3. 로그 처리 파이프라인(예: Logstash)에서 필요한 변환 및 보강
4. 중앙 로그 저장소(예: Elasticsearch)에 저장
5. 시각화 도구(예: Kibana)를 통해 로그 분석 및 모니터링

## 5. 로그 쿼리 및 분석

### 5.1 표준 쿼리 패턴
```
// 특정 사용자의 활동 조회
user_id:"user123" AND level:info

// 특정 리소스에 대한 모든 변경 조회
resource_id:"cycle456" AND event:*CHANGED

// 권한 관련 이슈 조회
event:PERMISSION* AND level:(warn OR error)

// 성능 문제 조회
performance.duration_ms:>1000 AND level:warn

// 특정 상관 관계 ID의 전체 요청 추적
correlation_id:"corr-456"
```

### 5.2 대시보드 구성
모든 도메인에 공통으로 적용할 수 있는 대시보드 구성:

1. **시스템 건강 상태**
   - 오류율
   - 성능 지표 (응답 시간)
   - 로그 레벨별 분포

2. **보안 모니터링**
   - 권한 검증 실패
   - 인증 실패
   - 비정상 접근 패턴

3. **사용자 활동**
   - 사용자별 활동 로그
   - 주요 기능 사용 현황
   - 오류 경험 사용자

### 5.3 알림 구성
다음과 같은 기준으로 알림을 구성해야 합니다:

1. **긴급 알림** (즉시 대응 필요)
   - 다수의 ERROR 레벨 로그 발생
   - 주요 보안 위반 이벤트
   - 지속적인 성능 저하

2. **경고 알림** (주의 필요)
   - WARN 레벨 로그 빈도 증가
   - 특정 패턴의 오류 반복
   - 성능 임계값 초과

## 6. 로그 보존 정책

### 6.1 로그 보존 기간
- **운영 로그**
  - ERROR: 12개월
  - WARN: 6개월
  - INFO: 3개월
  - DEBUG: 2주
  - TRACE: 1주

- **보안 관련 로그**
  - 모든 레벨: 24개월 (규정 준수 요구사항에 따라 조정)

- **성능 로그**
  - 집계 데이터: 12개월
  - 원시 데이터: 1개월

### 6.2 데이터 보호 및 규정 준수
- 개인 식별 정보(PII)는 암호화 또는 마스킹 처리
- GDPR 및 업계 규정에 따른 접근 제어
- 로그 데이터 파기 프로세스 자동화

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-20 | bok@weltcorp.com | 최초 작성 |