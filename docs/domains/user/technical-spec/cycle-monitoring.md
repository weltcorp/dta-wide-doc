# 사용자 주기 모니터링 명세

## 1. 메트릭스 수집

### 1.1 API 메트릭스
```typescript
// API 요청 수
counter('cycle_api_requests_total', {
  method: string,    // HTTP 메서드
  path: string,      // API 경로
  status: number     // HTTP 상태 코드
})

// API 응답 시간
histogram('cycle_api_response_time_seconds', {
  method: string,    // HTTP 메서드
  path: string,      // API 경로
  status: number     // HTTP 상태 코드
})
```

### 1.2 비즈니스 메트릭스
```typescript
// 주기 상태별 카운트
gauge('cycle_status_count', {
  status: string,    // 주기 상태
  site_id: string    // 사이트 ID
})

// 주기 상태 변경 카운트
counter('cycle_status_changes_total', {
  from_status: string,   // 이전 상태
  to_status: string,     // 변경 상태
  site_id: string        // 사이트 ID
})

// 활성 주기 수
gauge('cycle_active_count', {
  site_id: string    // 사이트 ID
})
```

### 1.3 캐시 메트릭스
```typescript
// 캐시 히트율
gauge('cycle_cache_hit_ratio', {
  operation: string  // 조회 작업 유형
})

// 캐시 무효화 횟수
counter('cycle_cache_invalidations_total', {
  reason: string    // 무효화 사유
})
```

### 1.4 IAM 및 권한 메트릭스
```typescript
// 권한 검증 횟수
counter('cycle_permission_checks_total', {
  permission: string,     // 확인된 권한
  resource_type: string,  // 리소스 유형 (cycle, statistics 등)
  result: string,         // 'allowed' 또는 'denied'
  role: string            // 요청 사용자의 역할
})

// 권한 검증 응답 시간
histogram('cycle_permission_check_time_seconds', {
  permission: string,     // 확인된 권한
  result: string          // 'allowed' 또는 'denied'
})

// 권한 캐시 메트릭스
gauge('cycle_permission_cache_hit_ratio', {
  permission: string     // 확인된 권한
})

// 권한 위반 시도 횟수
counter('cycle_permission_violation_attempts_total', {
  permission: string,     // 시도된 권한
  user_role: string,      // 사용자 역할
  resource_type: string,  // 리소스 유형
  site_id: string         // 사이트 ID
})

// IAM 권한 변경 횟수
counter('cycle_iam_permission_changes_total', {
  operation: string,      // 'grant' 또는 'revoke'
  permission: string,     // 변경된 권한
  target_role: string     // 대상 역할
})
```

## 2. 로깅

> **참고**: 모든 로깅은 [공통 로깅 표준](/docs/infrastructure/logging-standards.md)을 준수해야 합니다. 여기서는 주기 모니터링과 관련된 주요 로깅 포인트만 정의합니다.

### 2.1 주요 로깅 포인트
```typescript
// 주기 생성
logger.info({
  event: 'CYCLE_CREATED',
  user_id: string,
  cycle_id: string,
  site_id: string,
  status: 'PENDING'
});

// 상태 변경
logger.info({
  event: 'CYCLE_STATUS_CHANGED',
  user_id: string,
  cycle_id: string,
  site_id: string,
  status: {
    from: string,
    to: string
  },
  reason: string
});

// 중복 주기 시도
logger.warn({
  event: 'DUPLICATE_CYCLE_ATTEMPT',
  user_id: string,
  site_id: string,
  period: {
    start: string,
    end: string
  }
});

// 권한 검증 실패
logger.warn({
  event: 'PERMISSION_CHECK_FAILED',
  user_id: string,
  security: {
    role: string,
    permission: string,
    action: string,
    resource: string,
    result: 'denied'
  },
  site_id: string,
  message: '사용자가 주기 상태 변경 권한이 없습니다'
});

// 권한 변경
logger.info({
  event: 'PERMISSION_CHANGED',
  user_id: string,
  security: {
    role: string,
    permission: string,
    action: 'grant', // 또는 'revoke'
    resource: 'cycle'
  },
  message: '사용자에게 주기 관리 권한이 부여되었습니다'
});

// 의심스러운 권한 사용
logger.warn({
  event: 'SUSPICIOUS_PERMISSION_USAGE',
  user_id: string,
  security: {
    role: string,
    permission: string,
    action: string,
    resource: string
  },
  site_id: string,
  message: '단시간에 다수의 주기 상태 변경 시도'
});
```

## 3. 알림 설정

### 3.1 시스템 알림
- 에러율이 임계치 초과 시 (5분 내 10% 이상)
- API 응답 시간이 임계치 초과 시 (P95 > 1초)
- 캐시 히트율이 임계치 미만 시 (1시간 평균 < 80%)
- 권한 검증 실패율이 높을 때 (5분 내 20% 이상)

### 3.2 비즈니스 알림
- 특정 사이트의 활성 주기 수가 급격히 감소 시
- 상태 변경 실패율이 임계치 초과 시
- 동일 사용자의 중복 주기 시도가 빈번할 때

### 3.3 보안 알림
- 중요 권한에 대한 반복적인 접근 실패 (5분 내 5회 이상)
- 관리자 계정의 비정상적인 권한 사용 패턴 감지
- 비정상 시간대의 고권한 작업 수행
- 다수의 주기에 대한 동시 상태 변경 시도 (일괄 처리 제외)
- 동일 IP에서 다수의 계정으로 접근 시도

### 3.4 알림 채널
- 긴급 (ERROR): Slack + SMS
- 경고 (WARN): Slack
- 정보 (INFO): 이메일 다이제스트
- 보안 인시던트: Slack + 전용 대시보드 + 보안팀 이메일

## 4. 대시보드

### 4.1 운영 대시보드
- API 성능 지표
  - 요청량 (RPS)
  - 응답 시간 분포
  - 에러율
- 시스템 상태
  - 캐시 히트율
  - DB 커넥션 상태
  - 메모리 사용량

### 4.2 비즈니스 대시보드
- 주기 상태별 분포
- 사이트별 활성 주기 수
- 시간대별 상태 변경 추이
- 에러 발생 추이

### 4.3 IAM 모니터링 대시보드
- 권한별 검증 지표
  - 권한 검증 성공/실패율
  - 가장 빈번하게 사용되는 권한
  - 가장 자주 실패하는 권한
- 역할별 통계
  - 역할별 API 사용 패턴
  - 역할별 리소스 접근 패턴
  - 역할 분포
- 보안 인시던트 모니터링
  - 권한 위반 시도 추이
  - 비정상 권한 사용 패턴
  - 인시던트 심각도별 분포
- 권한 캐싱 성능
  - 캐시 히트율
  - 캐시 무효화 이벤트

```typescript
interface IAMDashboardConfig {
  refreshInterval: number;  // 대시보드 갱신 간격(초)
  panels: {
    permissionMetrics: {
      displayMode: 'chart' | 'table';
      timeRange: string;     // '1h', '24h', '7d' 등
      groupBy: string[];     // 'permission', 'role', 'result' 등
    };
    securityIncidents: {
      severityFilter: string[];  // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
      timeRange: string;
      alertThreshold: number;    // 알림 임계값
    };
    roleActivityPatterns: {
      roles: string[];           // 모니터링할 역할
      unusualActivityDetection: boolean;
      aggregationPeriod: string; // '1h', '4h', '1d' 등
    };
  };
  alerts: {
    channels: {
      slack: string;             // Slack 채널
      email: string[];           // 이메일 주소 목록
      sms: string[];             // SMS 전화번호 목록
    };
    escalationPolicies: {
      [key: string]: {           // 심각도별 에스컬레이션 정책
        waitTime: number;        // 다음 단계로 에스컬레이션하기 전 대기 시간(분)
        notificationTargets: string[];
      }
    };
  };
}
```

## 5. 모니터링 데이터 보관 정책

### 5.1 메트릭스
- 원본 데이터: 15일
- 1분 집계: 30일
- 1시간 집계: 90일
- 1일 집계: 1년

### 5.2 로그
- ERROR 로그: 90일
- WARN 로그: 30일
- INFO 로그: 15일
- DEBUG 로그: 7일

### 5.3 보안 및 권한 관련 데이터
- 권한 위반 로그: 1년
- 관리자 권한 변경 로그: 2년
- 권한 변경 감사 로그: 2년
- 보안 인시던트 기록: 3년

## 6. 자동화된 보고서

### 6.1 일일 보고서
- 주기 상태 변경 요약
- API 사용량 요약
- 오류 및 경고 요약

### 6.2 주간 보고서
- 주기 상태 트렌드
- 사이트별 활동 요약
- 성능 메트릭 트렌드

### 6.3 IAM 및 보안 보고서
- 권한 위반 인시던트 요약 (주간)
- 권한 사용 패턴 분석 (월간)
- 역할별 API 사용 트렌드 (월간)
- IAM 권한 변경 감사 (월간)
- 보안 인시던트 분석 (월간)

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | IAM 및 권한 관련 모니터링 지표 추가 |
| 0.3.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |