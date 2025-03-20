# Audit API 요구사항

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 구현 가이드](./implementation.md)
- [API 테스트 명세](./test-spec.md)

## 1. 기능 요구사항

### 1.1 감사 로그 관리
- 시스템은 다양한 소스에서 생성된 감사 이벤트를 수집하고 저장할 수 있어야 한다.
- 감사 로그는 생성 후 변경 불가능(immutable)해야 한다.
- 모든 감사 로그는 이벤트 타입, 소스, 타임스탬프, 액터, 타겟, 액션 정보를 포함해야 한다.
- 사용자 활동, 데이터 변경, 권한 변경, 시스템 이벤트, 보안 이벤트 등 다양한 이벤트 타입을 지원해야 한다.
- 연관된 감사 로그를 상관 ID(correlation ID)로 그룹화하여 추적할 수 있어야 한다.

### 1.2 검색 및 조회
- 사용자는 다양한 필터(시간 범위, 이벤트 타입, 소스, 액터 등)를 기반으로 감사 로그를 검색할 수 있어야 한다.
- 권한이 있는 사용자만 감사 로그를 조회할 수 있어야 한다.
- 감사 로그 검색 결과는 페이지네이션과 정렬을 지원해야 한다.
- 특정 리소스나 사용자에 대한 감사 추적(audit trail)을 조회할 수 있어야 한다.
- 세션 ID를 기반으로 사용자의 전체 활동 이력을 조회할 수 있어야 한다.

### 1.3 감사 정책 관리
- 관리자는 감사 정책을 생성, 조회, 수정, 삭제할 수 있어야 한다.
- 감사 정책은 수집할 이벤트 타입, 대상 소스, 보존 기간 등을 정의할 수 있어야 한다.
- 감사 정책은 활성화/비활성화할 수 있어야 한다.
- 중요 감사 정책 변경 시 해당 변경 사항도 감사 로그로 기록되어야 한다.

### 1.4 데이터 보존 관리
- 감사 로그는 정의된 보존 정책에 따라 관리되어야 한다.
- 기본 보존 기간은 1년으로 설정하고, 규정 준수가 필요한 데이터는 5년 이상 보존해야 한다.
- 보존 기간이 만료된 데이터는 아카이빙 또는 삭제할 수 있어야 한다.
- 법적 보존(legal hold) 설정된 데이터는 보존 기간과 무관하게 유지되어야 한다.

### 1.5 분석 및 보고
- 감사 이벤트에 대한 통계 및 집계 데이터를 제공해야 한다.
- 규제 요구사항을 충족하는 감사 보고서를 생성할 수 있어야 한다.
- 사용자 활동 패턴, 이상 행동 등을 분석할 수 있는 데이터를 제공해야 한다.

### 1.6 IAM 감사 로그 관리
- IAM 관련 모든 작업(역할 생성/수정/삭제, 정책 변경 등)은 반드시 감사 로그로 기록되어야 한다.
- IAM 감사 로그는 역할, 정책, 그룹, 권한 범위 등의 변경 이력을 상세히 포함해야 한다.
- IAM 관리자는 자신의 조직/팀 범위 내의 IAM 감사 로그를 조회할 수 있어야 한다.
- IAM 감사 로그 조회 시 변경 전/후 상태를 비교할 수 있어야 한다.
- IAM 권한 검증 실패 이벤트도 감사 로그에 기록되어야 한다.

## 2. 비기능 요구사항

### 2.1 성능
- 감사 이벤트 수집 지연은 p95에서 100ms 이하여야 한다.
- 감사 로그 조회 API 응답 시간은 p95에서 500ms 이하여야 한다.
- 시스템은 초당 최소 1,000개의 감사 이벤트를 처리할 수 있어야 한다.
- 대량 쿼리는 비동기 처리를 통해 성능 저하를 방지해야 한다.

### 2.2 확장성
- 시스템은 데이터 증가에 따라 수평적으로 확장 가능해야 한다.
- 저장 용량은 자동으로 확장되어야 한다.
- 이벤트 수집 처리량은 필요에 따라 조정 가능해야 한다.

### 2.3 보안
- 모든 감사 데이터는 전송 중 암호화되어야 한다 (HTTPS 필수).
- 민감한 개인정보는 마스킹 처리해야 한다.
- 감사 로그 조회는 권한 기반 접근 제어(RBAC)를 적용해야 한다.
- 모든 API 엔드포인트는 JWT 인증을 필요로 한다.
- 감사 데이터의 무결성과 불변성을 보장해야 한다.

### 2.4 가용성
- 시스템은 99.9% 이상의 가용성을 유지해야 한다.
- 주 저장소 장애 시 백업 저장소로 자동 전환되어야 한다.
- 이벤트 수집은 일시적인 처리 서비스 장애에도 데이터 손실이 없어야 한다.

### 2.5 유지보수성
- 시스템 구성요소는 모듈화되어 독립적으로 업데이트 가능해야 한다.
- 로깅 및 모니터링을 통해 시스템 상태를 실시간으로 확인할 수 있어야 한다.
- 데이터 스키마 변경은 기존 데이터와의 하위 호환성을 유지해야 한다.

### 2.6 IAM 보안
- IAM 관련 감사 로그는 추가 보안 검증을 거쳐야 한다.
- IAM 감사 로그 조회는 조직/팀 범위로 제한되어야 한다.
- IAM 권한 변경은 반드시 다중 승인을 통해 이루어져야 한다.
- IAM 감사 로그는 최소 5년간 보존되어야 한다.

## 3. API 데이터 구조

### 3.1 감사 로그(AuditLog)
```typescript
interface AuditLog {
  id: string;              // 감사 로그 고유 식별자
  timestamp: string;       // 이벤트 발생 시간 (ISO 8601 형식)
  eventType: string;       // 이벤트 유형
  source: string;          // 이벤트 발생 소스
  actor?: Actor;           // 이벤트를 발생시킨 주체
  target?: Target;         // 이벤트의 대상
  action: string;          // 수행된 작업
  details?: object;        // 이벤트 상세 정보
  metadata?: AuditMetadata; // 감사 관련 메타데이터
  status: 'SUCCESS' | 'FAILURE'; // 감사 로그 상태
}

interface Actor {
  type: 'USER' | 'SYSTEM' | 'SERVICE'; // 주체 유형
  id: string;              // 주체 식별자
  name?: string;           // 주체 이름
  attributes?: object;     // 추가 속성
}

interface Target {
  type: 'USER' | 'RESOURCE' | 'SYSTEM'; // 대상 유형
  id: string;              // 대상 식별자
  name?: string;           // 대상 이름
  resourceType?: string;   // 리소스 유형
  attributes?: object;     // 추가 속성
}

interface AuditMetadata {
  correlationId?: string;  // 연관 이벤트 추적 ID
  requestId?: string;      // 요청 식별자
  ipAddress?: string;      // 이벤트 발생 IP 주소
  userAgent?: string;      // 사용자 에이전트 정보
  sessionId?: string;      // 클라이언트 세션 식별자
}
```

### 3.2 감사 정책(AuditPolicy)
```typescript
interface AuditPolicy {
  id: string;              // 정책 고유 식별자
  name: string;            // 정책 이름
  description?: string;    // 정책 설명
  eventTypes: string[];    // 수집할 이벤트 유형 목록
  sources: string[];       // 대상 소스 목록
  enabled: boolean;        // 정책 활성화 여부
  retentionPeriod: number; // 데이터 보존 기간 (일)
  createdAt: string;       // 정책 생성 시간
  updatedAt: string;       // 정책 수정 시간
}
```

### 3.3 보존 정책(RetentionPolicy)
```typescript
interface RetentionPolicy {
  id: string;              // 정책 고유 식별자
  name: string;            // 정책 이름
  description?: string;    // 정책 설명
  retentionPeriod: number; // 보존 기간 (일)
  archivePeriod?: number;  // 아카이빙 기간 (일)
  eventTypes: string[];    // 적용 대상 이벤트 유형
  sources: string[];       // 적용 대상 소스
  enabled: boolean;        // 정책 활성화 여부
  createdAt: string;       // 정책 생성 시간
  updatedAt: string;       // 정책 수정 시간
}
```

### 3.4 감사 이벤트 통계(AuditStats)
```typescript
interface AuditStats {
  period: string;          // 통계 기간
  totalEvents: number;     // 전체 이벤트 수
  eventCounts: {           // 이벤트 유형별 개수
    [eventType: string]: number;
  };
  sourceCounts: {          // 소스별 이벤트 개수
    [source: string]: number;
  };
  statusCounts: {          // 상태별 이벤트 개수
    success: number;
    failure: number;
  };
  topActors: Array<{       // 상위 액터
    actorId: string;
    actorType: string;
    count: number;
  }>;
  topTargets: Array<{      // 상위 타겟
    targetId: string;
    targetType: string;
    count: number;
  }>;
}
```

### 3.5 IAM 감사 로그(IAMAuditLog)
```typescript
interface IAMAuditLog extends AuditLog {
  iamDetails: {
    resourceType: 'ROLE' | 'POLICY' | 'GROUP' | 'SCOPE';
    operation: 'CREATE' | 'UPDATE' | 'DELETE' | 'ASSIGN' | 'REVOKE';
    resourceId: string;
    resourceName: string;
    previousState?: object;
    newState?: object;
    approvers?: string[];
    organizationId?: string;
    teamId?: string;
  };
}

interface IAMPermissionVerification {
  userId: string;
  resourceType: string;
  resourceId: string;
  permission: string;
  granted: boolean;
  reason?: string;
  timestamp: string;
}
```

## 4. 데이터베이스 스키마

### 4.1 BigQuery 테이블 구조
```sql
-- 감사 로그 메인 테이블
CREATE TABLE `project.audit.logs` (
  id STRING,
  timestamp TIMESTAMP,
  event_type STRING,
  source STRING,
  actor STRUCT<
    type STRING,
    id STRING,
    name STRING,
    attributes JSON
  >,
  target STRUCT<
    type STRING,
    id STRING,
    name STRING,
    resource_type STRING,
    attributes JSON
  >,
  action STRING,
  details JSON,
  metadata STRUCT<
    correlation_id STRING,
    request_id STRING,
    ip_address STRING,
    user_agent STRING,
    session_id STRING
  >,
  status STRING
)
PARTITION BY DATE(timestamp)
CLUSTER BY event_type, source, status;

-- 감사 정책 테이블
CREATE TABLE `project.audit.policies` (
  id STRING,
  name STRING,
  description STRING,
  event_types ARRAY<STRING>,
  sources ARRAY<STRING>,
  enabled BOOLEAN,
  retention_period INT64,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

-- 보존 정책 테이블
CREATE TABLE `project.audit.retention_policies` (
  id STRING,
  name STRING,
  description STRING,
  retention_period INT64,
  archive_period INT64,
  event_types ARRAY<STRING>,
  sources ARRAY<STRING>,
  enabled BOOLEAN,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

### 4.2 인덱스 구성
```sql
-- 감사 로그 검색 최적화를 위한 인덱스 (Elasticsearch)
PUT /audit-logs
{
  "mappings": {
    "properties": {
      "id": { "type": "keyword" },
      "timestamp": { "type": "date" },
      "event_type": { "type": "keyword" },
      "source": { "type": "keyword" },
      "actor.type": { "type": "keyword" },
      "actor.id": { "type": "keyword" },
      "actor.name": { "type": "text" },
      "target.type": { "type": "keyword" },
      "target.id": { "type": "keyword" },
      "target.name": { "type": "text" },
      "target.resource_type": { "type": "keyword" },
      "action": { "type": "keyword" },
      "status": { "type": "keyword" },
      "metadata.correlation_id": { "type": "keyword" },
      "metadata.session_id": { "type": "keyword" },
      "metadata.ip_address": { "type": "ip" }
    }
  }
}
```

### 4.3 IAM 감사 로그 테이블
```sql
-- IAM 감사 로그 테이블
CREATE TABLE `project.audit.iam_logs` (
  id STRING,
  timestamp TIMESTAMP,
  event_type STRING,
  source STRING,
  actor STRUCT<
    type STRING,
    id STRING,
    name STRING,
    attributes JSON
  >,
  iam_details STRUCT<
    resource_type STRING,
    operation STRING,
    resource_id STRING,
    resource_name STRING,
    previous_state JSON,
    new_state JSON,
    approvers ARRAY<STRING>,
    organization_id STRING,
    team_id STRING
  >,
  status STRING,
  metadata STRUCT<
    correlation_id STRING,
    request_id STRING,
    ip_address STRING,
    user_agent STRING,
    session_id STRING
  >
)
PARTITION BY DATE(timestamp)
CLUSTER BY event_type, source, status;

-- IAM 권한 검증 로그 테이블
CREATE TABLE `project.audit.iam_permission_verifications` (
  id STRING,
  user_id STRING,
  resource_type STRING,
  resource_id STRING,
  permission STRING,
  granted BOOLEAN,
  reason STRING,
  timestamp TIMESTAMP
)
PARTITION BY DATE(timestamp)
CLUSTER BY user_id, resource_type, granted;
```

## 5. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | IAM 관련 요구사항 추가: IAM 감사 로그 관리, IAM 보안 요구사항, IAM 데이터 구조 및 스키마 정의 | 