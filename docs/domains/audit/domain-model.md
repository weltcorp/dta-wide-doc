# Audit 도메인 모델

## 엔티티

### AuditLog
감사 로그는 시스템 내에서 발생한 중요 이벤트를 기록하는 엔티티입니다.

#### 속성
| 속성 | 타입 | 설명 |
|-----|-----|-----|
| id | UUID | 감사 로그 고유 식별자 |
| timestamp | DateTime | 이벤트 발생 시간 |
| eventType | String | 이벤트 유형 (예: USER_LOGIN, DATA_CHANGE) |
| source | String | 이벤트 발생 소스 (도메인/서비스 이름) |
| actor | ActorReference | 이벤트를 발생시킨 주체 |
| target | TargetReference | 이벤트의 대상 |
| action | String | 수행된 작업 (예: CREATE, UPDATE, DELETE) |
| details | Map<String, Object> | 이벤트 상세 정보 |
| metadata | AuditMetadata | 감사 관련 메타데이터 |
| status | AuditStatus | 감사 로그 상태 (SUCCESS, FAILURE) |

#### 불변식
- timestamp는 null이 될 수 없음
- eventType은 null이 될 수 없음
- source는 null이 될 수 없음
- actor 또는 target 중 최소 하나는 값이 존재해야 함

### AuditPolicy
감사 정책은 어떤 이벤트를 기록할지를 정의하는 규칙입니다.

#### 속성
| 속성 | 타입 | 설명 |
|-----|-----|-----|
| id | UUID | 정책 고유 식별자 |
| name | String | 정책 이름 |
| description | String | 정책 설명 |
| eventTypes | Set<String> | 수집할 이벤트 유형 목록 |
| sources | Set<String> | 대상 소스 목록 |
| enabled | boolean | 정책 활성화 여부 |
| retentionPeriod | Duration | 데이터 보존 기간 |
| createdAt | DateTime | 정책 생성 시간 |
| updatedAt | DateTime | 정책 수정 시간 |

#### 불변식
- name은 null이 될 수 없으며 고유해야 함
- eventTypes는 비어있을 수 없음
- retentionPeriod는 양수여야 함

## 값 객체

### ActorReference
이벤트를 발생시킨 주체에 대한 참조입니다.

#### 속성
| 속성 | 타입 | 설명 |
|-----|-----|-----|
| type | ActorType | 주체 유형 (USER, SYSTEM, SERVICE) |
| id | String | 주체 식별자 |
| name | String | 주체 이름 |
| attributes | Map<String, String> | 추가 속성 |

### TargetReference
이벤트의 영향을 받는 대상에 대한 참조입니다.

#### 속성
| 속성 | 타입 | 설명 |
|-----|-----|-----|
| type | TargetType | 대상 유형 (USER, RESOURCE, SYSTEM) |
| id | String | 대상 식별자 |
| name | String | 대상 이름 |
| resourceType | String | 리소스 유형 (USER, ROLE, PERMISSION 등) |
| attributes | Map<String, String> | 추가 속성 |

### AuditMetadata
감사 로그와 관련된 메타데이터입니다.

#### 속성
| 속성 | 타입 | 설명 |
|-----|-----|-----|
| correlationId | String | 연관 이벤트를 추적하기 위한 ID |
| requestId | String | 요청 식별자 |
| ipAddress | String | 이벤트 발생 IP 주소 |
| userAgent | String | 사용자 에이전트 정보 |
| sessionId | String | 클라이언트에서 생성한 세션 식별자. JWT 기반 인증 환경에서 서버는 세션을 관리하지 않지만, 클라이언트(특히 Mobile)에서 생성한 UUID로 사용자 활동의 연속성 추적에 사용됨 |

## 집계

### AuditEventAggregate
감사 이벤트를 생성하고 관리하는 집계입니다.

#### 책임
- 감사 이벤트 생성 및 유효성 검증
- 감사 정책에 따른 이벤트 필터링
- 이벤트 저장소 저장 관리

#### 연관 엔티티
- AuditLog (루트 엔티티)
- AuditPolicy (참조)

## 도메인 서비스

### AuditService
감사 로그 생성 및 조회를 위한 도메인 서비스입니다.

#### 책임
- 감사 이벤트 생성 및 저장
- 감사 로그 조회 및 검색
- 감사 정책 적용

#### 메서드
- `createAuditLog(AuditLogRequest): AuditLog`
- `queryAuditLogs(AuditLogQuery): List<AuditLog>`
- `getAuditTrail(TrailCriteria): AuditTrail`
- `findBySessionId(sessionId, PaginationOptions): PaginatedResponse<AuditLog>`

### RetentionService
감사 데이터 보존 정책을 관리하는 서비스입니다.

#### 책임
- 보존 기간이 만료된 데이터 정리
- 보관 정책 적용
- 데이터 아카이빙 관리

#### 메서드
- `applyRetentionPolicy(PolicyId): RetentionResult`
- `archiveAuditData(ArchiveRequest): ArchiveResult`
- `purgeExpiredData(): PurgeResult`

## 도메인 이벤트

### AuditLogCreated
새로운 감사 로그가 생성되었을 때 발행되는 이벤트입니다.

#### 속성
- `auditLogId`: 생성된 감사 로그 ID
- `timestamp`: 이벤트 발생 시간
- `eventType`: 감사 이벤트 유형
- `source`: 이벤트 소스

### RetentionPolicyApplied
보존 정책이 적용되었을 때 발행되는 이벤트입니다.

#### 속성
- `policyId`: 적용된 정책 ID
- `appliedAt`: 정책 적용 시간
- `affectedLogsCount`: 영향을 받은 로그 수
- `retentionPeriod`: 적용된 보존 기간

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|---|-----|-----|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 |