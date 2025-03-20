# Access Code 도메인 모델

## 1. 핵심 엔티티

### 1.1 AccessCode
```typescript
export class AccessCode {
  id: string;                 // 고유 식별자
  code: string;              // 실제 접근 코드 값
  type: CodeType;            // 코드 유형
  status: CodeStatus;        // 현재 상태
  userId: string;            // 발급 대상 사용자
  issuer: string;           // 발급자
  issuedAt: Date;           // 발급 시간
  expiresAt: Date;          // 만료 시간
  usageCount: number;       // 사용 횟수
  maxUsageCount: number;    // 최대 사용 가능 횟수
  lastUsedAt?: Date;        // 마지막 사용 시간
  metadata: CodeMetadata;   // 추가 메타데이터
}
```

### 1.2 CodePolicy
```typescript
export class CodePolicy {
  id: string;                // 고유 식별자
  name: string;              // 정책 이름
  type: CodeType;            // 코드 유형
  length: number;            // 코드 길이
  charset: string;           // 사용 가능 문자셋
  expirationMinutes: number; // 만료 시간(분)
  maxUsageCount: number;     // 최대 사용 횟수
  isActive: boolean;         // 활성화 여부
}
```

### 1.3 CodeUsageHistory
```typescript
export class CodeUsageHistory {
  id: string;                // 고유 식별자
  codeId: string;            // 접근 코드 ID
  userId: string;            // 사용자 ID
  usedAt: Date;             // 사용 시간
  ipAddress: string;         // 사용 IP
  userAgent: string;         // 사용 기기 정보
  status: UsageStatus;       // 사용 결과 상태
}
```

## 2. 값 객체

### 2.1 CodeMetadata
```typescript
export class CodeMetadata {
  purpose: string;           // 코드 발급 목적
  deviceInfo?: string;       // 발급 요청 기기 정보
  location?: string;         // 발급 위치
  additionalInfo?: Record<string, unknown>; // 추가 정보
}
```

### 2.2 CodeValidationResult
```typescript
export class CodeValidationResult {
  isValid: boolean;          // 유효성 여부
  status: CodeStatus;        // 코드 상태
  remainingUsages?: number;  // 남은 사용 횟수
  validationTime: Date;      // 검증 시간
  error?: CodeError;         // 오류 정보
}
```

## 3. 열거형

### 3.1 CodeType
```typescript
export enum CodeType {
  ONE_TIME = 'ONE_TIME',           // 일회용
  TIME_LIMITED = 'TIME_LIMITED',   // 시간 제한
  MULTI_USE = 'MULTI_USE'         // 다중 사용
}
```

### 3.2 CodeStatus
```typescript
export enum CodeStatus {
  ACTIVE = 'ACTIVE',       // 활성
  USED = 'USED',          // 사용됨
  EXPIRED = 'EXPIRED',     // 만료됨
  REVOKED = 'REVOKED'     // 취소됨
}
```

### 3.3 UsageStatus
```typescript
export enum UsageStatus {
  SUCCESS = 'SUCCESS',           // 성공
  INVALID_CODE = 'INVALID_CODE', // 잘못된 코드
  EXPIRED = 'EXPIRED',          // 만료됨
  EXCEEDED = 'EXCEEDED',        // 사용 횟수 초과
  ERROR = 'ERROR'              // 기타 오류
}
```

## 4. 도메인 서비스

### 4.1 AccessCodeService
```typescript
export interface AccessCodeService {
  generateCode(policy: CodePolicy, userId: string): Promise<AccessCode>;
  validateCode(code: string, userId: string): Promise<CodeValidationResult>;
  revokeCode(codeId: string, reason: string): Promise<void>;
  extendValidity(codeId: string, minutes: number): Promise<AccessCode>;
}
```

### 4.2 CodePolicyService
```typescript
export interface CodePolicyService {
  createPolicy(policy: CodePolicy): Promise<CodePolicy>;
  updatePolicy(id: string, updates: Partial<CodePolicy>): Promise<CodePolicy>;
  activatePolicy(id: string): Promise<void>;
  deactivatePolicy(id: string): Promise<void>;
}
```

## 5. 도메인 이벤트

### 5.1 AccessCodeEvents
```typescript
export class AccessCodeGeneratedEvent {
  codeId: string;
  userId: string;
  type: CodeType;
  expiresAt: Date;
}

export class AccessCodeValidatedEvent {
  codeId: string;
  userId: string;
  isValid: boolean;
  remainingUsages?: number;
}

export class AccessCodeExpiredEvent {
  codeId: string;
  userId: string;
  expirationTime: Date;
}
```

## 6. 도메인 규칙
1. 접근 코드는 정책에 따라 지정된 길이와 문자셋으로 생성
2. 일회용 코드는 사용 후 즉시 만료
3. 시간 제한 코드는 발급 시점부터 지정된 시간 후 만료
4. 다중 사용 코드는 최대 사용 횟수 도달 시 만료
5. 만료된 코드는 재사용 불가
6. 코드 검증 시 사용자 ID 일치 여부 확인
7. 모든 코드 사용은 이력으로 기록
8. 활성화된 정책만 코드 생성에 사용 가능

## IAM 관련 도메인 모델

### AccessCodePermissionService
```typescript
interface AccessCodePermissionService {
  /**
   * 사용자가 특정 접근 코드에 대한 권한을 가지고 있는지 확인합니다.
   * @param userId 사용자 ID
   * @param accessCodeId 접근 코드 ID
   * @param permission 확인할 권한
   * @param options 추가 옵션 (사이트 ID, 조직 ID 등)
   * @returns 권한 보유 여부
   */
  hasPermission(
    userId: number, 
    accessCodeId: string, 
    permission: AccessCodePermission, 
    options?: { 
      siteId?: number,
      organizationId?: string 
    }
  ): Promise<boolean>;
  
  /**
   * 사용자가 접근 코드 생성 권한을 가지고 있는지 확인합니다.
   * @param userId 사용자 ID
   * @param siteId 사이트 ID
   * @param codeType 코드 유형
   * @param count 생성할 코드 수량
   * @returns 권한 보유 여부
   */
  canCreateAccessCodes(
    userId: number,
    siteId: number,
    codeType: AccessCodeType,
    count: number
  ): Promise<boolean>;
  
  /**
   * 사용자가 접근 코드 취소 권한을 가지고 있는지 확인합니다.
   * @param userId 사용자 ID
   * @param accessCodeId 접근 코드 ID
   * @returns 권한 보유 여부
   */
  canRevokeAccessCode(
    userId: number,
    accessCodeId: string
  ): Promise<boolean>;
  
  /**
   * 사용자의 조직 범위 내에서 접근 가능한 사이트 목록을 반환합니다.
   * @param userId 사용자 ID
   * @returns 접근 가능한 사이트 ID 목록
   */
  getAccessibleSites(userId: number): Promise<number[]>;
}
```

### AccessCodeAuditLog
```typescript
/**
 * 액세스 코드 관련 감사 로깅
 * 
 * 참고: 모든 로깅은 공통 로깅 표준(/docs/infrastructure/logging-standards.md)을 준수해야 합니다.
 * 
 * 예시:
 * // 액세스 코드 생성
 * logger.info({
 *   event: 'ACCESS_CODE_CREATED',
 *   code_id: string,
 *   user_id: number,
 *   metadata: {
 *     ip_address: string,
 *     user_agent: string
 *   }
 * });
 * 
 * // 액세스 코드 권한 거부
 * logger.warn({
 *   event: 'ACCESS_CODE_PERMISSION_DENIED',
 *   code_id: string,
 *   user_id: number,
 *   permission: string,
 *   metadata: {
 *     ip_address: string,
 *     resource_id: string,
 *     request_id: string
 *   }
 * });
 */

interface AuditLogService {
  /**
   * 감사 로그 기록
   */
  log(logData: {
    domain: string;
    component: string;
    action: string;
    actor_id: number;
    resource_id: string;
    metadata: Record<string, any>;
  }): Promise<void>;
}
```

### AccessCodeSecurityService
```typescript
interface AccessCodeSecurityService {
  /**
   * 사용자의 접근 코드 관련 활동을 모니터링하고 보안 규칙을 적용합니다.
   * @param userId 사용자 ID
   * @param action 수행할 액션
   * @param resource 대상 리소스
   * @returns 보안 검증 결과
   */
  checkSecurityRules(
    userId: number,
    action: string,
    resource: string
  ): Promise<SecurityCheckResult>;
  
  /**
   * 접근 코드 관련 비정상 활동 감지 및 차단
   * @param userId 사용자 ID
   * @param ipAddress IP 주소
   * @returns 차단 여부
   */
  detectSuspiciousActivity(
    userId: number,
    ipAddress: string
  ): Promise<boolean>;
  
  /**
   * 권한 거부 이벤트 처리 및 알림
   * @param userId 사용자 ID
   * @param permission 거부된 권한
   * @param resource 대상 리소스
   */
  handlePermissionDenied(
    userId: number,
    permission: AccessCodePermission,
    resource: string
  ): Promise<void>;
}

interface SecurityCheckResult {
  allowed: boolean;
  reason?: string;
  rateLimit?: {
    remaining: number;
    resetAt: Date;
  };
}
```

### IAM 연동 이벤트
```typescript
// AccessCode 도메인 이벤트
interface AccessCodeIAMEvent {
  id: string;
  type: 'PERMISSION_CHANGED' | 'ROLE_ASSIGNED' | 'ROLE_REVOKED';
  userId: number;
  accessCodeId?: string;
  siteId?: number;
  roles?: string[];
  permissions?: AccessCodePermission[];
  timestamp: Date;
  metadata: Record<string, any>;
}
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | IAM 통합 관련 도메인 모델 추가 |
| 0.3.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |