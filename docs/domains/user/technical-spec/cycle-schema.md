# 사용자 주기 스키마 명세

## 1. 데이터 모델

### UserCycle
```typescript
interface UserCycle {
  id: number;
  userId: number;
  siteId: number;
  groupId?: number;
  departmentId?: number;
  accountId: number;
  accesscodeId: number;
  registrationChannelId?: number;
  status: UserCycleStatus;
  startAt: Date | null;
  endAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  iamRoleId?: string;          // 할당된 IAM 역할 ID
  permissionSetId?: string;    // 할당된 권한 세트 ID
  iamRoleAssignedAt?: Date;    // IAM 역할 할당 시간
  iamRoleRevokedAt?: Date;     // IAM 역할 회수 시간
  iamRoleAssignedBy?: number;  // IAM 역할 할당자 ID
}
```

### UserCycleStatus
```typescript
enum UserCycleStatus {
  PENDING = 0,
  ACTIVE = 1,
  COMPLETED = 2,
  SUSPENDED = 3,
  CANCELLED = 4
}
```

### CreateCycleDto
```typescript
interface CreateCycleDto {
  userId: number;
  siteId: number;
  groupId?: number;
  departmentId?: number;
  accountId: number;
  accesscodeId: number;
  registrationChannelId?: number;
  startAt?: Date;
  iamRoleId?: string;          // 할당할 IAM 역할 ID
  permissionSetId?: string;    // 할당할 권한 세트 ID
}
```

### UpdateCycleStatusDto
```typescript
interface UpdateCycleStatusDto {
  status: UserCycleStatus;
  reason?: string;
}
```

### GetCyclesQueryDto
```typescript
interface GetCyclesQueryDto {
  userId?: number;
  siteId?: number;
  status?: UserCycleStatus;
  startFrom?: Date;
  startTo?: Date;
  page?: number;
  limit?: number;
  sort?: 'ASC' | 'DESC';
  sortBy?: 'startAt' | 'createdAt';
}
```

### UserCycleResponse
```typescript
interface UserCycleResponse {
  id: number;
  userId: number;
  siteId: number;
  groupId?: number;
  departmentId?: number;
  accountId: number;
  accesscodeId: number;
  registrationChannelId?: number;
  status: UserCycleStatus;
  startAt: string | null;
  endAt: string | null;
  createdAt: string;
  updatedAt: string;
  iamRoleId?: string;
  permissionSetId?: string;
  iamRoleAssignedAt?: string;
  iamRoleRevokedAt?: string;
  iamRoleAssignedBy?: number;
  user?: UserAccountResponse;
  site?: SiteResponse;
  group?: GroupResponse;
  department?: DepartmentResponse;
  account?: AccountResponse;
  accesscode?: AccesscodeResponse;
  registrationChannel?: RegistrationChannelResponse;
  iamRole?: IAMRoleResponse;      // IAM 역할 정보
  permissionSet?: PermissionSetResponse;  // 권한 세트 정보
}
```

## 2. 상태 전이 규칙

### 허용된 상태 전이
```typescript
const ALLOWED_STATUS_TRANSITIONS = {
  [UserCycleStatus.PENDING]: [UserCycleStatus.ACTIVE, UserCycleStatus.CANCELLED],
  [UserCycleStatus.ACTIVE]: [UserCycleStatus.COMPLETED, UserCycleStatus.SUSPENDED],
  [UserCycleStatus.SUSPENDED]: [UserCycleStatus.ACTIVE, UserCycleStatus.CANCELLED],
  [UserCycleStatus.COMPLETED]: [],
  [UserCycleStatus.CANCELLED]: []
};
```

### 상태 전이 검증
```typescript
function isValidStatusTransition(currentStatus: UserCycleStatus, newStatus: UserCycleStatus): boolean {
  const allowedTransitions = ALLOWED_STATUS_TRANSITIONS[currentStatus];
  return allowedTransitions.includes(newStatus);
}
```

## 3. 유효성 검증 규칙

### 생성 시 검증
- userId는 존재하는 사용자여야 함
- siteId는 존재하는 사이트여야 함
- accountId는 존재하는 계정이어야 함
- accesscodeId는 유효한 액세스 코드여야 함
- 동일 사용자의 활성 주기가 없어야 함
- iamRoleId가 제공된 경우 유효한 IAM 역할 ID여야 함
- permissionSetId가 제공된 경우 유효한 권한 세트 ID여야 함

### 상태 변경 시 검증
- 허용된 상태 전이만 가능
- ACTIVE 상태로 변경 시 startAt이 설정되어야 함
- COMPLETED 상태로 변경 시 endAt이 설정되어야 함
- 상태 변경 권한이 있는지 확인해야 함

## 4. IAM 관련 스키마

### 사용자 주기 IAM 역할 연결
```typescript
interface UserCycleIAMMapping {
  id: number;
  cycleId: number;
  iamRoleId: string;
  permissionSetId?: string;
  assignedAt: Date;
  assignedBy: number;
  revokedAt?: Date;
  revokedBy?: number;
  expiresAt?: Date;
  reason?: string;
  createdAt: Date;
  updatedAt: Date;
}
```

### IAM 역할 할당 DTO
```typescript
interface AssignIAMRoleDto {
  iamRoleId: string;
  permissionSetId?: string;
  expiresAt?: Date;
  reason?: string;
}
```

### IAM 역할 회수 DTO
```typescript
interface RevokeIAMRoleDto {
  reason: string;
}
```

### IAM 역할 대응 모델
```typescript
interface IAMRoleResponse {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  isBuiltIn: boolean;
  scope: 'GLOBAL' | 'ORGANIZATION' | 'SITE' | 'GROUP';
}
```

### 권한 세트 대응 모델
```typescript
interface PermissionSetResponse {
  id: string;
  name: string;
  description?: string;
  permissions: {
    resource: string;
    actions: string[];
  }[];
}
```

### 주기 권한 검증 요청
```typescript
interface CyclePermissionCheckDto {
  cycleId: number;
  permission: string;
  resourceId?: string;
  action?: string;
}
```

### 권한 검증 응답
```typescript
interface PermissionCheckResponse {
  allowed: boolean;
  reason?: string;
  responseTime: number; // 밀리초
  requestId: string;
}
```

## 5. IAM 권한 검증 규칙

### IAM 역할 할당 시 검증
- 할당하려는 IAM 역할이 존재해야 함
- 할당자가 해당 역할 할당 권한을 가지고 있어야 함
- 동일 사용자 주기에 이미 할당된 동일 역할이 없어야 함
- 조직 범위(scope)가 사용자 주기의 사이트/그룹과 일치해야 함
- expiresAt이 설정된 경우 현재 시간보다 미래여야 함

### IAM 역할 회수 시 검증
- 회수하려는 역할이 실제로 할당되어 있어야 함
- 회수자가 해당 역할 회수 권한을 가지고 있어야 함
- 이미 회수된 역할이 아니어야 함
- 회수 사유가 명시되어야 함

### 권한 검증 프로세스
```typescript
async function validateCyclePermission(
  cycleId: number,
  userId: number,
  permission: string,
  context?: Record<string, any>
): Promise<PermissionCheckResponse> {
  // 1. 사용자 주기 조회
  const cycle = await getCycleById(cycleId);
  if (!cycle) {
    return {
      allowed: false,
      reason: 'CYCLE_NOT_FOUND',
      responseTime: 0,
      requestId: generateRequestId()
    };
  }
  
  // 2. IAM 권한 검증
  const startTime = Date.now();
  const result = await iamService.checkPermission({
    userId,
    resourceType: 'user_cycle',
    resourceId: cycleId.toString(),
    permission,
    context: {
      siteId: cycle.siteId,
      ...context
    }
  });
  
  const endTime = Date.now();
  
  // 3. 응답 생성
  return {
    allowed: result.allowed,
    reason: result.reason,
    responseTime: endTime - startTime,
    requestId: result.requestId
  };
}
```

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-30 | bok@weltcorp.com | IAM 관련 스키마 추가 |