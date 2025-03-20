# User API 엔드포인트

## 관련 문서
- [API 개요](./overview.md)
- [API 구현 가이드](./implementation.md)
- [API 요구사항](./requirements.md)
- [API 테스트 명세](./test-spec.md)

## 개요

User API는 사용자 정보 관리, 디바이스 관리, IAM 역할 관리 등 사용자 관련 리소스를 관리하는 API를 제공합니다. 회원가입 및 인증 관련 기능은 [Auth API 문서](../auth/endpoints.md)를 참조하세요.

> **중요**: 모든 API 호출은 앱 토큰(appToken) 또는 액세스 토큰(accessToken)이 필요합니다. 로그인 전에는 앱 토큰을, 로그인 후에는 액세스 토큰을 Authorization 헤더에 포함해야 합니다. 앱 토큰 발급 방법은 [Auth API 문서](../auth/endpoints.md#0-앱-인증-프로세스)를 참조하세요.

## 엔드포인트 접근 권한 매트릭스

| 엔드포인트 | System Admin | IAM Admin | Org Admin | Team Admin | Regular User |
|------------|--------------|-----------|------------|------------|--------------|
| POST /v1/users/{userId}/devices | ✓ | ✓ | 범위 내 | 범위 내 | 자신만 |
| GET /v1/users/{userId}/devices | ✓ | ✓ | 범위 내 | 범위 내 | 자신만 |
| GET /v1/users/{userId} | ✓ | ✓ | 범위 내 | 범위 내 | 자신만 |
| PATCH /v1/users/{userId} | ✓ | ✓ | 범위 내 | 범위 내 | 자신만 |
| DELETE /v1/users/{userId} | ✓ | ✓ | 범위 내 | ✘ | 자신만 |
| PUT /v1/users/{userId}/password | ✓ | ✓ | 범위 내 | ✘ | 자신만 |
| GET /v1/users/{userId}/roles | ✓ | ✓ | 범위 내 | 범위 내 | 자신만 |
| POST /v1/users/{userId}/roles | ✓ | ✓ | 범위 내(제한적) | ✘ | ✘ |
| DELETE /v1/users/{userId}/roles/{roleId} | ✓ | ✓ | 범위 내(제한적) | ✘ | ✘ |
| GET /v1/iam/requests | ✓ | ✓ | 범위 내 | 범위 내 | 자신의 요청만 |
| PUT /v1/iam/requests/{requestId}/{action} | ✓ | ✓ | 범위 내(제한적) | ✘ | ✘ |
| POST /v1/iam/check-permission | ✓ | ✓ | ✓ | ✓ | ✓ |

> **참고**:
> - ✓: 접근 가능
> - ✘: 접근 불가
> - 범위 내: 할당된 조직/팀 범위 내에서만 접근 가능
> - 자신만: 자신의 데이터에만 접근 가능
> - 범위 내(제한적): 할당된 범위 내에서 특정 역할에 대해서만 접근 가능

## 1. 디바이스 관리 API

### 1.1 디바이스 등록
- HTTP 메서드: POST
- 경로: /v1/users/{userId}/devices
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "deviceId": "device_123",
  "deviceType": "iOS",
  "deviceModel": "iPhone 15",
  "osVersion": "17.4.1",
  "appVersion": "1.0.0",
  "pushToken": "fcm_token_123"
}
```

#### 응답 (Response)
- 성공 응답 (201 Created)
```json
{
  "status": 201,
  "data": {
    "id": "device_123",
    "userId": "user_123",
    "deviceType": "iOS",
    "status": "ACTIVE",
    "createdAt": "2024-03-21T09:00:00Z"
  }
}
```

### 1.2 디바이스 목록 조회
- HTTP 메서드: GET
- 경로: /v1/users/{userId}/devices
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "devices": [
      {
        "id": "device_123",
        "deviceType": "iOS",
        "status": "ACTIVE",
        "lastActiveAt": "2024-03-21T09:00:00Z"
      }
    ]
  }
}
```

## 2. 사용자 정보 관리 API

### 2.1 사용자 정보 조회
- HTTP 메서드: GET
- 경로: /v1/users/{userId}
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "userId": "user_123",
    "email": "user@example.com",
    "name": "John Doe",
    "profile": {
      "nickname": "John",
      "language": "ko",
      "timezone": "Asia/Seoul"
    },
    "createdAt": "2024-03-21T09:00:00Z",
    "lastLoginAt": "2024-03-21T09:00:00Z"
  }
}
```

### 2.2 사용자 정보 수정
- HTTP 메서드: PATCH
- 경로: /v1/users/{userId}
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "name": "John Smith",
  "profile": {
    "nickname": "John",
    "language": "en",
    "timezone": "UTC"
  }
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "userId": "user_123",
    "name": "John Smith",
    "profile": {
      "nickname": "John",
      "language": "en",
      "timezone": "UTC"
    },
    "updatedAt": "2024-03-21T09:10:00Z"
  }
}
```

### 2.3 사용자 삭제
- HTTP 메서드: DELETE
- 경로: /v1/users/{userId}
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (204 No Content)

### 2.4 비밀번호 변경
- HTTP 메서드: PUT
- 경로: /v1/users/{userId}/password
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "currentPassword": "oldPassword123!",
  "newPassword": "newPassword456!"
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "message": "비밀번호가 성공적으로 변경되었습니다.",
    "updatedAt": "2024-03-21T09:15:00Z"
  }
}
```

## 3. IAM 역할 관리 API

### 3.1 사용자 역할 목록 조회
- HTTP 메서드: GET
- 경로: /v1/users/{userId}/roles
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "roles": [
      {
        "id": "SITE_ADMIN",
        "name": "사이트 관리자",
        "assignedAt": "2024-03-21T09:00:00Z",
        "expiresAt": null,
        "scope": {
          "organizationId": "org_123",
          "teamId": null
        }
      },
      {
        "id": "CONTENT_EDITOR",
        "name": "컨텐츠 편집자",
        "assignedAt": "2024-04-01T10:30:00Z",
        "expiresAt": "2024-07-01T00:00:00Z",
        "scope": {
          "organizationId": null,
          "teamId": "team_456"
        }
      }
    ]
  }
}
```

### 3.2 사용자 역할 할당
- HTTP 메서드: POST
- 경로: /v1/users/{userId}/roles
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "roleId": "SITE_ADMIN",
  "reason": "신규 사이트 관리자 임명",
  "scope": {
    "organizationId": "org_123",
    "teamId": null
  },
  "expiresAt": null
}
```

#### 응답 (Response)
- 성공 응답 (201 Created)
```json
{
  "status": 201,
  "data": {
    "requestId": "req_789",
    "status": "PENDING",
    "message": "역할 할당 요청이 생성되었습니다. 관리자 승인 후 적용됩니다."
  }
}
```

- 성공 응답 (자동 승인 시, 200 OK)
```json
{
  "status": 200,
  "data": {
    "message": "역할이 성공적으로 할당되었습니다.",
    "roleId": "SITE_ADMIN",
    "assignedAt": "2024-04-10T14:30:00Z"
  }
}
```

### 3.3 사용자 역할 회수
- HTTP 메서드: DELETE
- 경로: /v1/users/{userId}/roles/{roleId}
- Query Parameters:
  - reason: 역할 회수 사유 (필수)
  - scope_org_id: 조직 ID (선택, 범위 지정 시 필요)
  - scope_team_id: 팀 ID (선택, 범위 지정 시 필요)
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "message": "역할이 성공적으로 회수되었습니다.",
    "roleId": "SITE_ADMIN",
    "revokedAt": "2024-04-15T11:20:00Z"
  }
}
```

### 3.4 역할 변경 요청 목록 조회
- HTTP 메서드: GET
- 경로: /v1/iam/requests
- Query Parameters:
  - status: 요청 상태 (PENDING, APPROVED, REJECTED, EXPIRED)
  - user_id: 사용자 ID (특정 사용자에 대한 요청만 조회)
  - role_id: 역할 ID (특정 역할에 대한 요청만 조회)
- Headers:
  - Authorization: Bearer {accessToken}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "requests": [
      {
        "id": "req_789",
        "userId": "user_123",
        "roleId": "SITE_ADMIN",
        "operation": "ASSIGN",
        "status": "PENDING",
        "reason": "신규 사이트 관리자 임명",
        "requesterId": "user_456",
        "requesterName": "Jane Doe",
        "createdAt": "2024-04-10T14:25:00Z"
      },
      {
        "id": "req_790",
        "userId": "user_789",
        "roleId": "CONTENT_EDITOR",
        "operation": "REVOKE",
        "status": "APPROVED",
        "reason": "직무 변경으로 인한 권한 조정",
        "requesterId": "user_456",
        "requesterName": "Jane Doe",
        "approvedBy": "user_001",
        "approverName": "Admin User",
        "approvalNotes": "직무 변경 확인됨",
        "createdAt": "2024-04-09T10:15:00Z",
        "updatedAt": "2024-04-09T14:30:00Z"
      }
    ],
    "pagination": {
      "total": 10,
      "page": 1,
      "pageSize": 10
    }
  }
}
```

### 3.5 역할 변경 요청 승인/거부
- HTTP 메서드: PUT
- 경로: /v1/iam/requests/{requestId}/{action}
  - action: approve 또는 reject
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "notes": "직무 변경 확인되어 승인합니다."
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "requestId": "req_789",
    "status": "APPROVED",
    "message": "요청이 성공적으로 승인되었습니다.",
    "updatedAt": "2024-04-10T15:30:00Z"
  }
}
```

### 3.6 권한 검증
- HTTP 메서드: POST
- 경로: /v1/iam/check-permission
- Headers:
  - Authorization: Bearer {accessToken}
  - Content-Type: application/json

#### 요청 (Request)
```json
{
  "resourceType": "SITE",
  "resourceId": "site_123",
  "action": "EDIT"
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "hasPermission": true,
    "roles": ["SITE_ADMIN", "CONTENT_EDITOR"]
  }
}
```

## 4. 오류 코드

| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|--------------|---------|--------|------|---------|
| 400 | 1001 | INVALID_INPUT | 잘못된 입력값 | 요청 파라미터 검증 |
| 401 | 1002 | UNAUTHORIZED | 인증 필요 | 토큰 재발급 |
| 403 | 1003 | FORBIDDEN | 권한 없음 | 권한 확인 |
| 404 | 1004 | USER_NOT_FOUND | 사용자를 찾을 수 없음 | 사용자 ID 확인 |
| 409 | 1005 | EMAIL_ALREADY_EXISTS | 이미 존재하는 이메일 | 다른 이메일 사용 |
| 403 | 1006 | INSUFFICIENT_PERMISSIONS | 권한 부족 | 필요한 권한 확인 |
| 400 | 1007 | ROLE_ALREADY_ASSIGNED | 이미 할당된 역할 | 기존 할당 확인 |
| 400 | 1008 | INVALID_ROLE | 유효하지 않은 역할 | 역할 ID 확인 |
| 404 | 1009 | REQUEST_NOT_FOUND | 요청을 찾을 수 없음 | 요청 ID 확인 |
| 400 | 1010 | INVALID_REQUEST_STATUS | 유효하지 않은 요청 상태 | 요청 상태 확인 |
| 409 | 1011 | SELF_APPROVAL_FORBIDDEN | 자신의 요청 승인 불가 | 다른 승인자 필요 |

> **참고**: 인증 관련 오류 코드는 [Auth API 문서](../auth/endpoints.md#5-오류-코드)를 참조하세요.

## 5. IAM 역할 정의

다음은 시스템에서 사용되는 주요 IAM 역할 목록입니다:

| 역할 ID | 역할 이름 | 설명 | 필요 승인 레벨 |
|--------|---------|------|--------------|
| SYSTEM_ADMIN | 시스템 관리자 | 모든 시스템 리소스에 대한 완전한 접근 권한 | 다중 승인 필요 |
| SITE_ADMIN | 사이트 관리자 | 특정 사이트의 모든 기능에 대한 관리 권한 | 단일 승인 |
| ORG_ADMIN | 조직 관리자 | 특정 조직 내 사용자 및 리소스 관리 권한 | 단일 승인 |
| TEAM_ADMIN | 팀 관리자 | 특정 팀 내 사용자 및 리소스 관리 권한 | 자동 승인 |
| CONTENT_EDITOR | 컨텐츠 편집자 | 컨텐츠 생성 및 편집 권한 | 자동 승인 |
| USER | 일반 사용자 | 기본 사용자 권한 | 자동 승인 |

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-17 | bok@weltcorp.com | 앱 토큰 관련 내용 추가 |
| 0.3.0 | 2025-04-10 | bok@weltcorp.com | IAM 역할 관리 API 추가 |