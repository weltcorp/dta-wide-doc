# IAM API 엔드포인트

## 관련 문서
- [API 개요](./overview.md)
- [API 요구사항](./requirements.md)
- [API 구현 가이드](./implementation.md)

## 접근 권한 매트릭스

| 엔드포인트 | System Admin | IAM Admin | Service Account | Regular User |
|------------|--------------|-----------|-----------------|--------------|
| POST /v1/iam/permissions | ✓ | ✓ | - | - |
| GET /v1/iam/permissions/{permissionId} | ✓ | ✓ | ✓ (범위 내) | ✓ (자신) |
| PUT /v1/iam/permissions/{permissionId} | ✓ | ✓ | - | - |
| DELETE /v1/iam/permissions/{permissionId} | ✓ | - | - | - |
| POST /v1/iam/roles | ✓ | ✓ | - | - |
| GET /v1/iam/roles/{roleId} | ✓ | ✓ | ✓ (범위 내) | ✓ (자신) |
| PUT /v1/iam/roles/{roleId} | ✓ | ✓ | - | - |
| DELETE /v1/iam/roles/{roleId} | ✓ | - | - | - |
| POST /v1/iam/roles/{roleId}/permissions | ✓ | ✓ | - | - |
| GET /v1/iam/roles/{roleId}/permissions | ✓ | ✓ | ✓ (범위 내) | ✓ (자신) |
| POST /v1/iam/users/{userId}/roles | ✓ | ✓ | - | - |
| POST /v1/iam/policies | ✓ | ✓ | - | - |
| GET /v1/iam/policies/{policyId} | ✓ | ✓ | ✓ (범위 내) | - |
| PUT /v1/iam/policies/{policyId} | ✓ | ✓ | - | - |
| DELETE /v1/iam/policies/{policyId} | ✓ | - | - | - |
| POST /v1/iam/authorize | ✓ | ✓ | ✓ | ✓ |

## API 호출 제한

### 서비스 계정 제한사항
- Rate Limit: 1000 requests/minute
- 권한 검증 캐시 TTL: 5분
- 최대 동시 요청 수: 100
- 배치 요청 크기 제한: 1000 항목

### 일반 사용자 제한사항
- Rate Limit: 100 requests/minute
- 권한 검증 캐시 TTL: 15분
- 최대 동시 요청 수: 10
- 배치 요청 크기 제한: 100 항목

## 1. 권한 관리 API (Permissions)

### 권한 생성
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/permissions
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "name": "user:read",
  "description": "사용자 정보 조회 권한",
  "scope": "user",
  "actions": ["read"],
  "resources": ["users/*"],
  "conditions": {
    "ip_range": ["10.0.0.0/8"]
  }
}
```

#### 응답 (Response)
- 성공 응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "id": "perm_123",
    "name": "user:read",
    "description": "사용자 정보 조회 권한",
    "scope": "user",
    "actions": ["read"],
    "resources": ["users/*"],
    "conditions": {
      "ip_range": ["10.0.0.0/8"]
    },
    "created_at": "2024-03-21T09:00:00Z",
    "updated_at": "2024-03-21T09:00:00Z"
  }
}
```

### 권한 조회
#### 요청 (Request)
- HTTP 메서드: GET
- 경로: /v1/iam/permissions/{permissionId}
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "id": "perm_123",
    "name": "user:read",
    "description": "사용자 정보 조회 권한",
    "scope": "user",
    "actions": ["read"],
    "resources": ["users/*"],
    "conditions": {
      "ip_range": ["10.0.0.0/8"]
    },
    "created_at": "2024-03-21T09:00:00Z",
    "updated_at": "2024-03-21T09:00:00Z"
  }
}
```

## 2. 역할 관리 API (Roles)

### 역할 생성
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/roles
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "name": "user_admin",
  "description": "사용자 관리자 역할",
  "permissions": ["perm_123", "perm_124"],
  "parent_role": "admin"
}
```

#### 응답 (Response)
- 성공 응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "id": "role_123",
    "name": "user_admin",
    "description": "사용자 관리자 역할",
    "permissions": ["perm_123", "perm_124"],
    "parent_role": "admin",
    "created_at": "2024-03-21T09:00:00Z",
    "updated_at": "2024-03-21T09:00:00Z"
  }
}
```

### 역할 할당
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/users/{userId}/roles
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "roles": ["role_123"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

#### 응답 (Response)
- 성공 응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "userId": "user_123",
    "roles": ["role_123"],
    "expires_at": "2024-12-31T23:59:59Z",
    "created_at": "2024-03-21T09:00:00Z"
  }
}
```

### 역할에 권한 할당
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/roles/{roleId}/permissions
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "permissions": ["perm_123", "perm_124"]
}
```

#### 응답 (Response)
- 성공 응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "id": "role_123",
    "name": "user_admin",
    "permissions": ["perm_123", "perm_124"],
    "updated_at": "2024-03-21T09:30:00Z"
  }
}
```

### 역할 권한 조회
#### 요청 (Request)
- HTTP 메서드: GET
- 경로: /v1/iam/roles/{roleId}/permissions
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "roleId": "role_123",
    "permissions": [
      {
        "id": "perm_123",
        "name": "user:read",
        "description": "사용자 정보 조회 권한"
      },
      {
        "id": "perm_124",
        "name": "user:write",
        "description": "사용자 정보 수정 권한"
      }
    ]
  }
}
```

## 3. 정책 관리 API (Policies)

### 정책 생성
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/policies
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "name": "ip_restriction",
  "description": "IP 기반 접근 제한 정책",
  "type": "deny",
  "priority": 1,
  "conditions": {
    "ip_range": {
      "not_in": ["10.0.0.0/8"]
    }
  },
  "resources": ["users/*"],
  "actions": ["read", "write"]
}
```

#### 응답 (Response)
- 성공 응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "id": "pol_123",
    "name": "ip_restriction",
    "description": "IP 기반 접근 제한 정책",
    "type": "deny",
    "priority": 1,
    "conditions": {
      "ip_range": {
        "not_in": ["10.0.0.0/8"]
      }
    },
    "resources": ["users/*"],
    "actions": ["read", "write"],
    "created_at": "2024-03-21T09:00:00Z",
    "updated_at": "2024-03-21T09:00:00Z"
  }
}
```

## 4. 권한 검증 API (Authorization)

### 권한 검증
#### 요청 (Request)
- HTTP 메서드: POST
- 경로: /v1/iam/authorize
- Headers:
  - Authorization: Bearer {token}
  - Content-Type: application/json
- Body:
```json
{
  "userId": "user_123",
  "action": "read",
  "resource": "users/456",
  "context": {
    "ip": "10.0.0.1",
    "time": "2024-03-21T09:00:00Z"
  }
}
```

#### 응답 (Response)
- 성공 응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "allowed": true,
    "reason": "POLICY_ALLOW",
    "evaluatedPolicies": ["pol_123", "pol_124"],
    "timestamp": "2024-03-21T09:00:00Z"
  }
}
```

## 상태 코드
| 상태 코드 | 설명 | 발생 조건 |
|----|---|----|
| 200 | 성공 | 요청이 정상적으로 처리됨 |
| 201 | 생성됨 | 새 리소스가 생성됨 |
| 400 | 잘못된 요청 | 요청 파라미터가 유효하지 않음 |
| 401 | 인증 필요 | 인증 토큰이 없거나 유효하지 않음 |
| 403 | 권한 없음 | 인증은 되었으나 접근 권한이 없음 |
| 404 | 찾을 수 없음 | 요청한 리소스가 존재하지 않음 |
| 409 | 충돌 | 리소스 충돌 (예: 중복된 이름) |
| 500 | 서버 오류 | 서버 내부 오류 발생 |

## 에러 코드
| 에러 코드 | 메시지 | 설명 | 대응 방법 |
|-----|---|-----|-----|
| INVALID_PERMISSION | 권한이 유효하지 않음 | 요청한 권한이 존재하지 않거나 유효하지 않음 | 권한 정보 확인 |
| ROLE_NOT_FOUND | 역할을 찾을 수 없음 | 요청한 역할이 존재하지 않음 | 역할 ID 확인 |
| POLICY_CONFLICT | 정책 충돌 | 기존 정책과 충돌 발생 | 정책 우선순위 조정 |
| INVALID_CONDITION | 유효하지 않은 조건 | 정책 조건이 유효하지 않음 | 조건식 검증 |
| CIRCULAR_DEPENDENCY | 순환 참조 발생 | 역할 계층에서 순환 참조 발생 | 역할 계층 구조 확인 |

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|---|-----|-----|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 | 
| 0.2.0 | 2025-03-20 | bok@weltcorp.com | 역할별 권한 관리 API 추가 | 