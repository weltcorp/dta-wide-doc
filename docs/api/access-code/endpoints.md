# AccessCode API 명세서

## 관련 문서
- [API 개요](./overview.md)
- [API 구현 가이드](./implementation.md)
- [API 요구사항](./requirements.md)
- [API 테스트 명세](./test-spec.md)

## 1. 개요
AccessCode 도메인의 API는 불면증 진단을 받은 환자의 앱 회원가입을 위한 인증 코드의 생성, 검증, 관리를 위한 엔드포인트를 제공합니다. 모든 API는 RESTful 원칙을 따르며, 도메인 이벤트를 통해 다른 바운디드 컨텍스트와 상호작용합니다.

기본 URL: `https://api.example.com/v1/access-codes`

## 2. 공통 사항

### 2.1 인증 및 권한
- Bearer 토큰 인증 사용: `Authorization: Bearer {token}`
- 관리자 API는 추가로 `X-Admin-Token` 헤더 필요
- 권한 검증은 모든 요청에서 수행됨
- IAM 정책 기반 접근 제어 적용

### 2.2 엔드포인트 접근 권한 매트릭스

| 엔드포인트 | System Admin | IAM Admin | Service Account | Regular User |
|------------|--------------|-----------|-----------------|--------------|
| POST /v1/access-codes/permissions/validate | ✓ | ✓ | ✓ | - |
| POST /v1/access-codes/permissions/assign | ✓ | ✓ (범위 내) | - | - |
| DELETE /v1/access-codes/permissions/{permissionId} | ✓ | ✓ (범위 내) | - | - |
| GET /v1/access-codes/permissions | ✓ | ✓ (범위 내) | ✓ | - |
| POST /v1/access-codes | ✓ | ✓ (범위 내) | - | - |
| POST /v1/access-codes/validate | ✓ | ✓ | ✓ | ✓ |
| POST /v1/access-codes/{codeId}/use | ✓ | - | ✓ | - |
| POST /v1/access-codes/batch | ✓ | ✓ (범위 내) | - | - |
| GET /v1/access-codes/personal-data/{userId} | ✓ | ✓ (범위 내) | - | ✓ (자신만) |
| PATCH /v1/access-codes/personal-data/{userId} | ✓ | ✓ (범위 내) | - | ✓ (자신만) |
| DELETE /v1/access-codes/personal-data/{userId} | ✓ | - | - | ✓ (자신만) |
| POST /v1/access-codes/personal-data/{userId}/restrict | ✓ | - | - | ✓ (자신만) |
| GET /v1/access-codes/personal-data/{userId}/export | ✓ | - | - | ✓ (자신만) |
| GET /v1/access-codes/consent/{userId} | ✓ | ✓ (범위 내) | ✓ | ✓ (자신만) |
| PUT /v1/access-codes/consent/{userId} | ✓ | - | - | ✓ (자신만) |

> 참고:
> - ✓: 접근 가능
> - -: 접근 불가
> - (범위 내): 할당된 조직/팀 범위 내에서만 접근 가능
> - (자신만): 자신의 데이터에만 접근 가능

### 2.3 응답 형식
#### 성공 응답
```json
{
  "status": 200,
  "data": {
    // 응답 데이터
  }
}
```

#### 에러 응답
```json
{
  "status": 400,
  "code": "ERROR_CODE",
  "message": "에러 메시지",
  "detail": "상세 에러 설명"
}
```

### 2.4 개인정보 보호 헤더
모든 API 요청에 다음 헤더 포함 필요:
```http
Privacy-Policy-Version: 2024.1
Consent-Token: {consent_token}
Data-Processing-Purpose: USER_AUTHENTICATION
```

## 3. API 엔드포인트

### 3.1 권한 관리 API

#### 3.1.1 권한 검증
```http
POST /v1/access-codes/permissions/validate
Content-Type: application/json
Authorization: Bearer {token}
```

요청 본문:
```json
{
  "accessCodeId": "code_789",
  "action": "CREATE_CODE",
  "scope": "org_123",
  "resource": "access_code"
}
```

응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "allowed": true,
    "scope": "org_123",
    "permissions": ["CREATE_CODE", "READ_CODE"]
  }
}
```

#### 3.1.2 권한 할당
```http
POST /v1/access-codes/permissions/assign
Content-Type: application/json
Authorization: Bearer {token}
X-Admin-Token: {admin_token}
```

요청 본문:
```json
{
  "userId": "user_123",
  "scope": "org_123",
  "permissions": ["CREATE_CODE", "READ_CODE"],
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "id": "perm_456",
    "userId": "user_123",
    "scope": "org_123",
    "permissions": ["CREATE_CODE", "READ_CODE"],
    "grantedAt": "2024-03-29T10:00:00Z",
    "expiresAt": "2024-12-31T23:59:59Z"
  }
}
```

#### 3.1.3 권한 회수
```http
DELETE /v1/access-codes/permissions/{permissionId}
Authorization: Bearer {token}
X-Admin-Token: {admin_token}
```

응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "id": "perm_456",
    "revokedAt": "2024-03-29T11:00:00Z"
  }
}
```

#### 3.1.4 권한 조회
```http
GET /v1/access-codes/permissions
Authorization: Bearer {token}
```

쿼리 파라미터:
- `userId`: 사용자 ID (선택)
- `scope`: 권한 범위 (선택)
- `page`: 페이지 번호 (기본값: 1)
- `size`: 페이지 크기 (기본값: 10)

응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "items": [
      {
        "id": "perm_456",
        "userId": "user_123",
        "scope": "org_123",
        "permissions": ["CREATE_CODE", "READ_CODE"],
        "grantedAt": "2024-03-29T10:00:00Z",
        "expiresAt": "2024-12-31T23:59:59Z"
      }
    ],
    "pagination": {
      "page": 1,
      "size": 10,
      "total": 1
    }
  }
}
```

### 3.2 액세스 코드 관리 API

#### 3.2.1 코드 생성
```http
POST /v1/access-codes
Authorization: Bearer {token}
X-Admin-Token: {admin_token}
Privacy-Policy-Version: 2024.1
Data-Processing-Purpose: USER_AUTHENTICATION
Content-Type: application/json
```

요청 본문:
```json
{
  "type": "TREATMENT",
  "creatorId": "user_123",
  "accountId": "account_456",
  "treatmentPeriod": 90,
  "usagePeriod": 30,
  "email": "m***@example.com",
  "registrationChannel": "WEB",
  "randomizationCode": "RND123",
  "deliveryMethod": "EMAIL",
  "privacyConsent": {
    "dataProcessing": true,
    "emailMarketing": false,
    "thirdPartySharing": false
  },
  "timeMachineOptions": {
    "useTimeMachine": true,
    "testTime": "2024-03-20T09:00:00Z"
  }
}
```

응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "id": "code_789",
    "code": "AB12CD34EF56GH78",
    "expiresAt": "2024-04-20T09:00:00Z",
    "status": "UNUSED",
    "createdAt": "2024-03-20T09:00:00Z"
  }
}
```

#### 3.2.2 코드 검증
```http
POST /v1/access-codes/validate
Content-Type: application/json
```

요청 본문:
```json
{
  "code": "AB12CD34EF56GH78",
  "deviceId": "DEVICE_001"
}
```

응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "isValid": true,
    "codeInfo": {
      "id": "code_789",
      "treatmentPeriod": 90,
      "expiresAt": "2024-04-20T09:00:00Z"
    }
  }
}
```

#### 3.2.3 코드 사용
```http
POST /v1/access-codes/{codeId}/use
Content-Type: application/json
Authorization: Bearer {service_token}
```

요청 본문:
```json
{
  "userId": "user_123",
  "deviceId": "DEVICE_001",
  "timeMachineOptions": {
    "useTimeMachine": true,
    "testTime": "2024-03-25T14:30:00Z"
  }
}
```

응답 (200 OK):
```json
{
  "status": 200,
  "data": {
    "id": "code_789",
    "status": "USED",
    "usedAt": "2024-03-25T14:30:00Z",
    "userId": "user_123"
  }
}
```

#### 3.2.4 일괄 코드 생성
```http
POST /v1/access-codes/batch
Content-Type: application/json
Authorization: Bearer {token}
X-Admin-Token: {admin_token}
```

요청 본문:
```json
{
  "count": 10,
  "type": "TREATMENT",
  "creatorId": "user_123",
  "accountId": "account_456",
  "treatmentPeriod": 90,
  "usagePeriod": 30,
  "registrationChannel": "WEB",
  "timeMachineOptions": {
    "useTimeMachine": true,
    "testTime": "2024-03-20T09:00:00Z"
  }
}
```

응답 (201 Created):
```json
{
  "status": 201,
  "data": {
    "batchId": "batch_001",
    "codes": [
      {
        "id": "code_789",
        "code": "AB12CD34EF56GH78",
        "expiresAt": "2024-04-20T09:00:00Z"
      }
    ],
    "totalCount": 10
  }
}
```

### 3.3 개인정보 관리 API

#### 3.3.1 개인정보 열람
```http
GET /v1/access-codes/personal-data/{userId}
Authorization: Bearer {token}
Privacy-Policy-Version: 2024.1
```

#### 3.3.2 개인정보 수정
```http
PATCH /v1/access-codes/personal-data/{userId}
Authorization: Bearer {token}
Privacy-Policy-Version: 2024.1
```

#### 3.3.3 개인정보 삭제
```http
DELETE /v1/access-codes/personal-data/{userId}
Authorization: Bearer {token}
Privacy-Policy-Version: 2024.1
```

#### 3.3.4 개인정보 처리 제한
```http
POST /v1/access-codes/personal-data/{userId}/restrict
Authorization: Bearer {token}
Privacy-Policy-Version: 2024.1
```

#### 3.3.5 개인정보 이동
```http
GET /v1/access-codes/personal-data/{userId}/export
Authorization: Bearer {token}
Privacy-Policy-Version: 2024.1
```

### 3.4 동의 관리 API

#### 3.4.1 동의 상태 조회
```http
GET /v1/access-codes/consent/{userId}
Authorization: Bearer {token}
```

#### 3.4.2 동의 설정 변경
```http
PUT /v1/access-codes/consent/{userId}
Authorization: Bearer {token}
Content-Type: application/json
```

요청 본문:
```json
{
  "consents": {
    "dataProcessing": true,
    "emailMarketing": false,
    "thirdPartySharing": false
  },
  "validUntil": "2025-03-20T09:00:00Z"
}
```

## 4. 에러 코드

### 4.1 공통 에러 코드
| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|----------------|-----------|---------|-------|-----------|
| 400 | INVALID_INPUT | 잘못된 입력값 | 입력 데이터가 유효하지 않음 | 입력 데이터를 확인하고 다시 시도 |
| 401 | UNAUTHORIZED | 인증 필요 | 인증 정보가 제공되지 않음 | Bearer 토큰을 제공하거나 관리자에게 문의 |
| 403 | FORBIDDEN | 권한 없음 | 요청한 작업에 대한 권한이 없음 | 권한을 확인하거나 관리자에게 문의 |

### 4.2 권한 관련 에러 코드
| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|----------------|-----------|---------|-------|-----------|
| 403 | INVALID_PERMISSION | 권한이 없거나 유효하지 않음 | 요청한 작업에 대한 권한이 없음 | 권한을 확인하거나 관리자에게 문의 |
| 403 | PERMISSION_EXPIRED | 권한이 만료됨 | 권한이 만료됨 | 권한을 갱신하거나 관리자에게 문의 |
| 400 | INVALID_SCOPE | 유효하지 않은 권한 범위 | 권한 범위가 유효하지 않음 | 권한 범위를 확인하고 다시 시도 |
| 404 | SCOPE_NOT_FOUND | 권한 범위를 찾을 수 없음 | 요청한 권한 범위가 존재하지 않음 | 권한 범위를 확인하고 다시 시도 |

### 4.3 액세스 코드 관련 에러 코드
| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|----------------|-----------|---------|-------|-----------|
| 400 | INVALID_CODE | 유효하지 않은 코드 | 입력한 코드가 유효하지 않음 | 코드를 확인하고 다시 시도 |
| 400 | CODE_ALREADY_USED | 이미 사용된 코드 | 입력한 코드가 이미 사용됨 | 다른 코드를 사용하거나 관리자에게 문의 |
| 400 | CODE_EXPIRED | 만료된 코드 | 입력한 코드가 만료됨 | 새로운 코드를 발급받거나 관리자에게 문의 |
| 409 | DUPLICATE_CODE | 중복된 코드 | 입력한 코드가 이미 존재함 | 고유한 코드를 생성하거나 관리자에게 문의 |

### 4.4 시스템 에러 코드
| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|----------------|-----------|---------|-------|-----------|
| 500 | DATABASE_ERROR | 데이터베이스 오류 | 데이터베이스와의 통신 중 오류 발생 | 잠시 후 다시 시도하거나 관리자에게 문의 |
| 503 | SERVICE_UNAVAILABLE | 서비스 불가 | 서비스가 일시적으로 불가능함 | 잠시 후 다시 시도 |

## 5. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-29 | bok@weltcorp.com | IAM 권한 관리 API 추가 |
| 0.3.0 | 2025-03-30 | bok@weltcorp.com | 문서 구조 개선 및 에러 코드 체계화 |