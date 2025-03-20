# TimeMachine API 엔드포인트

## 1. 시간 조회/설정 API

### 1.1 현재 시간 조회
- HTTP 메서드: GET
- 경로: /v1/time-machine/current-time
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "currentTime": "2024-03-21T09:00:00Z",
    "timezone": "UTC",
    "offset": "+00:00",
    "isTimeMachineEnabled": true
  }
}
```

### 1.2 시간 설정
- HTTP 메서드: POST
- 경로: /v1/time-machine/set-time
- Headers:
  - Authorization: Bearer {token}
- Content-Type: application/json

#### 요청 (Request)
```json
{
  "targetTime": "2024-03-21T09:00:00Z",
  "timezone": "UTC",
  "reason": "테스트 시나리오 실행"
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "previousTime": "2024-03-20T09:00:00Z",
    "currentTime": "2024-03-21T09:00:00Z",
    "timezone": "UTC",
    "offset": "+00:00"
  }
}
```

## 2. 시간 조작 API

### 2.1 시간 이동
- HTTP 메서드: POST
- 경로: /v1/time-machine/move
- Headers:
  - Authorization: Bearer {token}
- Content-Type: application/json

#### 요청 (Request)
```json
{
  "direction": "forward",
  "amount": 24,
  "unit": "hours",
  "reason": "다음 날 시나리오 테스트"
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "previousTime": "2024-03-21T09:00:00Z",
    "currentTime": "2024-03-22T09:00:00Z",
    "movement": {
      "direction": "forward",
      "amount": 24,
      "unit": "hours"
    }
  }
}
```

### 2.2 시간 초기화
- HTTP 메서드: POST
- 경로: /v1/time-machine/reset
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "previousTime": "2024-03-22T09:00:00Z",
    "currentTime": "2024-03-21T09:00:00Z",
    "isTimeMachineEnabled": false
  }
}
```

## 3. 시간 동기화 API

### 3.1 시간 동기화 상태 조회
- HTTP 메서드: GET
- 경로: /v1/time-machine/sync/status
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "isSynced": true,
    "lastSyncTime": "2024-03-21T09:00:00Z",
    "syncSource": "NTP",
    "offset": 0.005
  }
}
```

### 3.2 시간 동기화 실행
- HTTP 메서드: POST
- 경로: /v1/time-machine/sync
- Headers:
  - Authorization: Bearer {token}
- Content-Type: application/json

#### 요청 (Request)
```json
{
  "source": "NTP",
  "forceSync": true
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "syncResult": "SUCCESS",
    "previousTime": "2024-03-21T09:00:00Z",
    "currentTime": "2024-03-21T09:00:00.005Z",
    "offset": 0.005
  }
}
```

## 4. 설정 관리 API

### 4.1 TimeMachine 설정 조회
- HTTP 메서드: GET
- 경로: /v1/time-machine/settings
- Headers:
  - Authorization: Bearer {token}

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "enabled": true,
    "defaultTimezone": "UTC",
    "syncEnabled": true,
    "syncInterval": 3600,
    "allowedUsers": ["user_123", "user_456"],
    "restrictions": {
      "maxTimeTravel": "30d",
      "minTime": "2024-01-01T00:00:00Z",
      "maxTime": "2024-12-31T23:59:59Z"
    }
  }
}
```

### 4.2 TimeMachine 설정 변경
- HTTP 메서드: PATCH
- 경로: /v1/time-machine/settings
- Headers:
  - Authorization: Bearer {token}
- Content-Type: application/json

#### 요청 (Request)
```json
{
  "enabled": true,
  "defaultTimezone": "Asia/Seoul",
  "syncEnabled": true,
  "syncInterval": 1800,
  "allowedUsers": ["user_123", "user_456", "user_789"],
  "restrictions": {
    "maxTimeTravel": "60d",
    "minTime": "2024-01-01T00:00:00Z",
    "maxTime": "2024-12-31T23:59:59Z"
  }
}
```

#### 응답 (Response)
- 성공 응답 (200 OK)
```json
{
  "status": 200,
  "data": {
    "updated": true,
    "appliedAt": "2024-03-21T09:00:00Z"
  }
}
```

## 5. 오류 코드

| HTTP 상태 코드 | 오류 코드 | 메시지 | 설명 | 대응 방법 |
|--------------|---------|--------|------|---------|
| 400 | 3001 | INVALID_TIME_FORMAT | 잘못된 시간 형식 | 시간 형식 확인 |
| 400 | 3002 | INVALID_TIMEZONE | 잘못된 시간대 | 시간대 확인 |
| 403 | 3003 | TIME_TRAVEL_RESTRICTED | 시간 이동 제한 | 제한 범위 확인 |
| 409 | 3004 | SYNC_IN_PROGRESS | 동기화 진행 중 | 동기화 완료 대기 |
| 503 | 3005 | SYNC_SOURCE_UNAVAILABLE | 동기화 소스 사용 불가 | 다른 소스 사용 |

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |