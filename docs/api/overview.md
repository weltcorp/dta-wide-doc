# API 개요

## 소개
이 문서는 시스템의 API 설계 원칙과 공통 사항을 정의합니다. 모든 API는 이 문서에서 정의한 규칙을 따라야 합니다.

## API 설계 원칙

### 1. RESTful 원칙
- 리소스 중심의 URL 설계
- 적절한 HTTP 메서드 사용
- 상태 코드의 올바른 사용
- HATEOAS 원칙 준수

### 2. 버전 관리
- 모든 API는 `/v1`으로 시작
- 하위 호환성이 깨질 경우 메이저 버전 업
- URL 경로에 버전 명시 (예: `/v1/users`)

### 3. 명명 규칙
- 복수형 명사로 리소스 표현 (예: `/users`)
- 소문자와 하이픈 사용 (예: `/user-profiles`)
- 일관된 명명 규칙 사용

## 공통 응답 형식

### 성공 응답
```json
{
  "status": 200,
  "data": {
    // 응답 데이터
  }
}
```

### 에러 응답
```json
{
  "status": 404,
  "code": 1000,
  "message": "RESOURCE_NOT_FOUND",
  "detail": "The requested resource was not found in the system"
}
```

#### 유효성 검증 에러 응답 예시
```json
{
  "status": 400,
  "code": 1001,
  "message": "VALIDATION_ERROR",
  "detail": "The request contains invalid parameters",
  "errors": [
    {
      "field": "email",
      "message": "Invalid email format"
    },
    {
      "field": "password",
      "message": "Password must be at least 8 characters"
    }
  ]
}
```

## HTTP 상태 코드

| 상태 코드 | 설명 | 사용 시점 |
|----------|------|-----------|
| 200 | OK | 요청 성공 |
| 201 | Created | 리소스 생성 성공 |
| 204 | No Content | 성공했지만 응답 본문 없음 |
| 400 | Bad Request | 잘못된 요청 |
| 401 | Unauthorized | 인증 필요 |
| 403 | Forbidden | 권한 없음 |
| 404 | Not Found | 리소스를 찾을 수 없음 |
| 500 | Internal Server Error | 서버 오류 |

## API 문서화

### 1. 문서 구조
- API 개요
- 요청/응답 형식
- 에러 코드
- 예제 코드
- 테스트 방법

### 2. Swagger/OpenAPI
- API 문서 자동화
- 테스트 환경 제공
- 스키마 정의
- 예제 포함

## 보안

### 1. 인증
- JWT 기반 인증
- API 키 인증 (B2B)
- OAuth2.0 지원
- 컨센트 토큰 기반 권한 위임

### 2. 권한 관리
- 역할 기반 접근 제어 (RBAC)
- 리소스별 권한 관리
- API 엔드포인트별 권한 설정
- 컨센트 토큰 기반 범위 제한

### 3. IAM 역할 및 권한
- 표준화된 역할 정의
  - System Admin: 전체 시스템 관리 권한
  - IAM Admin: 사용자 권한 관리
  - Org Admin: 특정 조직 내 관리 권한
  - Team Admin: 특정 팀 내 관리 권한
  - Regular User: 일반 사용자 권한
- 모든 API는 IAM 역할 기반 접근 제어 적용
- 역할별 접근 범위 정의
  - 전체 접근: 모든 리소스 접근
  - 범위 내 접근: 할당된 조직/팀 내 리소스만 접근
  - 자신만 접근: 자신의 리소스만 접근
- 모든 도메인별 API 문서에는 접근 권한 매트릭스 포함 필수

### 4. 컨센트 토큰
- 사용자 동의 기반 권한 위임
- 범위(scope) 기반 접근 제어
- 목적 기반 권한 관리
- 만료 시간 자동 관리

## 성능

### 1. 응답 시간
- 95% 요청: 300ms 이내
- 99% 요청: 500ms 이내
- 최대 응답 시간: 1초

### 2. 처리량
- 초당 최소 1000 요청 처리
- 동시 사용자 10000명 지원

### 3. 캐싱
- 응답 캐싱 전략
- ETags 사용
- 캐시 무효화 정책

## API 도메인 구조

```
/v1
├── /users                        # 사용자 관리
│   ├── /{userId}                # 사용자 정보 관리
│   ├── /{userId}/devices        # 디바이스 관리
│   └── /{userId}/password       # 비밀번호 관리
│
├── /auth                         # 인증 도메인
│   ├── /app-token               # 앱 토큰 발급
│   │   └── /{appId}            # 앱 토큰 조회
│   ├── /terms                   # 약관 관리
│   │   └── /agreement          # 약관 동의 저장
│   ├── /email                   # 이메일 인증
│   │   ├── /verification-code  # 인증 코드 발송
│   │   └── /verify             # 인증 코드 확인
│   ├── /login                   # 로그인
│   ├── /logout                  # 로그아웃
│   ├── /token                   # 토큰 관리
│   │   ├── /refresh            # 토큰 갱신
│   │   └── /validate           # 토큰 검증
│   ├── /permissions            # 권한 관리
│   │   └── /check              # 권한 확인
│   └── /consent-tokens         # 컨센트 토큰
│       └── /device             # 디바이스 기반 컨센트 토큰
│
├── /iam                          # IAM 관리
│   ├── /roles                   # 역할 관리
│   │   ├── /{roleId}           # 역할 정보 관리
│   │   └── /{roleId}/permissions # 역할별 권한 관리
│   ├── /users                   # 사용자 역할 관리
│   │   └── /{userId}/roles     # 사용자별 역할 할당
│   ├── /organizations          # 조직 관리
│   │   ├── /{orgId}            # 조직 정보 관리
│   │   └── /{orgId}/members    # 조직 멤버 관리
│   └── /teams                   # 팀 관리
│       ├── /{teamId}           # 팀 정보 관리
│       └── /{teamId}/members   # 팀 멤버 관리
│
├── /time-machine                 # 시간 관리
│   ├── /current-time            # 현재 시간 조회
│   ├── /set-time                # 시간 설정
│   ├── /move                    # 시간 이동
│   ├── /reset                   # 시간 초기화
│   ├── /sync                    # 시간 동기화 실행
│   │   └── /status             # 동기화 상태 조회
│   └── /settings                # 설정 관리
│
├── /access-codes                 # 접근 코드
│   ├── /validate                # 코드 검증
│   ├── /{codeId}/use            # 코드 사용
│   ├── /batch                   # 일괄 코드 생성
│   └── /personal-data           # 개인정보 관리
│       └── /{userId}            # 사용자별 개인정보
│
└── /security                    # 보안 관리
```

## API 문서 링크

### 사용자 도메인
- [사용자 API](./user/endpoints.md)
- [디바이스 관리 API](./user/endpoints.md#1-디바이스-관리-api)
- [사용자 정보 관리 API](./user/endpoints.md#2-사용자-정보-관리-api)

### 인증 도메인
#### 앱 인증
- [앱 인증 프로세스](./auth/endpoints.md#0-앱-인증-프로세스)
- [앱 토큰 발급](./auth/endpoints.md#01-앱-토큰-발급)
- [앱 토큰 조회](./auth/endpoints.md#02-앱-토큰-조회)

#### 회원가입
- [회원가입 프로세스](./auth/endpoints.md#1-회원가입-프로세스)
- [약관 목록 조회](./auth/endpoints.md#11-약관-목록-조회)
- [약관 동의 저장](./auth/endpoints.md#12-약관-동의-저장)
- [이메일 인증 코드 발송](./auth/endpoints.md#13-이메일-인증-코드-발송)
- [이메일 인증 코드 확인](./auth/endpoints.md#14-이메일-인증-코드-확인)

#### 로그인 및 인증
- [로그인 및 인증 프로세스](./auth/endpoints.md#2-로그인-및-인증-프로세스)
- [로그인](./auth/endpoints.md#21-로그인)
- [토큰 갱신](./auth/endpoints.md#22-토큰-갱신)
- [토큰 검증](./auth/endpoints.md#23-토큰-검증)
- [로그아웃](./auth/endpoints.md#24-로그아웃)

#### 권한 및 동의 관리
- [권한 및 동의 관리 프로세스](./auth/endpoints.md#3-권한-및-동의-관리-프로세스)
- [권한 확인](./auth/endpoints.md#31-권한-확인)
- [컨센트 토큰 관리](./auth/endpoints.md#32-컨센트-토큰-생성-deviceid-기반)

### 시간 관리 도메인
- [시간 조회/설정 API](./time-machine/endpoints.md#1-시간-조회설정-api)
- [현재 시간 조회](./time-machine/endpoints.md#11-현재-시간-조회)
- [시간 설정](./time-machine/endpoints.md#12-시간-설정)
- [시간 조작 API](./time-machine/endpoints.md#2-시간-조작-api)
- [시간 이동](./time-machine/endpoints.md#21-시간-이동)
- [시간 초기화](./time-machine/endpoints.md#22-시간-초기화)
- [시간 동기화 API](./time-machine/endpoints.md#3-시간-동기화-api)
- [시간 동기화 상태 조회](./time-machine/endpoints.md#31-시간-동기화-상태-조회)
- [시간 동기화 실행](./time-machine/endpoints.md#32-시간-동기화-실행)
- [설정 관리 API](./time-machine/endpoints.md#4-설정-관리-api)
- [TimeMachine 설정 조회](./time-machine/endpoints.md#41-timemachine-설정-조회)
- [TimeMachine 설정 변경](./time-machine/endpoints.md#42-timemachine-설정-변경)

### 접근 코드 도메인
- [접근 코드 API 개요](./access-code/endpoints.md#1-개요)
- [개인정보 처리 정책](./access-code/endpoints.md#2-개인정보-처리-정책)
- [코드 생성 API](./access-code/endpoints.md#51-코드-생성-api)
- [코드 검증 API](./access-code/endpoints.md#52-코드-검증-api)
- [코드 사용 API](./access-code/endpoints.md#53-코드-사용-api-내부-서비스-통신용)
- [일괄 코드 생성 API](./access-code/endpoints.md#54-일괄-코드-생성-api)
- [개인정보 보호 API](./access-code/endpoints.md#8-개인정보-보호-api)

### 보안 관리
- [DeviceId 관련 보안 정책](./security/endpoints.md)
- [보안 요구사항](./security/requirements.md)

### IAM 도메인
- [IAM API 개요](./iam/overview.md)
- [역할 관리 API](./iam/endpoints.md#1-역할-관리-api)
- [사용자 역할 관리 API](./iam/endpoints.md#2-사용자-역할-관리-api)
- [조직 관리 API](./iam/endpoints.md#3-조직-관리-api)
- [팀 관리 API](./iam/endpoints.md#4-팀-관리-api)

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | IAM 추가 |