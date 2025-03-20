# API 작성 규약

## 1. API 설계 원칙

### 1.1 URL 구조
- 모든 API 엔드포인트는 `/v1`으로 시작
- 리소스는 복수형 명사 사용 (예: `/users`, `/orders`)
- 다중 단어는 케밥 케이스 사용 (예: `/user-profiles`)
- 계층 구조는 경로로 표현 (예: `/users/{userId}/orders`)

### 1.2 HTTP 메서드
- GET: 리소스 조회
- POST: 리소스 생성
- PUT: 리소스 전체 수정
- PATCH: 리소스 부분 수정
- DELETE: 리소스 삭제

### 1.3 상태 코드
- 200 OK: 성공적인 GET, PUT, PATCH 요청
- 201 Created: 성공적인 POST 요청
- 204 No Content: 성공적인 DELETE 요청
- 400 Bad Request: 잘못된 요청
- 401 Unauthorized: 인증 필요
- 403 Forbidden: 권한 없음
- 404 Not Found: 리소스 없음
- 409 Conflict: 리소스 충돌
- 500 Internal Server Error: 서버 오류

## 2. 응답 형식

### 2.1 성공 응답
```typescript
interface SuccessResponse<T> {
  status: number;    // HTTP 상태 코드
  data: T;          // 응답 데이터
}
```

예시:
```json
{
  "status": 200,
  "data": {
    "id": "user1",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

### 2.2 에러 응답
```typescript
interface ErrorResponse {
  status: number;    // HTTP 상태 코드
  code: number;      // 애플리케이션 에러 코드
  message: string;   // 에러 메시지
  detail?: string;   // 상세 설명
  errors?: {         // 필드별 유효성 검증 에러
    field: string;
    message: string;
  }[];
}
```

예시:
```json
{
  "status": 400,
  "code": 1001,
  "message": "INVALID_INPUT",
  "detail": "Invalid input parameters",
  "errors": [
    {
      "field": "email",
      "message": "Invalid email format"
    }
  ]
}
```

## 3. 페이지네이션

### 3.1 요청 파라미터
- page: 페이지 번호 (1부터 시작)
- size: 페이지 크기
- sort: 정렬 기준 (예: "name:asc,createdAt:desc")

### 3.2 응답 형식
```typescript
interface PaginatedResponse<T> {
  status: number;
  data: {
    items: T[];
    pagination: {
      page: number;
      size: number;
      total: number;
      totalPages: number;
    };
  };
}
```

## 4. 검색 및 필터링

### 4.1 검색 파라미터
- q: 검색어
- filter: 필터 조건 (예: "status:active,type:premium")

### 4.2 필터 연산자
- eq: 같음
- ne: 같지 않음
- gt: 초과
- gte: 이상
- lt: 미만
- lte: 이하
- in: 포함
- nin: 미포함

## 5. 버전 관리

### 5.1 버전 표기
- URL 경로에 버전 명시 (예: /v1/users)
- 메이저 버전만 URL에 포함
- 마이너 버전은 헤더로 처리 (X-API-Version)

### 5.2 하위 호환성
- 기존 필드 제거 금지
- 필수 필드 추가 시 새 버전 생성
- 응답 필드 확장은 하위 호환성 유지

## 6. 보안

### 6.1 인증
- Bearer 토큰 사용
- Authorization 헤더 사용
- 토큰 만료 시간 설정

### 6.2 권한 검사
- RBAC (Role-Based Access Control) 구현
- 리소스별 권한 정의
- 세분화된 접근 제어

### 6.3 IAM 역할 관리
- 모든 API는 IAM 역할 기반의 접근 제어 적용
- IAM 역할은 아래와 같은 계층 구조로 정의
  - System Admin: 전체 시스템 관리 권한
  - IAM Admin: 사용자 권한 관리
  - Org Admin: 특정 조직 내 관리 권한
  - Team Admin: 특정 팀 내 관리 권한
  - Regular User: 일반 사용자 권한
- 각 역할별 접근 가능 범위 지정
  - 전체 접근: 모든 리소스 접근 가능
  - 범위 내 접근: 할당된 조직/팀 범위 내에서만 접근 가능
  - 자신만 접근: 자신의 리소스에만 접근 가능

### 6.4 권한 위임 및 승인
- 역할 할당/회수 요청 시 승인 프로세스 적용
- 승인 레벨 정의 (자동 승인, 단일 승인, 다중 승인)
- 권한 남용 방지를 위한 감사 로깅

## 7. 성능

### 7.1 캐싱
- ETag 헤더 사용
- Cache-Control 헤더 설정
- 적절한 캐시 만료 시간 설정
- Cloud CDN 활용 고려

### 7.2 압축
- gzip 압축 사용
- 대용량 응답 처리
- 청크 전송 고려

### 7.3 Cloud Run 최적화
- 콜드 스타트 최소화
  - 이미지 크기 최적화
  - 초기화 시간 단축
  - 워밍업 엔드포인트 구현
- 자동 스케일링 설정
  - 최소/최대 인스턴스 수 설정
  - 동시성 레벨 조정
- 메모리 사용량 최적화
  - 메모리 누수 방지
  - 가비지 컬렉션 튜닝
- 요청 타임아웃 설정
  - Cloud Run 최대 타임아웃: 60분
  - 일반적인 API 응답: 30초 이내

## 8. 문서화

### 8.1 Swagger/OpenAPI
- 모든 API 엔드포인트 문서화
- 요청/응답 스키마 정의
- 예제 포함

### 8.2 에러 코드
- 모든 에러 코드 문서화
- 에러 발생 조건 설명
- 해결 방법 제시

### 8.3 접근 권한 매트릭스
- 모든 도메인 API 문서에는 엔드포인트 접근 권한 매트릭스 포함
- 매트릭스 형식으로 각 엔드포인트별 역할 접근 권한 명시
- 권한 표기는 다음과 같은 기호로 통일
  - ✓: 접근 가능
  - ✘: 접근 불가
  - 범위 내: 할당된 조직/팀 범위 내에서만 접근 가능
  - 자신만: 자신의 데이터에만 접근 가능
- 권한 제한이 있는 경우 괄호 안에 추가 설명 기재 (예: 범위 내(제한적))

## 9. 배포 환경

### 9.1 Cloud Run 설정 (TBD)
- 리전: asia-northeast3 (서울)
- 최소 인스턴스: 0
- 최대 인스턴스: 자동 스케일링
- 메모리: 512MB ~ 2GB
- CPU: 1-2
- 타임아웃: 300초
- HTTPS 강제
- 인그레스: all
- VPC 연결: Serverless VPC Access

### 9.2 환경 구성
- 개발(dev)
  - 도메인: api-dev.example.com
  - 자동 배포 (main 브랜치)
- 스테이징(staging)
  - 도메인: api-staging.example.com
  - 수동 배포 (릴리즈 태그)
- 프로덕션(prod)
  - 도메인: api.example.com
  - 수동 배포 (릴리즈 태그)

### 9.3 모니터링
- Cloud Monitoring
  - 요청 지연 시간
  - 에러율
  - 인스턴스 수
  - 메모리 사용량
- Cloud Logging
  - 구조화된 로깅
  - 에러 추적
  - 감사 로그

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | Cloud Run 관련 내용 추가 및 Kubernetes 관련 내용 제거 | 
| 0.3.0 | 2025-03-20 | bok@weltcorp.com | IAM 및 접근 권한 매트릭스 관련 내용 추가 |