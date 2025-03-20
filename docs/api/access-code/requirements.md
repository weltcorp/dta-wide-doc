# AccessCode API 요구사항 명세서

## 관련 문서
- [API 개요](./overview.md)
- [API 엔드포인트](./endpoints.md)
- [API 구현 가이드](./implementation.md)
- [API 테스트 명세](./test-spec.md)

## 1. 개요
AccessCode API는 WELT 앱 등록 및 인증을 위한 코드를 생성, 검증, 관리하는 API입니다. 이 API를 통해 관리자는 코드를 생성하고, 사용자는 발급받은 코드를 통해 앱을 등록할 수 있습니다.

## 2. 기능 요구사항

### 2.1 권한 관리
#### 2.1.1 사용자 유형별 권한
- System Admin
  - 모든 액세스 코드 정책 관리 권한
  - 전체 액세스 코드 생성 및 관리 권한
  - 모든 이력 조회 권한
  - 긴급 액세스 코드 발급 권한
  - 권한 위임 및 회수 권한

- IAM Admin
  - 할당된 범위 내 액세스 코드 관리 권한
  - 범위 내 코드 생성 및 재발급 권한
  - 범위 내 코드 상태 관리 권한
  - 범위 내 이력 조회 권한

- Service Account
  - 액세스 코드 검증 권한
  - 코드 상태 조회 권한
  - 대량 코드 검증 권한

- Regular User
  - 자신의 액세스 코드 관리 권한
  - 코드 요청 및 사용 권한
  - 개인 이력 조회 권한

#### 2.1.2 권한 범위 관리
- 글로벌 범위: 전체 시스템
- 조직 범위: 특정 조직 내
- 팀 범위: 특정 팀 내
- 개인 범위: 개인 리소스만

### 2.2 코드 생성
- 관리자는 치료용, 시험용, 데모용 코드를 생성할 수 있어야 함
- 코드는 고유하고 안전한 방식으로 생성되어야 함
- 코드 생성 시 만료 기간을 설정할 수 있어야 함
- 일괄 코드 생성 기능을 제공해야 함

### 2.3 코드 검증
- 코드의 유효성을 검증할 수 있어야 함
- 디바이스 정보와 함께 검증이 이루어져야 함
- 만료된 코드는 사용할 수 없어야 함
- 이미 사용된 코드는 재사용할 수 없어야 함

### 2.4 코드 사용
- 검증된 코드는 특정 사용자와 디바이스에 연결되어야 함
- 코드 사용 시 TimeMachine 서비스와 연동되어야 함
- 코드 사용 이력이 기록되어야 함

### 2.5 개인정보 처리
- GDPR과 개인정보보호법을 준수해야 함
- 개인정보 처리에 대한 동의를 관리해야 함
- 데이터 주체의 권리를 보장해야 함

## 3. 비기능 요구사항

### 3.1 성능
- 권한 검증: 응답시간 50ms 이내
- 코드 생성: 응답시간 500ms 이내
- 코드 검증: 응답시간 200ms 이내
- 코드 사용: 응답시간 300ms 이내
- 일괄 코드 생성: 초당 100개 처리

### 3.2 보안
- 모든 API는 인증이 필요함
- 권한 검증은 모든 요청에서 수행
- IAM 정책 기반 접근 제어
- 권한 변경 이력 추적 및 감사
- 관리자 API는 추가 인증 필요
- 개인정보는 암호화하여 저장
- API 요청/응답 로깅 시 민감정보 마스킹

### 3.3 가용성
- API 가용성 99.9% 이상
- 장애 복구 시간 10분 이내
- 백업 및 복구 계획 수립

### 3.4 확장성
- 수평적 확장 가능한 설계
- 새로운 코드 유형 추가 용이성
- 다국어 지원 가능한 구조

## 4. 제약사항

### 4.1 기술적 제약
- NestJS 프레임워크 사용
- TypeScript strict 모드 적용
- PostgreSQL 데이터베이스 사용
- Redis 캐싱 사용

### 4.2 비즈니스 제약
- 코드 유효기간은 최대 1년
- 동일 사용자당 활성 코드는 1개만 허용
- 일괄 생성은 한 번에 최대 1000개까지 가능
- IAM Admin은 자신의 범위를 벗어난 권한을 위임할 수 없음
- Service Account는 권한 위임 불가
- Regular User는 자신의 리소스만 접근 가능

### 4.3 규제 제약
- GDPR 준수
- 개인정보보호법 준수
- 의료기기 규제 준수

## 5. 용어 정의

### 5.1 코드 상태
- UNUSED: 미사용 상태의 코드
- USED: 사용이 완료된 코드
- EXPIRED: 유효기간이 만료된 코드
- REVOKED: 관리자에 의해 취소된 코드

### 5.2 코드 유형
- WELT: 치료 목적 코드
- CLINICAL_TRIAL: 임상시험용 코드
- DEMO: 데모용 코드

### 5.3 권한 관련 용어
- Scope: 권한의 적용 범위 (글로벌, 조직, 팀, 개인)
- Permission: 특정 작업을 수행할 수 있는 권한
- Role: 권한들의 집합
- Resource: 접근 제어의 대상이 되는 자원

## 6. API 데이터 구조

### 6.1 AccessCode
```typescript
interface AccessCode {
  id: string;
  code: string;
  type: AccessCodeType;
  status: CodeStatus;
  expiresAt: Date;
  userId?: string;
  deviceId?: string;
  creatorId: string;
  createdAt: Date;
  updatedAt: Date;
  usedAt?: Date;
  scope: string;
  permissions: string[];
}
```

### 6.2 AccessCodePermission
```typescript
interface AccessCodePermission {
  id: string;
  accessCodeId: string;
  scope: string;
  permissions: string[];
  grantedBy: string;
  grantedAt: Date;
  expiresAt?: Date;
}
```

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | IAM 권한 관리 요구사항 추가 |
