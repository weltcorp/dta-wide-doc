# 시스템 문서

## 개요
이 디렉토리는 시스템의 전체 문서를 포함하고 있습니다. DDD(Domain-Driven Design) 원칙에 따라 구조화되어 있으며, 도메인 모델, 아키텍처, API, 인프라, 운영 문서를 포함합니다.

## 문서 구조

```
docs/
├── domains/                    # 도메인 문서
│   ├── overview.md           # 도메인 전체 개요
│   ├── glossary.md          # 용어 사전
│   ├── user/                # 사용자 도메인
│   │   ├── overview.md     # 도메인 개요
│   │   ├── bounded-context.md  # 바운디드 컨텍스트
│   │   ├── domain-model.md    # 도메인 모델
│   │   ├── business-rules.md  # 비즈니스 규칙
│   │   └── technical-spec/    # 기술 명세
│   ├── auth/                # 인증 도메인
│   ├── access-code/         # 접근 코드 도메인
│   └── time-machine/       # 시간 관리 도메인
│
├── api/                    # API 문서
│   ├── overview.md        # API 설계 원칙
│   ├── conventions.md     # API 작성 규약
│   ├── user/             # 사용자 API
│   ├── auth/            # 인증 API
│   ├── access-code/     # 접근 코드 API
│   └── time-machine/    # 시간 관리 API
│
├── architecture/          # 아키텍처 문서
│   ├── overview.md       # 아키텍처 개요
│   ├── principles.md     # 설계 원칙
│   └── decisions/       # 아키텍처 결정 기록(ADR)
│
├── infrastructure/       # 인프라 문서
│   ├── cloud-run.md     # Cloud Run 설정
│   ├── monitoring.md    # 모니터링
│   └── security.md      # 보안 구성
│
└── operations/          # 운영 문서
    ├── runbook.md      # 운영 매뉴얼
    ├── monitoring.md    # 모니터링 가이드
    └── incident.md     # 장애 대응 가이드
```

## 문서 작성 가이드라인

### 1. 도메인 문서
- 도메인 개요 및 책임 정의
- 바운디드 컨텍스트 정의
- 도메인 모델과 비즈니스 규칙
- 기술 명세 및 구현 가이드
- 도메인 간 통합 및 이벤트 정의

### 2. API 문서
- RESTful API 설계 원칙
- 엔드포인트 명세
- 요청/응답 형식
- 에러 처리 방식
- API 버전 관리
- 보안 및 인증

### 3. 아키텍처 문서
- 시스템 구조와 설계 원칙
- 주요 기술 결정사항과 이유
- 컴포넌트 간 관계
- 성능, 보안, 확장성 고려사항
- 이벤트 기반 아키텍처 (GCP Pub/Sub)

### 4. 인프라 문서
- Cloud Run 배포 구성
  - 리전: asia-northeast3 (서울)
  - 최소/최대 인스턴스 설정
  - 메모리 및 CPU 할당
  - 타임아웃 설정
- Cloud SQL 설정
- Cloud Memorystore 구성
- Cloud CDN 설정
- VPC 및 네트워크 구성

### 5. 운영 문서
- 시스템 운영 절차
- 모니터링 방법
- 장애 대응 절차
- 유지보수 가이드
- 로깅 및 추적

## 문서 관리 규칙

1. **버전 관리**
   - 모든 문서는 Git을 통해 버전 관리
   - 주요 변경사항은 커밋 메시지에 명확히 기록
   - 변경 이력은 각 문서 하단에 기록

2. **검토 프로세스**
   - 모든 문서 변경은 리뷰 필요
   - 주요 변경은 관련 팀의 승인 필요
   - 변경 사항은 관련 팀에 공유

3. **문서 포맷**
   - 마크다운 형식 사용
   - 다이어그램은 mermaid 사용
   - 코드 예제는 실행 가능한 형태로 제공

## 기술 스택

### 백엔드
- NestJS
- TypeScript
- PostgreSQL
- Redis
- GCP Pub/Sub (이벤트 메시징)

### 인프라
- Google Cloud Platform (GCP)
  - Cloud Run (서버리스 컨테이너)
  - Cloud SQL (관리형 PostgreSQL)
  - Cloud Memorystore (관리형 Redis)
  - Cloud CDN
  - Cloud Build (CI/CD)
  - Cloud Monitoring
  - Cloud Logging

### 모니터링
- Cloud Monitoring
- Cloud Logging
- Error Reporting
- Cloud Trace

## 변경 이력

| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-15 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-16 | bok@weltcorp.com | Cloud Run 기반 인프라 문서 업데이트 |