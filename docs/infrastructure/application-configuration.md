# 애플리케이션 구성 및 환경 설정

## 개요
이 문서는 애플리케이션의 환경 설정 및 구성 메커니즘을 설명합니다.

## 환경 변수

애플리케이션은 다음 환경 변수를 사용합니다:

| 환경 변수 | 설명 | 기본값 |
|----------|------|--------|
| PORT | 애플리케이션 리스닝 포트 | 3000 |
| RUNTIME_ENV | 실행 환경 (LOCAL, DEV, STAGE, PROD) | - |
| API_PREFIX | API 경로 접두사 | v1 |
| API_HOST | API 호스트 주소 (비 로컬 환경용) | - |
| SERVICE_NAME | 서비스 이름 | dta-wir-api-ts |
| GOOGLE_APPLICATION_CREDENTIALS | GCP 인증 정보 경로 | - |
| CLOUD_PROJECT_ID | GCP 프로젝트 ID | dta-cloud-dev |

## 환경별 구성

### 로컬 환경
- Swagger UI: `http://localhost:{PORT}/v1/docs`
- API 엔드포인트: `http://localhost:{PORT}/v1/*`

### 개발/스테이징/프로덕션 환경
- Swagger UI: `{API_HOST}/v1/docs`
- API 엔드포인트: `{API_HOST}/v1/*`

## Google Cloud 인증

애플리케이션은 다음 로직으로 Google Cloud 인증을 설정합니다:

- 로컬 환경: `{workspaceRoot}/apps/{serviceName}/{credentialsPath}`
- 클라우드 환경: `/app/{credentialsPath}`

## OpenTelemetry 설정 (현재 비활성화)

애플리케이션은 OpenTelemetry 통합을 위한 코드가 준비되어 있으나 현재 비활성화되어 있습니다. 
활성화 시 Google Cloud Trace와 연동하여 분산 추적을 지원합니다.

## 관련 아티팩트

- `main.ts`: 초기화 및 환경 설정 로딩
- `.env` 파일: 환경 변수 기본값