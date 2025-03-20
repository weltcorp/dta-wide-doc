# 모니터링 가이드

## 애플리케이션 부트스트랩 모니터링

애플리케이션 부트스트랩 과정은 주요 진단 지점입니다. 
다음 로그 패턴을 모니터링하여 애플리케이션 시작 문제를 감지할 수 있습니다:

### 정상 시작 로그 패턴
Starting dta-wir-api-ts bootstrap
Creating NestJS application
Getting ConfigService
Setting up Google Cloud authentication
Setting global prefix
Setting up Swagger
Setting up global pipes
Getting port from config
Attempting to listen on port 3000
🚀 Application is running on: http://localhost:3000/v1



### 오류 패턴
Failed during bootstrap: [오류 메시지]
Failed to set up Swagger: [오류 메시지]
Unhandled error during bootstrap: [오류 메시지]
Bootstrap timed out after 30000ms


## OpenTelemetry 모니터링 (향후 활성화 시)
애플리케이션에는 OpenTelemetry 기반 분산 추적 기능이 코드에 포함되어 있으나 현재 비활성화되어 있습니다.
활성화 시 Cloud Trace에서 다음 정보를 확인할 수 있습니다:

1. 애플리케이션 초기화 스팬
2. HTTP 요청 추적
3. NestJS/Express 미들웨어 성능 지표