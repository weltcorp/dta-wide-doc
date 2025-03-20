# 배포 가이드라인

## 1. 배포 환경

### 1.1 환경 구성
- 개발 환경 (Development)
- 스테이징 환경 (Staging)
- 프로덕션 환경 (Production)

### 1.2 환경별 설정
```
environments/
├── development/
│   ├── .env
│   └── docker-compose.yml
├── staging/
│   ├── .env
│   └── docker-compose.yml
└── production/
    ├── .env
    └── docker-compose.yml
```

### 1.3 리전 설정
- DiGA 및 GDPR 규제 준수를 위한 리전 설정
  - 프로덕션 환경: 독일 리전(europe-west3, 프랑크푸르트) 필수
  - 스테이징 환경: 독일 리전(europe-west3, 프랑크푸르트) 권장
  - 개발 환경: 가능한 독일 리전(europe-west3, 프랑크푸르트) 사용 권장
- 개인식별정보(PII)가 포함된 데이터는 모든 환경에서 독일 리전에서만 처리

## 2. 배포 프로세스

### 2.1 빌드 프로세스
```bash
# 의존성 설치
npm install

# 타입 체크
npm run type-check

# 린트 체크
npm run lint

# 테스트 실행
npm run test

# 빌드
npm run build
```

### 2.2 Docker 이미지 생성
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start:prod"]
```

### 2.3 배포 스크립트
```bash
#!/bin/bash

# 환경 변수 로드
source .env

# 이미지 빌드
docker build -t app:latest .

# 이전 컨테이너 중지
docker-compose down

# 새 컨테이너 시작
docker-compose up -d
```

### 2.4 리전 검증 스크립트
```bash
#!/bin/bash

# GCP 리전 검증
CURRENT_REGION=$(gcloud config get-value compute/region)

if [[ "$CURRENT_REGION" != "europe-west3" && "$NODE_ENV" == "production" ]]; then
  echo "ERROR: Production environment must be deployed to europe-west3 region for DiGA/GDPR compliance"
  exit 1
fi

# 데이터베이스 리전 검증
DB_REGION=$(gcloud sql instances describe $DB_INSTANCE --format="value(region)")
if [[ "$DB_REGION" != "europe-west3" && "$NODE_ENV" == "production" ]]; then
  echo "ERROR: Database must be hosted in europe-west3 region for DiGA/GDPR compliance"
  exit 1
fi

# 기타 서비스 리전 검증
# ...

echo "Region compliance check passed"
```

## 3. 환경 설정

### 3.1 환경 변수
```env
# 애플리케이션 설정
NODE_ENV=production
PORT=3000

# 데이터베이스 설정
DB_HOST=localhost
DB_PORT=5432
DB_NAME=app
DB_USER=user
DB_PASSWORD=password
DB_REGION=europe-west3

# Redis 설정
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_REGION=europe-west3

# BigQuery 설정
BIGQUERY_DATASET=de
BIGQUERY_PROJECT=dtx-data
BIGQUERY_LOCATION=europe-west3

# Firestore 설정
FIRESTORE_LOCATION=europe-west3

# JWT 설정
JWT_SECRET=your-secret-key
JWT_EXPIRES_IN=1h

# 이메일 설정
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASS=password
```

### 3.2 설정 검증
```typescript
import { IsString, IsNumber, IsIn } from 'class-validator';

export class EnvironmentConfig {
  @IsNumber()
  PORT: number;

  @IsString()
  DB_HOST: string;
  
  @IsString()
  @IsIn(['europe-west3'], { message: 'DB_REGION must be europe-west3 for DiGA/GDPR compliance' })
  DB_REGION: string;
  
  @IsString()
  @IsIn(['europe-west3'], { message: 'REDIS_REGION must be europe-west3 for DiGA/GDPR compliance' })
  REDIS_REGION: string;
  
  @IsString()
  @IsIn(['europe-west3'], { message: 'BIGQUERY_LOCATION must be europe-west3 for DiGA/GDPR compliance' })
  BIGQUERY_LOCATION: string;
  
  @IsString()
  @IsIn(['europe-west3'], { message: 'FIRESTORE_LOCATION must be europe-west3 for DiGA/GDPR compliance' })
  FIRESTORE_LOCATION: string;

  // ... 기타 설정 검증
}
```

## 4. 모니터링

### 4.1 로깅 설정
```typescript
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

const logger = WinstonModule.createLogger({
  transports: [
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
    }),
  ],
});
```

### 4.2 메트릭스 수집
- Prometheus 설정
- Grafana 대시보드
- 알림 설정

### 4.3 규정 준수 모니터링
- DiGA/GDPR 리전 설정 규정 준수 모니터링
- Cloud Logging을 통한 데이터 액세스 감사 로그 수집
- 리전 위반 자동 알림 설정

## 5. 백업 전략

### 5.1 데이터베이스 백업
```bash
#!/bin/bash

# 백업 디렉토리 생성
BACKUP_DIR="/backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# 데이터베이스 덤프
pg_dump -U $DB_USER -h $DB_HOST $DB_NAME > $BACKUP_DIR/db_backup.sql

# 오래된 백업 삭제
find /backups -type d -mtime +7 -exec rm -rf {} +
```

### 5.2 파일 백업
- 설정 파일 백업
- 로그 파일 백업
- 업로드된 파일 백업

### 5.3 리전 간 백업 제한
- 백업은 EU 내 리전으로만 제한
- 백업 데이터도 DiGA/GDPR 규정 준수 필요
- 백업 보존 정책 준수

## 6. 롤백 전략

### 6.1 자동 롤백
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
```

### 6.2 수동 롤백
```bash
# 이전 버전으로 롤백
kubectl rollout undo deployment/app-deployment

# 특정 버전으로 롤백
kubectl rollout undo deployment/app-deployment --to-revision=2
```

## 7. 보안 설정

### 7.1 보안 헤더
```typescript
app.use(helmet());
app.use(cors());
```

### 7.2 환경 변수 암호화
- AWS KMS 사용
- Vault 사용

### 7.3 데이터 규정 준수
- 개인식별정보(PII) 암호화 저장
- 데이터 액세스 로그 기록
- 데이터 만료 및 삭제 정책 적용
- 국경 간 데이터 전송 방지

## 8. 성능 최적화

### 8.1 캐시 설정
```typescript
@CacheModule({
  store: redisStore,
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  ttl: 60 * 60 * 24, // 24시간
})
```

### 8.2 로드 밸런싱
- Nginx 설정
- 세션 관리
- 헬스 체크

### 8.3 리전별 최적화
- 독일 리전 내 서비스 간 통신 최적화
- 리전 간 지연시간 최소화 전략
- 독일 리전 내 서비스 간 네트워크 토폴로지 최적화

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | DiGA 및 GDPR 규제 준수를 위한 데이터 호스팅 위치 관련 내용 추가 |