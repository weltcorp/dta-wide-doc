# Audit 데이터 저장소 기술 명세

## 1. 개요
Audit 도메인에서는 대량의 감사 로그 데이터를 효율적으로 저장하고 검색하기 위한 데이터 저장소 전략이 필요합니다. 이 문서에서는 Google BigQuery를 활용한 저장소 구현에 대한 기술적 세부 사항을 설명합니다.

## 2. 저장소 아키텍처

### 2.1 데이터 저장소 구조
```
dtx-data
  └── de
      ├── audit_logs (테이블)
      ├── audit_logs_current (파티션 테이블)
      ├── audit_logs_archive (파티션 테이블)
      └── audit_policies (테이블)
```

### 2.2 스키마 정의

#### audit_logs 테이블
```sql
CREATE TABLE `dtx-data.de.audit_logs` (
  id STRING NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  event_type STRING NOT NULL,
  source STRING NOT NULL,
  actor JSON,
  target JSON,
  action STRING NOT NULL,
  details JSON,
  metadata JSON,
  status STRING NOT NULL
)
PARTITION BY DATE(timestamp)
CLUSTER BY event_type, source
OPTIONS (
  description = '감사 로그 데이터',
  require_partition_filter = TRUE,
  partition_expiration_days = 365
);
```

#### audit_policies 테이블
```sql
CREATE TABLE `dtx-data.de.audit_policies` (
  id STRING NOT NULL,
  name STRING NOT NULL,
  description STRING,
  event_types ARRAY<STRING> NOT NULL,
  sources ARRAY<STRING> NOT NULL,
  enabled BOOL NOT NULL,
  retention_period INT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
)
OPTIONS (description = '감사 정책 데이터');
```

### 2.3 파티셔닝 전략
- 날짜(timestamp) 기준 파티셔닝
- 쿼리 성능 최적화를 위한 event_type 및 source 기준 클러스터링
- 보존 기간 설정을 통한 자동 데이터 정리

## 3. 데이터 액세스 패턴

### 3.1 주요 쿼리 패턴
1. **시간 범위 기반 조회**
   ```sql
   SELECT * FROM `de.audit_logs`
   WHERE DATE(timestamp) BETWEEN DATE('2023-01-01') AND DATE('2023-01-31')
   AND event_type IN ('USER_LOGIN', 'USER_LOGOUT')
   ORDER BY timestamp DESC
   LIMIT 100;
   ```

2. **특정 사용자 활동 조회**
   ```sql
   SELECT * FROM `de.audit_logs`
   WHERE DATE(timestamp) BETWEEN DATE('2023-01-01') AND DATE('2023-01-31')
   AND JSON_EXTRACT_SCALAR(actor, '$.id') = 'user-123'
   ORDER BY timestamp DESC;
   ```

3. **특정 리소스 변경 이력 조회**
   ```sql
   SELECT * FROM `de.audit_logs`
   WHERE DATE(timestamp) BETWEEN DATE('2023-01-01') AND DATE('2023-01-31')
   AND JSON_EXTRACT_SCALAR(target, '$.id') = 'resource-456'
   ORDER BY timestamp ASC;
   ```

4. **상관관계 기반 감사 추적**
   ```sql
   SELECT * FROM `de.audit_logs`
   WHERE JSON_EXTRACT_SCALAR(metadata, '$.correlationId') = 'corr-789'
   ORDER BY timestamp ASC;
   ```

### 3.2 인덱싱 전략
- 타임스탬프 필드에 대한 파티션 인덱스
- event_type 및 source 필드에 대한 클러스터링 인덱스
- 자주 사용되는 JSON 필드에 대한 쿼리 최적화 (actor.id, target.id, metadata.correlationId)

## 4. 데이터 보존 및 아카이빙

### 4.1 데이터 라이프사이클
1. **활성 데이터**: 최근 3개월 데이터는 `audit_logs_current` 테이블에 유지
2. **아카이브 데이터**: 3개월 이상 5년 미만 데이터는 `audit_logs_archive` 테이블로 이동
3. **만료 데이터**: 정책에 따라 5년 이상 된 데이터는 자동 삭제

### 4.2 아카이빙 프로세스
```sql
-- 아카이브 데이터 이동 (스케줄링된 쿼리로 실행)
INSERT INTO `de.audit_logs_archive`
SELECT * FROM `de.audit_logs_current`
WHERE DATE(timestamp) < DATE_SUB(CURRENT_DATE(), INTERVAL 3 MONTH);

-- 이동 후 현재 테이블에서 데이터 삭제
DELETE FROM `de.audit_logs_current`
WHERE DATE(timestamp) < DATE_SUB(CURRENT_DATE(), INTERVAL 3 MONTH);
```

### 4.3 보존 정책 적용
```sql
-- 보존 기간이 만료된 데이터 삭제 (각 정책별로 적용)
CREATE OR REPLACE PROCEDURE apply_retention_policy(policy_id STRING)
BEGIN
  DECLARE retention_days INT64;
  DECLARE policy_sources ARRAY<STRING>;
  DECLARE policy_event_types ARRAY<STRING>;
  
  -- 정책 정보 조회
  SELECT retention_period, sources, event_types
  INTO retention_days, policy_sources, policy_event_types
  FROM `de.audit_policies`
  WHERE id = policy_id;
  
  -- 만료된 데이터 삭제
  DELETE FROM `de.audit_logs_archive`
  WHERE DATE(timestamp) < DATE_SUB(CURRENT_DATE(), INTERVAL retention_days DAY)
  AND event_type IN UNNEST(policy_event_types)
  AND source IN UNNEST(policy_sources);
END;
```

## 5. 데이터 마이그레이션 전략

### 5.1 스키마 변경 관리
- 하위 호환성을 유지하는 스키마 변경 적용
- JSON 필드 사용으로 스키마 유연성 확보
- 정확한 버전 관리 및 마이그레이션 스크립트 관리

### 5.2 마이그레이션 프로세스
1. 새 스키마 테이블 생성
2. 데이터 마이그레이션 수행
3. 검증 절차 실행
4. 트래픽 전환
5. 롤백 계획 유지

## 6. 성능 최적화

### 6.1 쿼리 최적화 기법
- 파티션 필터 적극 활용
- 필요한 컬럼만 선택하여 조회
- 데이터 크기를 줄이기 위해 JSON 필드 압축
- 복잡한 분석 쿼리는 구체화된 뷰 활용

### 6.2 비용 최적화 전략
- 쿼리별 비용 모니터링
- 자동 만료 설정으로 스토리지 비용 관리
- 불필요한 스캔 방지를 위한 파티션 필터 필수화
- 데이터 볼륨에 따른 예산 계획 수립

## 7. 보안 고려사항

### 7.1 데이터 접근 제어
- IAM을 통한 세분화된 접근 제어
- 역할 기반 권한 부여
- 로우 레벨 보안 적용 (특정 소스나 액터에 대한 제한)

### 7.2 데이터 암호화
- 저장 데이터 암호화 (Google 기본 제공)
- 민감 정보는 별도 암호화 처리
- 키 관리 전략 수립

### 7.3 데이터 호스팅 위치
- DiGA 및 GDPR 규제 준수를 위한 독일 리전 사용
  - BigQuery 데이터셋 위치를 europe-west3(프랑크푸르트) 리전으로 설정
  - 모든 데이터는 독일 내에서만 처리 및 저장
  - 데이터 처리 작업(쿼리) 실행 시 리전 간 데이터 이동 방지
- 리전 구성 검증
  - BigQuery 데이터셋 생성 시 리전 설정 자동화
  - 정기적인 위치 설정 감사 수행
  - 리전 위반 시 즉시 수정 조치

## 8. 모니터링 및 경고

### 8.1 모니터링 지표
- 데이터 수집 속도
- 쿼리 성능 및 비용
- 스토리지 사용량
- 에러율

### 8.2 경고 설정
- 데이터 수집 중단 감지
- 비정상적 스토리지 증가
- 쿼리 타임아웃 또는 실패
- 비용 예산 초과

## 9. 재해 복구

### 9.1 백업 전략
- 정기 스냅샷 백업
- 다중 리전 복제
- 시점 복구 기능 활용

### 9.2 복구 절차
1. 장애 감지 및 원인 분석
2. 복구 계획 수립
3. 데이터 복원 실행
4. 무결성 검증
5. 서비스 재개

## 10. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|---|-----|-----|
| 0.1.0 | 2025-03-19 | bok@weltcorp.com | 최초 작성 | 
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | DiGA 및 GDPR 규제 준수를 위한 데이터 호스팅 위치 관련 내용 추가 | 