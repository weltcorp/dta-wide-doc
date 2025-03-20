# ADR 7: Redis 캐시 전략

## 상태
승인됨 (2025-03-16)

## 컨텍스트
- 고성능 캐시 시스템 필요
- 세션 관리 필요
- 실시간 데이터 처리 필요
- 분산 락 구현 필요
- TimeMachine 시간 동기화 필요
- 메모리 효율성 고려 필요

## 결정
Redis를 주요 캐시 및 세션 스토어로 선택

### 주요 기능 활용
1. 캐시 전략
   - 응답 캐시
   - 데이터베이스 쿼리 캐시
   - 세션 스토어
   - 분산 락

2. 데이터 구조
   - Strings: 단순 캐시
   - Hashes: 사용자 세션
   - Lists: 작업 큐
   - Sets: 고유 값 관리
   - Sorted Sets: 순위 관리

3. 시간 관리
   - TTL 기반 만료
   - 자동 삭제
   - 이벤트 알림

4. 운영 기능
   - 영속성 설정
   - 복제 구성
   - 모니터링
   - 백업

### 구현 예시
```typescript
// 캐시 서비스 예시
@Injectable()
export class CacheService {
  constructor(
    private readonly redis: Redis,
    private readonly config: ConfigService,
  ) {}

  async get<T>(key: string): Promise<T | null> {
    const data = await this.redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.redis.set(
      key,
      JSON.stringify(value),
      'EX',
      ttl || this.config.get('redis.defaultTTL'),
    );
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }
}

// TimeMachine 시간 관리 예시
@Injectable()
export class TimeMachineService {
  constructor(private readonly redis: Redis) {}

  async getCurrentTime(userId: string): Promise<Date> {
    const time = await this.redis.get(`time:${userId}`);
    return time ? new Date(time) : new Date();
  }

  async setCurrentTime(userId: string, time: Date): Promise<void> {
    await this.redis.set(`time:${userId}`, time.toISOString());
  }
}
```

## 결과
### 긍정적
- 고성능
- 다양한 데이터 구조
- 원자적 연산 지원
- 분산 환경 지원
- 간단한 설정
- 활성화된 커뮤니티
- 풍부한 클라이언트
- NestJS 통합 용이

### 부정적
- 메모리 제한
- 영속성 관리 필요
- 데이터 일관성 관리
- 운영 복잡도

## 대안
1. Memcached
2. Hazelcast
3. Ehcache
4. Node.js 내장 캐시

## 관련 결정
- ADR 2: 모듈형 모놀리스 아키텍처 채택
- ADR 5: NestJS 프레임워크 사용
- ADR 6: PostgreSQL 데이터베이스 선택

## 구현 가이드라인
1. 캐시 전략
   - 적절한 TTL 설정
   - 캐시 무효화 정책
   - 캐시 키 네이밍
   - 메모리 사용량 관리

2. 보안 설정
   - 접근 제어
   - 네트워크 보안
   - 데이터 암호화
   - 인증 설정

3. 모니터링
   - 메모리 사용량
   - 히트율
   - 연결 상태
   - 성능 메트릭스

4. 장애 대응
   - 장애 복구 절차
   - 백업 전략
   - 페일오버 설정
   - 알림 구성

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |