# TimeMachine 도메인 구현 가이드

## 1. 도메인 구조

```
src/domains/time-machine/
├── domain/                 # 도메인 계층
│   ├── entity/
│   │   └── time-context.entity.ts
│   ├── value-object/
│   │   └── time-machine-options.vo.ts
│   └── repository/
│       └── time-context.repository.ts
├── application/           # 응용 계층
│   ├── service/
│   │   └── time-machine.service.ts
│   └── dto/
│       ├── time-context.dto.ts
│       └── time-machine.dto.ts
├── infrastructure/        # 인프라 계층
│   ├── persistence/
│   │   └── typeorm-time-context.repository.ts
│   ├── cache/
│   │   └── redis-time-machine.cache.ts
│   └── event/
│       └── time-machine.event.ts
└── presentation/         # 프레젠테이션 계층
    ├── controller/
    │   └── time-machine.controller.ts
    └── error/
        └── time-machine.error.ts
```

## 2. 엔티티 및 값 객체 정의

### 2.1 TimeContext 엔티티
```typescript
@Entity('time_context')
export class TimeContext {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'user_id', nullable: true })
  userId?: number;

  @Column({ name: 'device_id', nullable: true })
  deviceId?: string;

  @Column({ name: 'base_time', type: 'timestamp with time zone' })
  baseTime: Date;

  @Column({ name: 'offset_ms' })
  offsetMs: number;

  @Column()
  timezone: string;

  @Column({ name: 'last_modified', type: 'timestamp with time zone' })
  lastModified: Date;

  @Column({ name: 'created_at', type: 'timestamp with time zone' })
  createdAt: Date;

  getCurrentTime(): Date {
    const now = new Date();
    return new Date(now.getTime() + this.offsetMs);
  }

  setOffset(offsetMs: number): void {
    this.offsetMs = offsetMs;
    this.lastModified = new Date();
  }
}
```

### 2.2 TimeMachineOptions 값 객체
```typescript
export class TimeMachineOptions {
  constructor(
    public readonly timezone: string,
    public readonly offsetMs: number = 0,
    public readonly userId?: number,
    public readonly deviceId?: string,
  ) {}

  static createDefault(): TimeMachineOptions {
    return new TimeMachineOptions('UTC');
  }

  withOffset(offsetMs: number): TimeMachineOptions {
    return new TimeMachineOptions(
      this.timezone,
      offsetMs,
      this.userId,
      this.deviceId,
    );
  }
}
```

## 3. 리포지토리 인터페이스

```typescript
export interface ITimeContextRepository {
  save(context: TimeContext): Promise<TimeContext>;
  findByUserId(userId: number): Promise<TimeContext | null>;
  findByDeviceId(deviceId: string): Promise<TimeContext | null>;
  update(id: number, context: Partial<TimeContext>): Promise<TimeContext>;
  delete(id: number): Promise<void>;
}
```

## 4. 서비스 구현

```typescript
@Injectable()
export class TimeMachineService {
  constructor(
    @Inject('ITimeContextRepository')
    private readonly timeContextRepository: ITimeContextRepository,
    private readonly cacheService: TimeMachineCacheService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async getCurrentTime(options: TimeMachineOptions): Promise<Date> {
    const cacheKey = this.getCacheKey(options);
    const cachedTime = await this.cacheService.get(cacheKey);
    
    if (cachedTime) {
      return new Date(cachedTime);
    }

    const context = await this.getTimeContext(options);
    const currentTime = context.getCurrentTime();
    
    await this.cacheService.set(cacheKey, currentTime.toISOString());
    return currentTime;
  }

  async setTime(userId: number, targetTime: Date, reason: string): Promise<void> {
    const context = await this.timeContextRepository.findByUserId(userId);
    if (!context) {
      throw new TimeContextNotFoundException(userId);
    }

    const oldTime = context.getCurrentTime();
    const offsetMs = targetTime.getTime() - new Date().getTime();
    
    context.setOffset(offsetMs);
    await this.timeContextRepository.update(context.id, context);
    
    this.eventEmitter.emit('time.set', {
      userId,
      oldTime,
      newTime: targetTime,
      reason,
    });

    await this.cacheService.invalidate(userId);
  }

  private getCacheKey(options: TimeMachineOptions): string {
    if (options.userId) {
      return `time:user:${options.userId}`;
    }
    return `time:device:${options.deviceId}`;
  }

  private async getTimeContext(options: TimeMachineOptions): Promise<TimeContext> {
    let context: TimeContext | null = null;

    if (options.userId) {
      context = await this.timeContextRepository.findByUserId(options.userId);
    } else if (options.deviceId) {
      context = await this.timeContextRepository.findByDeviceId(options.deviceId);
    }

    if (!context) {
      context = new TimeContext();
      context.timezone = options.timezone;
      context.offsetMs = options.offsetMs;
      context.userId = options.userId;
      context.deviceId = options.deviceId;
      context.baseTime = new Date();
      context.lastModified = new Date();
      context.createdAt = new Date();
      
      return this.timeContextRepository.save(context);
    }

    return context;
  }
}
```

## 5. 컨트롤러 구현

```typescript
@Controller('v1/time-machine')
export class TimeMachineController {
  constructor(private readonly timeMachineService: TimeMachineService) {}

  @Get('current-time')
  async getCurrentTime(
    @Query('userId') userId?: number,
    @Query('deviceId') deviceId?: string,
    @Query('timezone') timezone: string = 'UTC',
  ): Promise<SuccessResponse<CurrentTimeResponseDto>> {
    const options = new TimeMachineOptions(timezone, 0, userId, deviceId);
    const currentTime = await this.timeMachineService.getCurrentTime(options);

    return {
      status: 200,
      data: {
        currentTime: currentTime.toISOString(),
        timezone: options.timezone,
        offset: options.offsetMs,
      },
    };
  }

  @Post('set-time')
  @UseGuards(AdminGuard)
  async setTime(
    @Body() dto: SetTimeRequestDto,
  ): Promise<SuccessResponse<void>> {
    await this.timeMachineService.setTime(
      dto.userId,
      new Date(dto.targetTime),
      dto.reason,
    );

    return {
      status: 200,
      data: null,
    };
  }
}
```

## 6. 이벤트 처리

```typescript
@Injectable()
export class TimeMachineEventHandler {
  constructor(private readonly cacheService: TimeMachineCacheService) {}

  @OnEvent('time.set')
  async handleTimeSet(payload: TimeSetEvent) {
    await this.cacheService.invalidate(payload.userId);
  }

  @OnEvent('time.context.changed')
  async handleContextChanged(payload: TimeContextChangedEvent) {
    await this.cacheService.invalidate(payload.userId);
  }
}
```

## 7. 캐싱 전략

```typescript
@Injectable()
export class TimeMachineCacheService {
  constructor(
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
  ) {}

  async get(key: string): Promise<string | null> {
    return this.cacheManager.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    await this.cacheManager.set(key, value, { ttl: 60 }); // 60초 캐시
  }

  async invalidate(userId: number): Promise<void> {
    await this.cacheManager.del(`time:user:${userId}`);
  }
}
```

## 8. 에러 처리

```typescript
export class TimeMachineError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly detail?: string,
  ) {
    super(message);
  }
}

@Catch(TimeMachineError)
export class TimeMachineErrorFilter implements ExceptionFilter {
  catch(exception: TimeMachineError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    response.status(400).json({
      status: 400,
      code: exception.code,
      message: exception.message,
      detail: exception.detail,
    });
  }
}
```

## 9. 모니터링

```typescript
@Injectable()
export class TimeMachineMetricsService {
  private readonly histogram: Histogram;

  constructor() {
    this.histogram = new Histogram({
      name: 'time_machine_response_time',
      help: 'Time Machine API response time in seconds',
      labelNames: ['endpoint'],
    });
  }

  recordResponseTime(endpoint: string, duration: number): void {
    this.histogram.labels(endpoint).observe(duration);
  }
}
```

## 10. 성능 최적화

### 10.1 데이터베이스 인덱스
```sql
CREATE INDEX idx_time_context_user_id ON time_context(user_id);
CREATE INDEX idx_time_context_device_id ON time_context(device_id);
```

### 10.2 N+1 쿼리 방지
- 시간 컨텍스트 조회 시 한 번의 쿼리로 모든 관련 데이터를 로드
- 배치 작업 시 벌크 연산 사용

## 6. 데이터 보안 및 규정 준수

### 6.1 데이터 호스팅 위치
- DiGA 및 GDPR 규제 준수를 위한 독일 리전 사용
  - Redis(Memorystore): europe-west3(프랑크푸르트) 리전 인스턴스 사용
    - 시간 오프셋 및 시간 설정 데이터 저장
    - 테스트 시나리오 시간 데이터 관리
    - 임시 데이터이지만 시스템 전체에 영향을 미치므로 독일 리전 필수
  - 데이터 처리 작업의 지역적 제한
    - 시간 관련 데이터 처리는 독일 리전 내에서만 수행
    - 시스템 전체의 시간 관리가 독일 리전에서 이루어지도록 보장
- 리전 구성 검증
  - 인프라 배포 시 리전 설정 자동 검증
  - 정기적인 규정 준수 감사 수행
  - 규정 위반 시 즉시 시정 조치 및 보고

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-15 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | DiGA 및 GDPR 규제 준수를 위한 데이터 호스팅 위치 관련 내용 추가 |