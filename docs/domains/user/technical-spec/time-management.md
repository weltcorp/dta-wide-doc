# 시간 관리 기술 명세

## 1. 개요

사용자 도메인의 시간 관리는 TimeMachine 서비스를 통해 이루어집니다. 이는 사용자별로 독립적인 시간을 관리하고, 타임존을 고려한 정확한 일자 계산을 제공합니다.

## 2. TimeMachine 통합

### 2.1 인터페이스
```typescript
interface TimeMachineRepository {
  getCurrentTime(userId: number): Promise<number>;
  isEnabled(userId: number): Promise<boolean>;
  getRealworldCurrentTimestamp(): number;
}
```

### 2.2 사용 규칙
```typescript
/**
 * 금지된 시간 조회 방식:
 * - new Date()
 * - Date.now()
 * - moment()
 * 
 * 허용된 시간 조회 방식:
 * - timeMachineRepository.getCurrentTime()
 * - timeMachineRepository.getRealworldCurrentTimestamp()
 */
```

## 3. 시간 계산

### 3.1 일자 인덱스 계산
```typescript
/**
 * 일자 인덱스 계산 알고리즘:
 * 
 * 1. 입력:
 *    - userCycle.startAt: Date
 *    - currentTime: ZonedDateTime
 * 
 * 2. 타임존 변환:
 *    - startAtZoned = createZonedDateTime(startAt, userTimezone)
 *    - startDateStr = toDateString(startAtZoned)
 *    - currentDateStr = toDateString(currentTime)
 * 
 * 3. 일수 계산:
 *    - startDate = new Date(startDateStr)
 *    - currentDate = new Date(currentDateStr)
 *    - diffTime = currentDate.getTime() - startDate.getTime()
 *    - diffDays = Math.floor(diffTime / millisecondsInDay)
 * 
 * 4. 결과:
 *    - dayIndex = diffDays + 1
 */

const TIME_CONSTANTS = {
  millisecondsInSecond: 1000,
  millisecondsInMinute: 60 * 1000,
  millisecondsInDay: 24 * 60 * 60 * 1000,
  secondsInDay: 24 * 60 * 60,
  secondsInMonth: 30 * 24 * 60 * 60
};
```

### 3.2 타임존 처리
```typescript
interface ZonedDateTime {
  date: Date;
  timezoneId: string;
  timezoneOffset: number;
}

/**
 * 타임존 변환 규칙:
 * 1. 모든 DB 저장은 UTC
 * 2. 모든 계산은 사용자 타임존 기준
 * 3. 일자 변경점은 사용자 타임존의 00:00
 */
```

## 4. 캐싱 전략

### 4.1 일자 인덱스 캐싱
```typescript
/**
 * 캐시 정책:
 * - TTL: secondsInDay (86400초)
 * - 무효화 트리거:
 *   - TIMEMACHINE_DAY_CHANGED
 *   - USER_SIGN_OUT
 *   - USER_ACCOUNT_UPDATED
 */

const cacheConfig = {
  type: CacheType.USERS,
  resource: CacheResource.USERS,
  identifier: CacheIdentifier.DAY_INDEX,
  invalidationContexts: [
    UserContextId.TIMEMACHINE_DAY_CHANGED,
    UserContextId.USER_SIGN_OUT,
    UserContextId.USER_ACCOUNT_UPDATED
  ]
};
```

### 4.2 사용자 타임존 캐싱
```typescript
/**
 * 캐시 정책:
 * - TTL: secondsInDay
 * - 무효화 트리거:
 *   - USER_ACCOUNT_UPDATED
 *   - USER_SIGN_OUT
 */

const timezoneCacheConfig = {
  type: CacheType.USERS,
  resource: CacheResource.USERS,
  identifier: CacheIdentifier.USER_TIMEZONE_ID,
  invalidationContexts: [
    UserContextId.USER_ACCOUNT_UPDATED,
    UserContextId.USER_SIGN_OUT
  ]
};
```

## 5. 에러 처리

### 5.1 시간 계산 에러
```typescript
/**
 * 주요 에러 케이스:
 * 1. 음수 일자 인덱스
 *    - 원인: 시작일이 현재보다 미래
 *    - 처리: BadRequestException
 * 
 * 2. 타임존 변환 실패
 *    - 원인: 잘못된 타임존 ID
 *    - 처리: InternalServerErrorException
 * 
 * 3. TimeMachine 서비스 오류
 *    - 원인: 서비스 연결 실패
 *    - 처리: 실제 시스템 시간으로 폴백
 */
```

### 5.2 에러 로깅
```typescript
/**
 * 로깅 포맷:
 * {
 *   message: string;
 *   module: 'UsersService';
 *   method: string;
 *   error?: {
 *     message: string;
 *     stack?: string;
 *   };
 *   context: {
 *     userId: number;
 *     startAt?: Date;
 *     currentTime?: Date;
 *     timezoneId?: string;
 *   };
 * }
 */
```

## 6. IAM 통합

### 6.1 시간 기반 권한 제어
```typescript
/**
 * 시간 기반 권한 제어 기능:
 * 1. 권한 만료 일자 관리
 *    - expireRole(userId: number, roleId: string, expiresAt: Date)
 *    - checkRoleExpiration(userId: number, roleId: string): boolean
 * 
 * 2. 권한 유효 시간대 제한
 *    - assignTimeRestrictedRole(userId: number, roleId: string, timeRestrictions: TimeRestriction[])
 *    - validateTimeRestrictedPermission(userId: number, permission: string): boolean
 * 
 * 3. 자동 권한 할당
 *    - scheduleRoleAssignment(userId: number, roleId: string, assignAt: Date)
 *    - cancelScheduledAssignment(userId: number, roleId: string): boolean
 */

interface TimeRestriction {
  dayOfWeek?: number[];      // 0-6 (일-토)
  startTime?: string;        // HH:MM 형식
  endTime?: string;          // HH:MM 형식
  startDate?: Date;          // 시작 날짜
  endDate?: Date;            // 종료 날짜
  timeZoneId: string;        // 시간대 식별자
}
```

### 6.2 IAM 서비스 인터페이스
```typescript
interface IAMTimeService {
  /**
   * 현재 시간 기준으로 사용자의 특정 권한이 유효한지 확인
   */
  isPermissionValid(userId: number, permission: string, context?: any): Promise<boolean>;
  
  /**
   * 특정 시간에 활성화된 역할 목록 조회
   */
  getActiveRolesAtTime(userId: number, pointInTime: Date): Promise<string[]>;
  
  /**
   * 역할에 시간 제한 설정
   */
  setRoleTimeRestriction(
    userId: number, 
    roleId: string,
    timeRestrictions: TimeRestriction[]
  ): Promise<void>;
  
  /**
   * 권한 변경 예약
   */
  schedulePermissionChange(
    userId: number,
    roleId: string,
    operation: 'ASSIGN' | 'REVOKE',
    scheduledTime: Date,
    metadata?: Record<string, any>
  ): Promise<string>;
}
```

### 6.3 구현
```typescript
@Injectable()
class UserIAMTimeService implements IAMTimeService {
  constructor(
    private readonly timeMachineRepository: TimeMachineRepository,
    private readonly iamRepository: IAMRepository,
    private readonly cacheService: CacheService
  ) {}
  
  async isPermissionValid(userId: number, permission: string, context?: any): Promise<boolean> {
    // 1. 사용자 현재 시간 조회
    const currentTime = await this.timeMachineRepository.getCurrentTime(userId);
    const currentDate = new Date(currentTime);
    
    // 2. 사용자 역할 조회
    const roles = await this.iamRepository.getUserRoles(userId);
    
    // 3. 각 역할별 시간 제한 확인
    for (const role of roles) {
      // 만료 체크
      if (role.expiresAt && role.expiresAt < currentDate) {
        continue;
      }
      
      // 시간 제한 체크
      if (role.timeRestrictions && !this.isWithinTimeRestrictions(currentDate, role.timeRestrictions)) {
        continue;
      }
      
      // 권한 체크
      if (await this.iamRepository.checkRoleHasPermission(role.id, permission, context)) {
        return true;
      }
    }
    
    return false;
  }
  
  private isWithinTimeRestrictions(date: Date, restrictions: TimeRestriction[]): boolean {
    if (!restrictions.length) {
      return true; // 제한 없음
    }
    
    // 하나라도 매칭되면 유효
    return restrictions.some(restriction => {
      // 요일 체크
      if (restriction.dayOfWeek && !restriction.dayOfWeek.includes(date.getDay())) {
        return false;
      }
      
      // 날짜 범위 체크
      if (restriction.startDate && date < restriction.startDate) {
        return false;
      }
      
      if (restriction.endDate && date > restriction.endDate) {
        return false;
      }
      
      // 시간 범위 체크
      if (restriction.startTime && restriction.endTime) {
        const timeString = date.toTimeString().substring(0, 5); // HH:MM
        if (timeString < restriction.startTime || timeString > restriction.endTime) {
          return false;
        }
      }
      
      return true;
    });
  }
  
  // 다른 메서드 구현...
}
```

### 6.4 캐싱 전략
```typescript
/**
 * IAM 시간 관련 캐싱 정책:
 * - TTL: 10분 (600초)
 * - 무효화 트리거:
 *   - ROLE_ASSIGNED
 *   - ROLE_REVOKED
 *   - PERMISSION_CHANGED
 *   - TIMEMACHINE_TIME_CHANGED
 */

const iamTimeCacheConfig = {
  type: CacheType.USERS,
  resource: CacheResource.IAM,
  identifier: CacheIdentifier.TIME_RESTRICTED_PERMISSIONS,
  ttl: 600, // 10분
  invalidationContexts: [
    UserContextId.ROLE_ASSIGNED,
    UserContextId.ROLE_REVOKED,
    UserContextId.PERMISSION_CHANGED,
    UserContextId.TIMEMACHINE_TIME_CHANGED
  ]
};
```

## 7. 모니터링

### 6.1 메트릭스
```typescript
/**
 * 수집 지표:
 * 1. TimeMachine 서비스 응답 시간
 * 2. 일자 인덱스 계산 시간
 * 3. 타임존 변환 오류율
 * 4. 캐시 히트율
 */
```

### 6.2 알림 설정
```typescript
/**
 * 알림 트리거:
 * 1. TimeMachine 서비스 응답 시간 > 1초
 * 2. 타임존 변환 오류 > 1%
 * 3. 캐시 히트율 < 80%
 */
```

### 6.3 IAM 타임 메트릭스
```typescript
/**
 * IAM 타임 관련 지표:
 * 1. 시간 기반 권한 검증 횟수
 * 2. 시간 제한으로 거부된 권한 요청 수
 * 3. 만료된 권한으로 인한 거부 수
 * 4. 권한 예약 작업 실행 시간
 */

// 시간 제한 권한 검증 메트릭스
counter('iam_time_permission_checks_total', {
  permission: string,
  result: 'allowed' | 'denied',
  denial_reason: 'expired' | 'time_restricted' | 'not_assigned' | null
});

// 시간 제한 메트릭스
gauge('iam_time_restricted_roles_active', {
  role_id: string
});

// 권한 예약 작업 메트릭스
counter('iam_scheduled_permission_changes_total', {
  operation: 'assign' | 'revoke',
  status: 'scheduled' | 'executed' | 'failed' | 'cancelled'
});
```

## 8. 테스트

### 7.1 단위 테스트
```typescript
describe('TimeManagement', () => {
  describe('calculateDayIndex', () => {
    it('should handle timezone differences correctly', () => {
      // Test cases
    });

    it('should handle date transitions at midnight', () => {
      // Test cases
    });

    it('should reject future start dates', () => {
      // Test cases
    });
  });
});
```

### 7.2 통합 테스트
```typescript
describe('TimeManagement Integration', () => {
  describe('TimeMachine integration', () => {
    it('should use TimeMachine service when enabled', () => {
      // Test cases
    });

    it('should fallback to system time when service fails', () => {
      // Test cases
    });
  });
});
```

### 7.3 IAM 시간 테스트
```typescript
describe('IAMTimeService', () => {
  describe('isPermissionValid', () => {
    it('should validate time-restricted permissions', async () => {
      // Arrange
      const userId = 1;
      const now = new Date('2025-03-30T14:00:00Z');
      const timeRestriction = {
        dayOfWeek: [1, 2, 3, 4, 5], // 월-금
        startTime: '09:00',
        endTime: '17:00',
        timeZoneId: 'Asia/Seoul'
      };
      
      // 사용자에게 시간 제한 역할 할당
      await iamService.assignRole(userId, 'restricted-role');
      await iamService.setRoleTimeRestriction(userId, 'restricted-role', [timeRestriction]);
      
      // 타임머신 시간 설정
      timeMachineRepository.getCurrentTime.mockResolvedValue(now.getTime());
      
      // Act & Assert - 업무 시간 내 권한 체크
      let result = await service.isPermissionValid(userId, 'user:read');
      expect(result).toBe(true);
      
      // 업무 시간 외 권한 체크
      const afterHours = new Date('2025-03-30T20:00:00Z');
      timeMachineRepository.getCurrentTime.mockResolvedValue(afterHours.getTime());
      
      result = await service.isPermissionValid(userId, 'user:read');
      expect(result).toBe(false);
    });
    
    it('should handle expired roles correctly', async () => {
      // Arrange
      const userId = 1;
      const now = new Date('2025-03-30T14:00:00Z');
      const pastDate = new Date('2025-03-29T14:00:00Z');
      
      // 만료된 역할 할당
      await iamService.assignRole(userId, 'expired-role', { expiresAt: pastDate });
      
      // 타임머신 시간 설정
      timeMachineRepository.getCurrentTime.mockResolvedValue(now.getTime());
      
      // Act
      const result = await service.isPermissionValid(userId, 'user:read');
      
      // Assert
      expect(result).toBe(false);
    });
  });
  
  describe('schedulePermissionChange', () => {
    it('should schedule future permission changes', async () => {
      // Arrange
      const userId = 1;
      const roleId = 'temp-role';
      const futureTime = new Date();
      futureTime.setHours(futureTime.getHours() + 1); // 1시간 후
      
      // Act
      const scheduleId = await service.schedulePermissionChange(
        userId,
        roleId,
        'ASSIGN',
        futureTime
      );
      
      // Assert
      expect(scheduleId).toBeDefined();
      
      // 스케줄 실행 확인 (시간 조작)
      // 현재 시간을 미래로 설정
      const future = new Date(futureTime.getTime() + 1000); // 1초 후
      timeMachineRepository.getCurrentTime.mockResolvedValue(future.getTime());
      
      // 스케줄 처리 작업 실행
      await service.processScheduledPermissionChanges();
      
      // 역할이 할당되었는지 확인
      const roles = await iamService.getUserRoles(userId);
      expect(roles.some(r => r.id === roleId)).toBe(true);
    });
  });
});
```

## 9. 변경 이력

| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 | 
| 0.2.0 | 2025-03-30 | bok@weltcorp.com | IAM 통합 기능 추가 | 