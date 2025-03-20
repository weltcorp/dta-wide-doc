# 사용자 주기 구현 명세

## 1. 데이터베이스 스키마

### 테이블 정의
```sql
CREATE TABLE user_cycles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_accounts(id),
    site_id INTEGER NOT NULL REFERENCES sites(id),
    group_id INTEGER REFERENCES groups(id),
    department_id INTEGER REFERENCES departments(id),
    account_id INTEGER NOT NULL REFERENCES md_accounts(id),
    accesscode_id INTEGER NOT NULL REFERENCES user_accesscodes(id),
    registration_channel_id INTEGER REFERENCES registration_channels(id),
    status SMALLINT NOT NULL DEFAULT 0,
    start_at TIMESTAMPTZ,
    end_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 인덱스
```sql
CREATE INDEX idx_user_cycles_status_start_at ON user_cycles(status, start_at);
CREATE INDEX idx_user_cycles_user_id ON user_cycles(user_id);
CREATE INDEX idx_user_cycles_site_id ON user_cycles(site_id);
CREATE INDEX idx_user_cycles_accesscode_id ON user_cycles(accesscode_id);
```

## 2. 캐시 전략

### 캐시 키 구조
```typescript
const CACHE_KEYS = {
  ACTIVE_CYCLE: (userId: number) => `user:${userId}:active-cycle`,
  CYCLE_STATUS: (cycleId: number) => `cycle:${cycleId}:status`,
  USER_CYCLES: (userId: number) => `user:${userId}:cycles`
};
```

### TTL 설정
- ACTIVE_CYCLE: 5분
- CYCLE_STATUS: 1분
- USER_CYCLES: 10분

### 캐시 무효화 트리거
- 주기 상태 변경 시
- 새로운 주기 생성 시
- 주기 종료 시

## 3. IAM 통합 및 권한 모델

### 3.1 주기 관련 권한 정의

```typescript
enum CyclePermission {
  READ = 'cycle:read',                  // 주기 조회
  CREATE = 'cycle:create',              // 주기 생성
  UPDATE = 'cycle:update',              // 주기 수정
  DELETE = 'cycle:delete',              // 주기 삭제
  CHANGE_STATUS = 'cycle:change-status', // 주기 상태 변경
  MANAGE_ALL = 'cycle:manage-all',      // 모든 사용자의 주기 관리
  VIEW_STATISTICS = 'cycle:view-stats'  // 주기 통계 조회
}

// IAM 역할과 주기 권한 매핑
const ROLE_PERMISSIONS = {
  'SYSTEM_ADMIN': [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.UPDATE,
    CyclePermission.DELETE,
    CyclePermission.CHANGE_STATUS,
    CyclePermission.MANAGE_ALL,
    CyclePermission.VIEW_STATISTICS
  ],
  'CYCLE_ADMIN': [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.UPDATE,
    CyclePermission.CHANGE_STATUS,
    CyclePermission.MANAGE_ALL,
    CyclePermission.VIEW_STATISTICS
  ],
  'SITE_ADMIN': [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.UPDATE,
    CyclePermission.CHANGE_STATUS,
    CyclePermission.VIEW_STATISTICS
  ],
  'CLINICIAN': [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.CHANGE_STATUS
  ],
  'USER': [
    CyclePermission.READ
  ]
};
```

### 3.2 권한 검증 서비스

```typescript
@Injectable()
export class CyclePermissionService {
  constructor(
    private readonly userIAMService: UserIAMService,
    private readonly cacheService: CacheService,
    private readonly userCycleRepository: UserCycleRepository
  ) {}
  
  async hasPermission(
    userId: number,
    permission: CyclePermission,
    cycleId?: number,
    contextOptions?: {
      siteId?: number;
      groupId?: number;
    }
  ): Promise<boolean> {
    // 1. 자신의 주기에 대한 기본 권한 확인
    if (cycleId && await this.isOwnCycle(userId, cycleId)) {
      return this.isSelfManagementPermission(permission);
    }
    
    // 2. 캐시된 권한 확인
    const cacheKey = `user:${userId}:cycle:permissions`;
    const cachedPermissions = await this.cacheService.get<CyclePermission[]>(cacheKey);
    
    if (cachedPermissions) {
      if (cachedPermissions.includes(permission)) {
        // 모든 주기 관리 권한이 있거나, 컨텍스트 제약 조건 충족 시 권한 부여
        if (cachedPermissions.includes(CyclePermission.MANAGE_ALL)) {
          return true;
        }
        
        // 사이트/그룹 수준의 권한 제약 확인
        if (cycleId && contextOptions) {
          return this.checkContextConstraints(userId, cycleId, contextOptions);
        }
        
        return true;
      }
      return false;
    }
    
    // 3. IAM 서비스에서 사용자 역할 조회
    const roles = await this.userIAMService.getUserRoles(userId);
    
    // 4. 역할에 따른 권한 확인
    const permissions = this.getPermissionsFromRoles(roles);
    
    // 5. 권한 캐싱 (5분)
    await this.cacheService.set(cacheKey, permissions, 5 * 60);
    
    // 6. 권한 확인 결과 반환
    if (permissions.includes(permission)) {
      // 모든 주기 관리 권한이 있거나, 컨텍스트 제약 조건 충족 시 권한 부여
      if (permissions.includes(CyclePermission.MANAGE_ALL)) {
        return true;
      }
      
      // 사이트/그룹 수준의 권한 제약 확인
      if (cycleId && contextOptions) {
        return this.checkContextConstraints(userId, cycleId, contextOptions);
      }
      
      return true;
    }
    
    return false;
  }
  
  private async isOwnCycle(userId: number, cycleId: number): Promise<boolean> {
    const cycle = await this.userCycleRepository.findOne({
      where: { id: cycleId }
    });
    return cycle?.userId === userId;
  }
  
  private isSelfManagementPermission(permission: CyclePermission): boolean {
    // 자신의 주기에 대해 허용되는 권한
    return [
      CyclePermission.READ,
      CyclePermission.UPDATE,
      CyclePermission.CHANGE_STATUS
    ].includes(permission);
  }
  
  private async checkContextConstraints(
    userId: number, 
    cycleId: number,
    options: { siteId?: number; groupId?: number; }
  ): Promise<boolean> {
    // 사용자가 특정 사이트나 그룹에 대한 권한이 있는지 확인
    const cycle = await this.userCycleRepository.findOne({
      where: { id: cycleId }
    });
    
    if (!cycle) {
      return false;
    }
    
    // 사이트 관리자는 해당 사이트의 주기에 대해 권한 가짐
    if (options.siteId && cycle.siteId === options.siteId) {
      const hasSitePermission = await this.userIAMService.hasContextPermission(
        userId, 
        'site:manage', 
        { siteId: options.siteId }
      );
      if (hasSitePermission) {
        return true;
      }
    }
    
    // 그룹 관리자는 해당 그룹의 주기에 대해 권한 가짐
    if (options.groupId && cycle.groupId === options.groupId) {
      const hasGroupPermission = await this.userIAMService.hasContextPermission(
        userId, 
        'group:manage', 
        { groupId: options.groupId }
      );
      if (hasGroupPermission) {
        return true;
      }
    }
    
    return false;
  }
  
  private getPermissionsFromRoles(roles: IAMRole[]): CyclePermission[] {
    // 중복 제거를 위해 Set 사용
    const permissionSet = new Set<CyclePermission>();
    
    for (const role of roles) {
      const permissions = ROLE_PERMISSIONS[role.id];
      if (permissions) {
        permissions.forEach(permission => permissionSet.add(permission));
      }
    }
    
    return Array.from(permissionSet);
  }
}
```

### 3.3 권한 검증 데코레이터

```typescript
export function RequireCyclePermission(permission: CyclePermission) {
  return applyDecorators(
    SetMetadata('permission', permission),
    UseGuards(CyclePermissionGuard)
  );
}

@Injectable()
export class CyclePermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly cyclePermissionService: CyclePermissionService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const permission = this.reflector.get<CyclePermission>(
      'permission',
      context.getHandler()
    );

    if (!permission) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      return false;
    }

    // 주기 ID 파라미터 가져오기
    const cycleId = request.params.id ? parseInt(request.params.id, 10) : undefined;
    
    // 컨텍스트 제약 조건 가져오기 (사이트 ID, 그룹 ID)
    const contextOptions = {
      siteId: request.query.siteId ? parseInt(request.query.siteId, 10) : undefined,
      groupId: request.query.groupId ? parseInt(request.query.groupId, 10) : undefined
    };

    return this.cyclePermissionService.hasPermission(
      user.id,
      permission,
      cycleId,
      contextOptions
    );
  }
}
```

## 4. API 엔드포인트

### 주기 생성
```typescript
@Post('/v1/user-cycles')
@RequireCyclePermission(CyclePermission.CREATE)
async createCycle(
  @Body() dto: CreateCycleDto, 
  @CurrentUser() user: UserContext
): Promise<UserCycleResponse> {
  // 사이트/그룹 수준의 권한 검증
  if (dto.siteId) {
    const hasSitePermission = await this.cyclePermissionService.hasPermission(
      user.id,
      CyclePermission.CREATE,
      undefined,
      { siteId: dto.siteId }
    );
    
    if (!hasSitePermission) {
      throw new ForbiddenException('해당 사이트에 주기를 생성할 권한이 없습니다.');
    }
  }
  
  // IAM 감사 로깅
  await this.auditLogService.logAction({
    userId: user.id,
    action: 'cycle.create',
    resourceType: 'user_cycle',
    resourceId: null, // 아직 생성 전이므로 ID 없음
    details: {
      siteId: dto.siteId,
      userId: dto.userId || user.id
    }
  });
  
  // 비즈니스 로직 실행
  return this.userCycleService.createCycle(dto);
}
```

### 주기 상태 변경
```typescript
@Patch('/v1/user-cycles/:id/status')
@RequireCyclePermission(CyclePermission.CHANGE_STATUS)
async updateCycleStatus(
  @Param('id') id: number,
  @Body() dto: UpdateCycleStatusDto,
  @CurrentUser() user: UserContext
): Promise<UserCycleResponse> {
  // 현재 주기 정보 조회
  const cycle = await this.userCycleService.getCycleById(id);
  if (!cycle) {
    throw new NotFoundException('주기를 찾을 수 없습니다.');
  }
  
  // IAM 감사 로깅
  await this.auditLogService.logAction({
    userId: user.id,
    action: 'cycle.status_change',
    resourceType: 'user_cycle',
    resourceId: id,
    details: {
      previousStatus: cycle.status,
      newStatus: dto.status,
      reason: dto.reason
    }
  });
  
  // 비즈니스 로직 실행
  return this.userCycleService.updateCycleStatus(id, dto);
}
```

### 주기 조회
```typescript
@Get('/v1/user-cycles')
@RequireCyclePermission(CyclePermission.READ)
async getCycles(
  @Query() query: GetCyclesQueryDto,
  @CurrentUser() user: UserContext
): Promise<PaginatedResponse<UserCycleResponse>> {
  // 권한에 따른 쿼리 조정
  const hasManageAllPermission = await this.cyclePermissionService.hasPermission(
    user.id,
    CyclePermission.MANAGE_ALL
  );
  
  // 일반 사용자는 자신의 주기만 볼 수 있음
  if (!hasManageAllPermission && !query.userId) {
    query.userId = user.id;
  }
  
  // 다른 사용자의 주기를 조회하려는 경우 추가 권한 검증
  if (query.userId && query.userId !== user.id) {
    const hasPermission = await this.cyclePermissionService.hasPermission(
      user.id,
      CyclePermission.READ,
      undefined,
      {
        siteId: query.siteId,
        groupId: query.groupId
      }
    );
    
    if (!hasPermission) {
      throw new ForbiddenException('다른 사용자의 주기를 조회할 권한이 없습니다.');
    }
  }
  
  // 비즈니스 로직 실행
  return this.userCycleService.getCycles(query);
}
```

### 주기 통계 조회
```typescript
@Get('/v1/user-cycles/statistics')
@RequireCyclePermission(CyclePermission.VIEW_STATISTICS)
async getCycleStatistics(
  @Query() query: CycleStatisticsQueryDto,
  @CurrentUser() user: UserContext
): Promise<CycleStatisticsResponse> {
  // 사이트/그룹 수준의 권한 검증
  if (query.siteId) {
    const hasSitePermission = await this.cyclePermissionService.hasPermission(
      user.id,
      CyclePermission.VIEW_STATISTICS,
      undefined,
      { siteId: query.siteId }
    );
    
    if (!hasSitePermission) {
      throw new ForbiddenException('해당 사이트의 주기 통계를 조회할 권한이 없습니다.');
    }
  }
  
  // 비즈니스 로직 실행
  return this.userCycleService.getCycleStatistics(query);
}
```

## 5. 성능 최적화

### 쿼리 최적화
- 복합 인덱스 활용
- 페이지네이션 적용
- 필요한 필드만 조회

### N+1 문제 해결
- Relations Eager Loading
- DataLoader 패턴 적용

### 벌크 작업 최적화
- 배치 처리
- 트랜잭션 관리

### 권한 검증 성능 최적화
- 권한 캐싱
- 배치 권한 검증
- 권한 결정 트리 최적화

## 6. 모니터링 및 감사

### 메트릭스
- 주기 생성 수
- 상태별 주기 수
- 평균 처리 시간
- 에러율
- 권한 검증 성공/실패 비율

### 알림 설정
- 높은 에러율 발생 시
- 비정상적인 상태 전이 발생 시
- 성능 저하 시
- 권한 검증 실패 급증 시

### 감사 로깅
- 모든 주기 상태 변경
- 주기 생성 및 삭제 작업
- 권한 검증 실패
- 관리자의 주기 수정 작업

## 7. 에러 처리

### HTTP 상태 코드
- 200: 성공
- 201: 주기 생성 성공
- 400: 잘못된 요청
- 403: 권한 없음
- 404: 주기 없음
- 409: 중복된 활성 주기

### 에러 응답 형식
```typescript
interface ErrorResponse {
  status: number;
  code: string;
  message: string;
  details?: any;
}
```

### IAM 관련 에러 코드
```typescript
enum CycleErrorCode {
  PERMISSION_DENIED = 'CYCLE_PERMISSION_DENIED',
  INVALID_STATUS_TRANSITION = 'INVALID_STATUS_TRANSITION',
  CYCLE_NOT_FOUND = 'CYCLE_NOT_FOUND',
  DUPLICATE_ACTIVE_CYCLE = 'DUPLICATE_ACTIVE_CYCLE',
  INVALID_CONTEXT = 'INVALID_CONTEXT',
  IAM_SERVICE_ERROR = 'IAM_SERVICE_ERROR'
}
```

## 8. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | IAM 통합 및 권한 모델 추가, API 엔드포인트 권한 검증 로직 구현 |