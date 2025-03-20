# 사용자 주기 보안 명세

## 1. 접근 제어

### 역할 기반 접근 제어 (RBAC)
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

const ROLE_PERMISSIONS = {
  ADMIN: [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.UPDATE,
    CyclePermission.DELETE,
    CyclePermission.CHANGE_STATUS,
    CyclePermission.MANAGE_ALL,
    CyclePermission.VIEW_STATISTICS
  ],
  MANAGER: [
    CyclePermission.READ,
    CyclePermission.CREATE,
    CyclePermission.UPDATE,
    CyclePermission.CHANGE_STATUS,
    CyclePermission.VIEW_STATISTICS
  ],
  USER: [
    CyclePermission.READ
  ]
};
```

### IAM 통합 접근 제어
```typescript
// IAM 역할과 주기 권한 매핑
const IAM_ROLE_CYCLE_PERMISSIONS = {
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

// IAM 권한 검증 인터페이스
interface IAMPermissionValidator {
  hasPermission(
    userId: number,
    permission: CyclePermission,
    cycleId?: number,
    contextOptions?: {
      siteId?: number;
      groupId?: number;
      organizationId?: string;
    }
  ): Promise<boolean>;
  
  hasContextPermission(
    userId: number,
    permission: string,
    context: {
      siteId?: number;
      groupId?: number;
      organizationId?: string;
    }
  ): Promise<boolean>;
}
```

### API 엔드포인트 보안
```typescript
@UseGuards(AuthGuard, CyclePermissionGuard)
@Controller('v1/user-cycles')
export class UserCycleController {
  @Post()
  @RequireCyclePermission(CyclePermission.CREATE)
  async createCycle() {}

  @Get()
  @RequireCyclePermission(CyclePermission.READ)
  async getCycles() {}

  @Patch(':id/status')
  @RequireCyclePermission(CyclePermission.CHANGE_STATUS)
  async updateCycleStatus() {}
  
  @Get('/statistics')
  @RequireCyclePermission(CyclePermission.VIEW_STATISTICS)
  async getCycleStatistics() {}
}
```

## 2. 데이터 보안

### 민감 정보 처리
- 사용자 식별 정보는 암호화하여 저장
- 로그에서 민감 정보 마스킹 처리
- API 응답에서 불필요한 정보 제외
- 민감 데이터 전송 시 항상 TLS/SSL 사용

### 데이터 접근 제한
```typescript
@Injectable()
export class CycleDataAccessService {
  constructor(
    private readonly cyclePermissionService: CyclePermissionService,
    private readonly userCycleRepository: UserCycleRepository
  ) {}

  async validateAccess(
    userId: number, 
    cycleId: number, 
    requiredPermission: CyclePermission
  ): Promise<boolean> {
    const cycle = await this.userCycleRepository.findOne({
      where: { id: cycleId }
    });
    
    if (!cycle) return false;
    
    // IAM 기반 권한 검증
    const hasPermission = await this.cyclePermissionService.hasPermission(
      userId,
      requiredPermission,
      cycleId,
      {
        siteId: cycle.siteId,
        groupId: cycle.groupId
      }
    );
    
    return hasPermission;
  }
  
  async applyDataFilters(userId: number, query: any): Promise<any> {
    const hasManageAllPermission = await this.cyclePermissionService.hasPermission(
      userId,
      CyclePermission.MANAGE_ALL
    );
    
    // 권한에 따라 데이터 필터링 적용
    if (!hasManageAllPermission) {
      // 자신의 데이터 또는 특정 사이트/그룹 내의 데이터만 조회 가능
      query.where = {
        ...query.where,
        userId
      };
    }
    
    return query;
  }
}
```

## 3. 감사 로깅

> **참고**: 모든 로깅은 [공통 로깅 표준](/docs/infrastructure/logging-standards.md)을 준수해야 합니다. 여기서는 주기 보안과 관련된 주요 로깅 이벤트만 정의합니다.

### 주요 로깅 이벤트
```typescript
// 주기 생성
logger.info({
  event: 'CYCLE_CREATED',
  cycle_id: string,
  user_id: string,
  performed_by: string, // 실제 작업 수행자 (관리자 등)
  metadata: {
    site_id: string,
    status: 'PENDING',
    ip_address: string
  }
});

// 주기 상태 변경
logger.info({
  event: 'CYCLE_STATUS_CHANGED',
  cycle_id: string,
  user_id: string,
  performed_by: string,
  status: {
    from: string,
    to: string
  },
  metadata: {
    site_id: string,
    reason: string,
    ip_address: string
  }
});

// 주기 접근 권한 거부
logger.warn({
  event: 'CYCLE_ACCESS_DENIED',
  cycle_id: string,
  user_id: string,
  permission: string,
  metadata: {
    site_id: string,
    ip_address: string,
    reason: string
  }
});
```

// 감사 서비스 연동
async function logCycleAction(
  auditLogService: AuditLogService,
  action: string,
  userId: number,
  resourceId: number | null,
  metadata: Record<string, any>
): Promise<void> {
  await auditLogService.log({
    domain: 'USER',
    component: 'CYCLE',
    action,
    actor_id: userId,
    resource_id: resourceId,
    metadata
  });
}

### 로그 저장 정책
- 감사 로그는 최소 1년간 보관
- 로그 데이터는 암호화하여 저장
- 정기적인 로그 백업 수행
- 개인정보 관련 로그는 GDPR 규정에 따라 처리
- 권한 변경 로그는 별도 보관 및 정기 검토

## 4. IAM 통합 보안 요구사항

### 4.1 주기 권한 관리

#### IAM 역할과 주기 권한 연동
- IAM 역할 권한 우선: IAM 시스템의 역할 권한이 로컬 RBAC 설정보다 우선 적용
- 컨텍스트 기반 권한 검증: 사용자-사이트-조직 계층 구조 기반 권한 확인
- 스코프 제한: 사이트/조직 범위가 설정된 IAM 역할은 해당 범위 내에서만 권한 적용
- 권한 캐싱: 성능 최적화를 위한 권한 캐싱 (5분 TTL)
- 자가 관리 예외: 사용자는 자신의 주기에 대해 제한된 권한 보유 (읽기, 상태 변경)

#### 주기 접근을 위한 IAM 권한 정책
```typescript
interface CycleIAMPolicy {
  // 필요한 IAM 역할 또는 권한
  requiredRole: string | string[];
  
  // 접근 가능한 리소스 필터
  resourceFilter?: {
    siteIds?: number[];
    organizationIds?: string[];
    ownedOnly?: boolean;
  };
  
  // 조건부 접근 로직
  condition?: (user: UserAccount, cycle: UserCycle) => boolean;
}

const CYCLE_IAM_POLICIES: Record<CyclePermission, CycleIAMPolicy> = {
  [CyclePermission.CREATE]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN', 'SITE_ADMIN', 'CLINICIAN']
  },
  [CyclePermission.READ]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN', 'SITE_ADMIN', 'CLINICIAN', 'USER'],
    condition: (user, cycle) => user.id === cycle.userId || 
      hasAdminPermission(user, cycle.siteId) || 
      user.roles.includes('SYSTEM_ADMIN') || 
      user.roles.includes('CYCLE_ADMIN')
  },
  [CyclePermission.UPDATE]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN', 'SITE_ADMIN'],
    condition: (user, cycle) => hasAdminPermission(user, cycle.siteId) || 
      user.roles.includes('SYSTEM_ADMIN')
  },
  [CyclePermission.DELETE]: {
    requiredRole: 'SYSTEM_ADMIN'
  },
  [CyclePermission.CHANGE_STATUS]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN', 'SITE_ADMIN', 'CLINICIAN'],
    condition: (user, cycle) => user.id === cycle.userId || 
      hasAdminPermission(user, cycle.siteId) || 
      user.roles.includes('SYSTEM_ADMIN') || 
      user.roles.includes('CYCLE_ADMIN')
  },
  [CyclePermission.MANAGE_ALL]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN']
  },
  [CyclePermission.VIEW_STATISTICS]: {
    requiredRole: ['SYSTEM_ADMIN', 'CYCLE_ADMIN', 'SITE_ADMIN'],
    condition: (user, cycle) => hasAdminPermission(user, cycle.siteId) || 
      user.roles.includes('SYSTEM_ADMIN') || 
      user.roles.includes('CYCLE_ADMIN')
  }
};

// 사이트 관리 권한 검증 헬퍼 함수
function hasAdminPermission(user: UserAccount, siteId: number): boolean {
  return user.adminSites?.includes(siteId) || false;
}
```

### 4.2 권한 위반 감지 및 대응

#### 위반 감지 체계
- 권한 검증 실패 감사: 모든 권한 거부 이벤트 로깅
- 이상 탐지: 짧은 시간 내 다수의 권한 검증 실패 탐지
- 관리자 알림: 중요 리소스 접근 시도 실패 시 관리자 알림
- 패턴 분석: 사용자별, IP별, 리소스별 접근 패턴 분석 및 이상 징후 탐지

#### 자동화된 대응
```typescript
interface SecurityIncident {
  userId: number;
  resourceType: string;
  resourceId: string;
  attemptedPermission: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  requestPath: string;
  requestMethod: string;
}

enum IncidentSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

interface IncidentResponse {
  severity: IncidentSeverity;
  automaticActions: string[];
  notifyRoles: string[];
  escalationRequired: boolean;
  blockRequest: boolean;
  temporaryRestrictions?: {
    duration: number; // 초 단위
    restrictionType: 'RATE_LIMIT' | 'BLOCK' | 'ADDITIONAL_VERIFICATION';
  };
}

@Injectable()
export class SecurityIncidentHandler {
  constructor(
    private readonly auditLogService: AuditLogService,
    private readonly notificationService: NotificationService,
    private readonly userRestrictionService: UserRestrictionService
  ) {}

  async handleIncident(incident: SecurityIncident): Promise<void> {
    // 1. 이전 인시던트 이력 조회
    const recentIncidents = await this.getRecentIncidents(
      incident.userId,
      incident.resourceType,
      incident.ipAddress
    );
    
    // 2. 인시던트 심각도 및 대응 방안 결정
    const response = this.determineResponse(incident, recentIncidents);
    
    // 3. 감사 로깅
    await this.auditLogService.logSecurityIncident({
      ...incident,
      severity: response.severity,
      actions: response.automaticActions
    });
    
    // 4. 자동화된 대응 실행
    if (response.blockRequest) {
      // 요청 차단 로직
    }
    
    if (response.temporaryRestrictions) {
      await this.userRestrictionService.applyRestriction(
        incident.userId,
        response.temporaryRestrictions.restrictionType,
        response.temporaryRestrictions.duration
      );
    }
    
    // 5. 관리자 알림
    if (response.notifyRoles.length > 0) {
      await this.notificationService.notifyRoles(
        response.notifyRoles,
        '보안 인시던트 발생',
        {
          incidentType: '권한 위반',
          user: incident.userId,
          resource: `${incident.resourceType}:${incident.resourceId}`,
          severity: response.severity,
          timestamp: incident.timestamp
        }
      );
    }
    
    // 6. 심각한 인시던트의 경우 추가 조치
    if (response.escalationRequired) {
      // 에스컬레이션 로직
    }
  }
  
  private determineResponse(
    currentIncident: SecurityIncident,
    recentIncidents: SecurityIncident[]
  ): IncidentResponse {
    // 인시던트 심각도 판단 및 대응 로직
    // ...

    // 예시: 기본 대응
    return {
      severity: IncidentSeverity.LOW,
      automaticActions: ['LOG'],
      notifyRoles: [],
      escalationRequired: false,
      blockRequest: false
    };
  }
  
  private async getRecentIncidents(
    userId: number,
    resourceType: string,
    ipAddress: string
  ): Promise<SecurityIncident[]> {
    // 최근 인시던트 조회 로직
    // ...
    return [];
  }
}
```

## 5. 보안 모니터링

### 모니터링 항목
- 비정상적인 접근 시도
- 권한 없는 작업 시도
- 대량의 상태 변경 시도
- API 호출 패턴 분석
- 세션 관련 이상 행동
- 권한 검증 실패율
- 권한 캐시 히트율

### 알림 설정
- 보안 위반 시도 발생 시
- 비정상적인 데이터 접근 시
- 권한 오류 임계치 초과 시
- 관리자 계정의 민감 작업 수행 시
- 주기 대량 변경 시

### 대시보드 구성
```typescript
interface SecurityDashboard {
  recentIncidents: {
    count: number;
    bySeverity: Record<IncidentSeverity, number>;
    byResourceType: Record<string, number>;
  };
  permissionMetrics: {
    verificationCount: number;
    failureRate: number;
    cachingEfficiency: number;
    topFailedPermissions: Array<{
      permission: string;
      count: number;
    }>;
  };
  userActivityMetrics: {
    activeUsers: number;
    suspiciousActivities: number;
    adminActions: number;
  };
}
```

## 6. 보안 정책

### 세션 관리
- 세션 타임아웃: 30분
- 동시 세션 제한: 최대 3개
- 세션 고정 공격 방지
- 세션 갱신 시 권한 재검증

### API 보안
- Rate Limiting 적용
- CORS 정책 설정
- API 키 관리
- JWT 토큰 검증
- HMAC 요청 서명 검증

### IAM 관련 추가 보안 정책
- 최소 권한 원칙 적용
- 역할 분리(SoD) 원칙 구현
- 권한 정기 검토 및 재인증 메커니즘
- 임시 권한 승격 요청 및 승인 워크플로우
- 중요 권한 변경 시 다중 승인 필요

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2024-03-17 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | IAM 통합 보안 요구사항 추가 |
| 0.3.0 | 2025-03-20 | bok@weltcorp.com | cycle-impl.md 파일과 일관성 있게 IAM 관련 내용 업데이트, 권한 모델 및 보안 정책 확장 |
| 0.4.0 | 2025-03-20 | bok@weltcorp.com | 공통 로깅 표준 참조로 변경 |