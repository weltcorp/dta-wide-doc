# User 도메인 구현 가이드

## 1. 도메인 구조

### 1.1 디렉토리 구조
```
src/domains/user/
├── domain/
│   ├── entities/
│   │   ├── User.ts
│   │   ├── Account.ts
│   │   ├── UserCycle.ts
│   │   ├── UserIAMMapping.ts
│   │   └── IAMChangeRequest.ts
│   ├── value-objects/
│   │   ├── UserProfile.ts
│   │   ├── AccountSettings.ts
│   │   ├── CycleSettings.ts
│   │   └── IAMRole.ts
│   ├── repositories/
│   │   ├── IUserRepository.ts
│   │   ├── IAccountRepository.ts
│   │   ├── ICycleRepository.ts
│   │   ├── IUserIAMRepository.ts
│   │   └── IIAMChangeRequestRepository.ts
│   └── events/
│       ├── UserEvents.ts
│       ├── CycleEvents.ts
│       └── IAMEvents.ts
├── application/
│   ├── services/
│   │   ├── UserService.ts
│   │   ├── AuthService.ts
│   │   ├── AccountService.ts
│   │   ├── CycleService.ts
│   │   └── UserIAMService.ts
│   ├── dtos/
│   │   ├── UserDto.ts
│   │   ├── AuthDto.ts
│   │   ├── CycleDto.ts
│   │   └── IAMDto.ts
│   └── errors/
│       ├── UserErrors.ts
│       └── IAMErrors.ts
├── infrastructure/
│   ├── repositories/
│   │   ├── PrismaUserRepository.ts
│   │   ├── PrismaAccountRepository.ts
│   │   ├── PrismaCycleRepository.ts
│   │   ├── PrismaUserIAMRepository.ts
│   │   └── PrismaIAMChangeRequestRepository.ts
│   ├── persistence/
│   │   ├── prisma/schema.prisma
│   │   └── prisma/migrations/
│   └── cache/
│       ├── UserCacheService.ts
│       └── IAMCacheService.ts
└── presentation/
    ├── controllers/
    │   ├── UserController.ts
    │   ├── AuthController.ts
    │   ├── CycleController.ts
    │   └── UserIAMController.ts
    ├── middlewares/
    │   ├── AuthMiddleware.ts
    │   ├── ValidationMiddleware.ts
    │   └── PermissionMiddleware.ts
    └── validators/
        ├── UserValidator.ts
        ├── CycleValidator.ts
        └── IAMValidator.ts
```

## 2. 엔티티 및 값 객체 정의

### 2.1 User 엔티티
```typescript
@Entity()
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude()
  password: string;

  @Column()
  name: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.PATIENT
  })
  role: UserRole;

  @Column(() => UserProfile)
  profile: UserProfile;

  @ManyToOne(() => Account)
  account: Account;

  @Column({
    type: 'enum',
    enum: UserStatus,
    default: UserStatus.ACTIVE
  })
  status: UserStatus;

  @Column()
  lastLoginAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  public validatePassword(password: string): boolean {
    return bcrypt.compareSync(password, this.password);
  }

  public setPassword(password: string): void {
    this.password = bcrypt.hashSync(password, 10);
  }
}
```

### 2.2 UserProfile 값 객체
```typescript
@Embeddable()
export class UserProfile {
  @Column({ nullable: true })
  phoneNumber?: string;

  @Column({ type: 'date', nullable: true })
  birthDate?: Date;

  @Column({
    type: 'enum',
    enum: Gender,
    nullable: true
  })
  gender?: Gender;

  @Column({ type: 'jsonb', nullable: true })
  additionalInfo?: Record<string, any>;
}
```

### 2.3 Account 엔티티
```typescript
@Entity()
export class Account extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({
    type: 'enum',
    enum: AccountType
  })
  type: AccountType;

  @Column({
    type: 'enum',
    enum: AccountStatus,
    default: AccountStatus.ACTIVE
  })
  status: AccountStatus;

  @Column(() => AccountSettings)
  settings: AccountSettings;

  @OneToMany(() => User, user => user.account)
  users: User[];
}
```

## 3. 리포지토리 인터페이스

### 3.1 IUserRepository
```typescript
export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findByAccountId(accountId: string, options?: FindOptions): Promise<User[]>;
  save(user: User): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
  softDelete(id: string): Promise<void>;
  validateCredentials(email: string, password: string): Promise<User | null>;
}
```

### 3.2 ICycleRepository
```typescript
export interface ICycleRepository {
  findById(id: string): Promise<UserCycle | null>;
  findActiveByUserId(userId: string): Promise<UserCycle | null>;
  create(cycle: UserCycle): Promise<UserCycle>;
  update(id: string, data: Partial<UserCycle>): Promise<UserCycle>;
  complete(id: string): Promise<void>;
}
```

## 4. 서비스 구현

### 4.1 UserService
```typescript
@Injectable()
export class UserService {
  constructor(
    @Inject('IUserRepository')
    private readonly userRepository: IUserRepository,
    private readonly eventEmitter: EventEmitter2,
    private readonly cacheService: UserCacheService,
    private readonly timeMachine: TimeMachineService
  ) {}

  async createUser(dto: CreateUserDto): Promise<User> {
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new UserError(
        ErrorCode.DUPLICATE_EMAIL,
        '이미 존재하는 이메일입니다.'
      );
    }

    const user = new User();
    Object.assign(user, dto);
    user.setPassword(dto.password);

    const savedUser = await this.userRepository.save(user);
    await this.eventEmitter.emit('user.created', savedUser);
    await this.cacheService.invalidateUser(savedUser.id);

    return savedUser;
  }

  async updateUser(id: string, dto: UpdateUserDto): Promise<User> {
    const user = await this.getUser(id);
    Object.assign(user, dto);

    const updatedUser = await this.userRepository.update(id, user);
    await this.eventEmitter.emit('user.updated', updatedUser);
    await this.cacheService.invalidateUser(id);

    return updatedUser;
  }

  @Cacheable('user', { ttl: 300 })
  async getUser(id: string): Promise<User> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      throw new UserError(
        ErrorCode.USER_NOT_FOUND,
        '사용자를 찾을 수 없습니다.'
      );
    }
    return user;
  }
}
```

### 4.2 AuthService
```typescript
@Injectable()
export class AuthService {
  constructor(
    @Inject('IUserRepository')
    private readonly userRepository: IUserRepository,
    private readonly jwtService: JwtService,
    private readonly timeMachine: TimeMachineService
  ) {}

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.userRepository.validateCredentials(email, password);
    if (!user) {
      throw new AuthError(
        ErrorCode.INVALID_CREDENTIALS,
        '이메일 또는 비밀번호가 잘못되었습니다.'
      );
    }
    return user;
  }

  async login(user: User): Promise<TokenDto> {
    const payload = { sub: user.id, email: user.email, role: user.role };
    
    const now = await this.timeMachine.getCurrentTime();
    const accessToken = this.jwtService.sign(payload, { expiresIn: '1h' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '14d' });

    user.lastLoginAt = now;
    await this.userRepository.update(user.id, user);

    return {
      accessToken,
      refreshToken,
      expiresIn: 3600,
      tokenType: 'Bearer'
    };
  }
}
```

## 5. 컨트롤러 구현

### 5.1 UserController
```typescript
@Controller('users')
@UseGuards(AuthGuard)
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly authService: AuthService
  ) {}

  @Post('register')
  @Public()
  async register(@Body() dto: CreateUserDto): Promise<UserResponseDto> {
    const user = await this.userService.createUser(dto);
    return UserResponseDto.fromEntity(user);
  }

  @Get(':id')
  async getUser(@Param('id') id: string): Promise<UserResponseDto> {
    const user = await this.userService.getUser(id);
    return UserResponseDto.fromEntity(user);
  }

  @Patch(':id')
  async updateUser(
    @Param('id') id: string,
    @Body() dto: UpdateUserDto
  ): Promise<UserResponseDto> {
    const user = await this.userService.updateUser(id, dto);
    return UserResponseDto.fromEntity(user);
  }

  @Post('login')
  @Public()
  async login(@Body() dto: LoginDto): Promise<TokenDto> {
    const user = await this.authService.validateUser(dto.email, dto.password);
    return this.authService.login(user);
  }
}
```

## 6. 이벤트 처리

### 6.1 UserEventHandler
```typescript
@Injectable()
export class UserEventHandler {
  constructor(
    private readonly cacheService: UserCacheService,
    private readonly notificationService: NotificationService
  ) {}

  @OnEvent('user.created')
  async handleUserCreated(user: User) {
    await this.notificationService.sendWelcomeEmail(user);
  }

  @OnEvent('user.updated')
  async handleUserUpdated(user: User) {
    await this.cacheService.invalidateUser(user.id);
  }

  @OnEvent('user.deactivated')
  async handleUserDeactivated(user: User) {
    await this.cacheService.invalidateUser(user.id);
    await this.notificationService.sendDeactivationEmail(user);
  }
}
```

## 7. 캐싱 전략

### 7.1 UserCacheService
```typescript
@Injectable()
export class UserCacheService {
  constructor(
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache
  ) {}

  private getKey(userId: string): string {
    return `user:${userId}`;
  }

  async getUser(userId: string): Promise<User | null> {
    return this.cacheManager.get<User>(this.getKey(userId));
  }

  async setUser(user: User): Promise<void> {
    await this.cacheManager.set(
      this.getKey(user.id),
      user,
      { ttl: 300 }
    );
  }

  async invalidateUser(userId: string): Promise<void> {
    await this.cacheManager.del(this.getKey(userId));
  }
}
```

## 8. 에러 처리

### 8.1 UserError
```typescript
export class UserError extends BaseError {
  constructor(code: ErrorCode, message: string, details?: any) {
    super(code, message, details);
    this.name = 'UserError';
  }
}
```

### 8.2 UserExceptionFilter
```typescript
@Catch(UserError)
export class UserExceptionFilter implements ExceptionFilter {
  catch(exception: UserError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = this.getHttpStatus(exception.code);

    response.status(status).json({
      status,
      code: exception.code,
      message: exception.message,
      detail: exception.details
    });
  }

  private getHttpStatus(code: ErrorCode): number {
    switch (code) {
      case ErrorCode.USER_NOT_FOUND:
        return HttpStatus.NOT_FOUND;
      case ErrorCode.INVALID_CREDENTIALS:
        return HttpStatus.UNAUTHORIZED;
      default:
        return HttpStatus.BAD_REQUEST;
    }
  }
}
```

## 9. 모니터링

### 9.1 UserMetricsService
```typescript
@Injectable()
export class UserMetricsService {
  private readonly histogram: Histogram;

  constructor() {
    this.histogram = new Histogram({
      name: 'user_operation_duration_seconds',
      help: 'Duration of user operations in seconds',
      labelNames: ['operation']
    });
  }

  async measureOperation<T>(
    operation: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const end = this.histogram.startTimer({ operation });
    try {
      return await fn();
    } finally {
      end();
    }
  }
}
```

## 10. 성능 최적화

### 10.1 데이터베이스 인덱스
```typescript
@Entity()
@Index(['email'], { unique: true })
@Index(['accountId', 'status'])
@Index(['lastLoginAt'])
export class User extends BaseEntity {
  // ... entity definition
}
```

### 10.2 N+1 쿼리 방지
```typescript
@Injectable()
export class UserService {
  async getUsersWithAccount(accountId: string): Promise<User[]> {
    return this.userRepository.findByAccountId(accountId, {
      relations: ['account'],
      join: {
        alias: 'user',
        leftJoinAndSelect: {
          account: 'user.account'
        }
      }
    });
  }
}
```

## 11. IAM 통합 구현

### 11.1 Prisma 스키마 정의
```prisma
// schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
  schemas  = ["public", "private"]
}

model UserAccount {
  id          Int       @id @default(autoincrement())
  displayName String?   @map("display_name") @db.VarChar(255)
  userName    String?   @map("user_name") @db.VarChar(100)
  timezoneId  String    @default("Asia/Seoul") @map("timezone_id") @db.VarChar(30)
  userCycleId Int?      @map("user_cycle_id")
  createdAt   DateTime  @default(now()) @map("created_at") @db.Timestamptz()
  updatedAt   DateTime  @default(now()) @map("updated_at") @db.Timestamptz()
  deleted     Boolean   @default(false)
  deletedAt   DateTime? @map("deleted_at") @db.Timestamptz()
  
  userCycle        UserCycle? @relation(fields: [userCycleId], references: [id], onDelete: SetNull)
  iamMappings      UserIAMMapping[]
  requestsReceived IAMChangeRequest[] @relation("targetUser")
  requestsCreated  IAMChangeRequest[] @relation("requesterUser")
  
  @@index([timezoneId], name: "idx_user_account_timezone")
  @@index([userCycleId], name: "idx_user_account_cycle")
  @@map("user_account")
  @@schema("private")
}

// ... 기존 모델 유지 ...

model UserIAMMapping {
  id            Int       @id @default(autoincrement())
  userId        Int       @map("user_id")
  iamRoleId     String    @map("iam_role_id") @db.VarChar(100)
  organizationId String?   @map("organization_id") @db.VarChar(100)
  teamId        String?   @map("team_id") @db.VarChar(100)
  assignedAt    DateTime  @default(now()) @map("assigned_at") @db.Timestamptz()
  revokedAt     DateTime? @map("revoked_at") @db.Timestamptz()
  expiresAt     DateTime? @map("expires_at") @db.Timestamptz()
  approvalStatus String    @default("APPROVED") @map("approval_status") @db.VarChar(20)
  approvedBy    Int?      @map("approved_by")
  createdAt     DateTime  @default(now()) @map("created_at") @db.Timestamptz()
  updatedAt     DateTime  @default(now()) @map("updated_at") @db.Timestamptz()
  
  user          UserAccount @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId], name: "idx_user_iam_mapping_user")
  @@index([iamRoleId], name: "idx_user_iam_mapping_role")
  @@index([organizationId], name: "idx_user_iam_mapping_org")
  @@map("user_iam_mapping")
  @@schema("private")
}

model IAMChangeRequest {
  id            Int       @id @default(autoincrement())
  requesterId   Int       @map("requester_id")
  userId        Int       @map("user_id")
  iamRoleId     String    @map("iam_role_id") @db.VarChar(100)
  operation     String    @map("operation") @db.VarChar(20)
  reason        String    @map("reason") @db.Text
  status        String    @default("PENDING") @map("status") @db.VarChar(20)
  approvedBy    Int?      @map("approved_by")
  approvalNotes String?   @map("approval_notes") @db.Text
  createdAt     DateTime  @default(now()) @map("created_at") @db.Timestamptz()
  updatedAt     DateTime  @default(now()) @map("updated_at") @db.Timestamptz()

  user          UserAccount @relation(fields: [userId], references: [id], onDelete: Cascade, name: "targetUser")
  requester     UserAccount @relation(fields: [requesterId], references: [id], name: "requesterUser")
  
  @@index([userId], name: "idx_iam_change_request_user")
  @@index([status], name: "idx_iam_change_request_status")
  @@index([requesterId], name: "idx_iam_change_request_requester")
  @@map("iam_change_request")
  @@schema("private")
}
```

### 11.2 엔티티 및 값 객체 구현

#### UserIAMMapping 엔티티
```typescript
export class UserIAMMapping {
  id: number;
  userId: number;
  iamRoleId: string;
  organizationId?: string;
  teamId?: string;
  assignedAt: Date;
  revokedAt?: Date;
  expiresAt?: Date;
  approvalStatus: UserIAMApprovalStatus;
  approvedBy?: number;
  createdAt: Date;
  updatedAt: Date;
  
  // 관계
  user?: UserAccount;
  
  // 비즈니스 규칙
  isActive(): boolean {
    const now = new Date();
    return (
      this.approvalStatus === UserIAMApprovalStatus.APPROVED &&
      !this.revokedAt &&
      (!this.expiresAt || this.expiresAt > now)
    );
  }
  
  revokeRole(now: Date = new Date()): void {
    if (this.revokedAt) {
      throw new Error('이미 회수된 역할입니다.');
    }
    this.revokedAt = now;
  }
  
  approve(approverId: number): void {
    if (this.approvalStatus !== UserIAMApprovalStatus.PENDING) {
      throw new Error('승인 대기 상태가 아닙니다.');
    }
    this.approvalStatus = UserIAMApprovalStatus.APPROVED;
    this.approvedBy = approverId;
  }
  
  reject(approverId: number): void {
    if (this.approvalStatus !== UserIAMApprovalStatus.PENDING) {
      throw new Error('승인 대기 상태가 아닙니다.');
    }
    this.approvalStatus = UserIAMApprovalStatus.REJECTED;
    this.approvedBy = approverId;
  }
}

export enum UserIAMApprovalStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED'
}
```

#### IAMRole 값 객체
```typescript
export class IAMRole {
  id: string;
  name: string;
  description: string;
  permissions: IAMPermission[];
  scopeType?: IAMScopeType;
  scopeDefinition?: object;
  isSystemRole: boolean;
  createdAt: Date;
  updatedAt: Date;
  
  hasPermission(resourceType: string, action: string): boolean {
    return this.permissions.some(
      perm => perm.resource === resourceType && perm.action === action
    );
  }
}

export enum IAMScopeType {
  GLOBAL = 'GLOBAL',
  ORGANIZATION = 'ORGANIZATION', 
  TEAM = 'TEAM',
  SITE = 'SITE',
  RESOURCE = 'RESOURCE'
}

export class IAMPermission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
}
```

### 11.3 리포지토리 구현

#### IUserIAMRepository 인터페이스
```typescript
export interface IUserIAMRepository {
  findById(id: number): Promise<UserIAMMapping | null>;
  findActiveByUser(userId: number): Promise<UserIAMMapping[]>;
  findByUserAndRole(userId: number, roleId: string): Promise<UserIAMMapping | null>;
  create(mapping: UserIAMMapping): Promise<UserIAMMapping>;
  update(id: number, data: Partial<UserIAMMapping>): Promise<UserIAMMapping>;
  revokeRole(id: number, revokedAt: Date): Promise<UserIAMMapping>;
  getUserRoleHistory(userId: number): Promise<UserIAMMapping[]>;
}
```

#### PrismaUserIAMRepository 구현
```typescript
@Injectable()
export class PrismaUserIAMRepository implements IUserIAMRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: number): Promise<UserIAMMapping | null> {
    const mapping = await this.prisma.userIAMMapping.findUnique({
      where: { id }
    });
    return mapping ? this.mapToEntity(mapping) : null;
  }

  async findActiveByUser(userId: number): Promise<UserIAMMapping[]> {
    const now = new Date();
    const mappings = await this.prisma.userIAMMapping.findMany({
      where: {
        userId,
        approvalStatus: 'APPROVED',
        revokedAt: null,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: now } }
        ]
      }
    });
    return mappings.map(this.mapToEntity);
  }

  async findByUserAndRole(userId: number, roleId: string): Promise<UserIAMMapping | null> {
    const mapping = await this.prisma.userIAMMapping.findFirst({
      where: {
        userId,
        iamRoleId: roleId,
        revokedAt: null
      }
    });
    return mapping ? this.mapToEntity(mapping) : null;
  }

  async create(mapping: UserIAMMapping): Promise<UserIAMMapping> {
    const created = await this.prisma.userIAMMapping.create({
      data: {
        userId: mapping.userId,
        iamRoleId: mapping.iamRoleId,
        organizationId: mapping.organizationId,
        teamId: mapping.teamId,
        assignedAt: mapping.assignedAt,
        expiresAt: mapping.expiresAt,
        approvalStatus: mapping.approvalStatus
      }
    });
    return this.mapToEntity(created);
  }

  async update(id: number, data: Partial<UserIAMMapping>): Promise<UserIAMMapping> {
    const updated = await this.prisma.userIAMMapping.update({
      where: { id },
      data
    });
    return this.mapToEntity(updated);
  }

  async revokeRole(id: number, revokedAt: Date): Promise<UserIAMMapping> {
    const updated = await this.prisma.userIAMMapping.update({
      where: { id },
      data: { revokedAt }
    });
    return this.mapToEntity(updated);
  }

  async getUserRoleHistory(userId: number): Promise<UserIAMMapping[]> {
    const mappings = await this.prisma.userIAMMapping.findMany({
      where: { userId },
      orderBy: { assignedAt: 'desc' }
    });
    return mappings.map(this.mapToEntity);
  }

  private mapToEntity(prismaMapping: any): UserIAMMapping {
    const mapping = new UserIAMMapping();
    Object.assign(mapping, prismaMapping);
    return mapping;
  }
}
```

### 11.4 서비스 구현

#### UserIAMService 구현
```typescript
@Injectable()
export class UserIAMService {
  constructor(
    @Inject('IUserIAMRepository')
    private readonly userIAMRepository: IUserIAMRepository,
    @Inject('IIAMChangeRequestRepository')
    private readonly changeRequestRepository: IIAMChangeRequestRepository,
    private readonly iamClient: IAMClient,
    private readonly auditService: AuditService,
    private readonly eventEmitter: EventEmitter2,
    private readonly cacheService: IAMCacheService
  ) {}

  async getUserRoles(userId: number): Promise<IAMRole[]> {
    // 캐시에서 먼저 확인
    const cachedRoles = await this.cacheService.getUserRoles(userId);
    if (cachedRoles) return cachedRoles;

    // 활성 역할 매핑 조회
    const activeMappings = await this.userIAMRepository.findActiveByUser(userId);
    
    // IAM 서비스에서 역할 정보 조회
    const roles: IAMRole[] = [];
    for (const mapping of activeMappings) {
      const role = await this.iamClient.getRole(mapping.iamRoleId);
      if (role) roles.push(role);
    }
    
    // 결과 캐싱
    await this.cacheService.setUserRoles(userId, roles);
    return roles;
  }

  async getUserPermissions(userId: number): Promise<IAMPermission[]> {
    // 캐시에서 먼저 확인
    const cachedPermissions = await this.cacheService.getUserPermissions(userId);
    if (cachedPermissions) return cachedPermissions;

    // 역할 조회
    const roles = await this.getUserRoles(userId);
    
    // 권한 추출 및 중복 제거
    const uniquePermissions = new Map<string, IAMPermission>();
    for (const role of roles) {
      for (const permission of role.permissions) {
        uniquePermissions.set(permission.id, permission);
      }
    }
    
    const permissions = Array.from(uniquePermissions.values());
    
    // 결과 캐싱
    await this.cacheService.setUserPermissions(userId, permissions);
    return permissions;
  }

  async hasPermission(
    userId: number,
    resourceType: string,
    resourceId: string,
    action: string
  ): Promise<boolean> {
    // 감사 로깅 위한 컨텍스트 준비
    const auditContext = {
      userId,
      resourceType,
      resourceId,
      action,
      timestamp: new Date()
    };
    
    try {
      const permissions = await this.getUserPermissions(userId);
      
      // 권한 검증
      const hasPermission = permissions.some(
        p => p.resource === resourceType && p.action === action
      );
      
      // 감사 로깅
      await this.auditService.logPermissionCheck({
        ...auditContext,
        result: hasPermission ? 'ALLOWED' : 'DENIED'
      });
      
      return hasPermission;
    } catch (error) {
      // 에러 발생 시 감사 로깅
      await this.auditService.logPermissionCheck({
        ...auditContext,
        result: 'ERROR',
        error: error.message
      });
      throw error;
    }
  }

  async assignRole(
    requesterId: number,
    userId: number,
    roleId: string,
    options?: {
      expiresAt?: Date,
      organizationId?: string,
      teamId?: string,
      requireApproval?: boolean
    }
  ): Promise<UserIAMMapping> {
    // 역할 정보 조회
    const role = await this.iamClient.getRole(roleId);
    if (!role) throw new Error('존재하지 않는 역할입니다.');
    
    // 기존 매핑 확인
    const existingMapping = await this.userIAMRepository.findByUserAndRole(userId, roleId);
    if (existingMapping && existingMapping.isActive()) {
      throw new Error('이미 할당된 역할입니다.');
    }
    
    // 권한 검증
    const canAssign = await this.iamClient.canAssignRole(requesterId, roleId, userId, options?.organizationId);
    if (!canAssign) {
      throw new Error('역할을 할당할 권한이 없습니다.');
    }
    
    // 매핑 생성
    const mapping = new UserIAMMapping();
    mapping.userId = userId;
    mapping.iamRoleId = roleId;
    mapping.organizationId = options?.organizationId;
    mapping.teamId = options?.teamId;
    mapping.assignedAt = new Date();
    mapping.expiresAt = options?.expiresAt;
    mapping.approvalStatus = options?.requireApproval 
      ? UserIAMApprovalStatus.PENDING 
      : UserIAMApprovalStatus.APPROVED;
    
    // 저장
    const savedMapping = await this.userIAMRepository.create(mapping);
    
    // 이벤트 발행
    await this.eventEmitter.emit('user.iam.role.assigned', {
      userId,
      roleId,
      requesterId,
      mapping: savedMapping
    });
    
    // 캐시 무효화
    await this.cacheService.invalidateUserRoles(userId);
    await this.cacheService.invalidateUserPermissions(userId);
    
    // 감사 로깅
    await this.auditService.logRoleAssignment({
      userId,
      roleId,
      requesterId,
      organization: options?.organizationId,
      team: options?.teamId,
      expiresAt: options?.expiresAt
    });
    
    return savedMapping;
  }
}
```

### 11.5 컨트롤러 구현

#### UserIAMController
```typescript
@Controller('users/iam')
@UseGuards(AuthGuard)
export class UserIAMController {
  constructor(
    private readonly userIAMService: UserIAMService
  ) {}

  @Get(':userId/roles')
  @Roles(['USER_ADMIN', 'IAM_ADMIN'])
  async getUserRoles(@Param('userId', ParseIntPipe) userId: number): Promise<RoleResponseDto[]> {
    const roles = await this.userIAMService.getUserRoles(userId);
    return roles.map(role => RoleResponseDto.fromEntity(role));
  }

  @Post(':userId/roles')
  @Roles(['USER_ADMIN', 'IAM_ADMIN'])
  async assignRole(
    @Param('userId', ParseIntPipe) userId: number,
    @Body() dto: AssignRoleDto,
    @CurrentUser() currentUser: UserDto
  ): Promise<RoleMappingResponseDto> {
    const mapping = await this.userIAMService.assignRole(
      currentUser.id,
      userId,
      dto.roleId,
      {
        expiresAt: dto.expiresAt,
        organizationId: dto.organizationId,
        teamId: dto.teamId,
        requireApproval: dto.requireApproval
      }
    );
    return RoleMappingResponseDto.fromEntity(mapping);
  }

  @Delete(':userId/roles/:roleId')
  @Roles(['USER_ADMIN', 'IAM_ADMIN'])
  @HttpCode(204)
  async revokeRole(
    @Param('userId', ParseIntPipe) userId: number,
    @Param('roleId') roleId: string,
    @CurrentUser() currentUser: UserDto
  ): Promise<void> {
    await this.userIAMService.revokeRole(
      currentUser.id,
      userId,
      roleId
    );
  }

  @Get('requests')
  @Roles(['USER_ADMIN', 'IAM_ADMIN'])
  async getRequests(
    @Query() query: GetRequestsDto,
    @CurrentUser() currentUser: UserDto
  ): Promise<PaginatedResponse<ChangeRequestResponseDto>> {
    const { items, total } = await this.userIAMService.getChangeRequests({
      ...query,
      approverId: query.myApprovals ? currentUser.id : undefined
    });
    
    return {
      items: items.map(item => ChangeRequestResponseDto.fromEntity(item)),
      total,
      page: query.page || 1,
      pageSize: query.pageSize || 20
    };
  }

  @Post('check-permission')
  async checkPermission(
    @Body() dto: CheckPermissionDto,
    @CurrentUser() currentUser: UserDto
  ): Promise<{ hasPermission: boolean }> {
    const result = await this.userIAMService.hasPermission(
      currentUser.id,
      dto.resourceType,
      dto.resourceId,
      dto.action
    );
    return { hasPermission: result };
  }
}
```

### 11.6 미들웨어 구현

#### PermissionMiddleware
```typescript
@Injectable()
export class PermissionMiddleware implements NestMiddleware {
  constructor(
    private readonly userIAMService: UserIAMService,
    private readonly reflector: Reflector
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const user = req.user;
    if (!user) return next();

    // 권한 요구사항 가져오기
    const handler = context.getHandler();
    const controller = context.getClass();
    
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      'permissions',
      [handler, controller]
    );
    
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return next();
    }
    
    // 요청 파라미터에서 리소스 ID 추출
    const resourceId = req.params.id || '';
    
    // 권한 확인
    try {
      for (const permission of requiredPermissions) {
        const [resourceType, action] = permission.split(':');
        
        const hasPermission = await this.userIAMService.hasPermission(
          user.id,
          resourceType,
          resourceId,
          action
        );
        
        if (!hasPermission) {
          throw new ForbiddenException('필요한 권한이 없습니다.');
        }
      }
      
      next();
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new InternalServerErrorException('권한 확인 중 오류가 발생했습니다.');
    }
  }
}
```

### 11.7 Prisma 사용 가이드

#### Prisma 초기화 및 마이그레이션
```typescript
// app.module.ts
@Module({
  imports: [
    UserModule,
    PrismaModule
  ],
  // ...
})
export class AppModule {}

// prisma.module.ts
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}

// prisma.service.ts
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'stdout', level: 'info' },
        { emit: 'stdout', level: 'warn' },
        { emit: 'stdout', level: 'error' },
      ],
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
```

#### Prisma 마이그레이션 실행
```bash
# 마이그레이션 생성
npx prisma migrate dev --name add_iam_tables

# 마이그레이션 적용 (프로덕션)
npx prisma migrate deploy
```

## 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-19 | bok@weltcorp.com | IAM 통합 구현 가이드 추가 |