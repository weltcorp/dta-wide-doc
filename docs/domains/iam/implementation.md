# IAM 도메인 구현 가이드

## 1. 개요
이 문서는 IAM(Identity and Access Management) 도메인의 구현 가이드를 제공합니다. IAM 도메인은 시스템 전반의 권한 관리, 역할 관리, 정책 관리를 담당합니다.

## 2. 구현 구조

### 2.1 모듈 구조
```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([Permission, Role, Policy, Principal]),
    CacheModule.register({
      store: redisStore,
      ttl: 300,
    }),
    EventEmitterModule.forRoot(),
  ],
  controllers: [
    PermissionController,
    RoleController,
    PolicyController,
  ],
  providers: [
    PermissionService,
    RoleService,
    PolicyService,
    PermissionEvaluationService,
    CacheService,
  ],
  exports: [
    PermissionService,
    RoleService,
    PolicyService,
  ],
})
export class IamModule {}
```

### 2.2 엔티티 구현

#### Permission 엔티티
```typescript
@Entity()
export class Permission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  description: string;

  @Column()
  domain: string;

  @Column()
  action: string;

  @Column()
  resource: string;

  @Column('jsonb', { nullable: true })
  metadata: Record<string, any>;

  @ManyToMany(() => Role, role => role.permissions)
  roles: Role[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

#### Role 엔티티
```typescript
@Entity()
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  description: string;

  @Column({ nullable: true })
  parentRoleId: string;

  @ManyToMany(() => Permission, permission => permission.roles)
  @JoinTable()
  permissions: Permission[];

  @ManyToMany(() => Principal, principal => principal.roles)
  principals: Principal[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

#### Policy 엔티티
```typescript
@Entity()
export class Policy {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  description: string;

  @Column('jsonb')
  conditions: PolicyCondition[];

  @Column({
    type: 'enum',
    enum: PolicyEffect,
    default: PolicyEffect.ALLOW,
  })
  effect: PolicyEffect;

  @Column()
  priority: number;

  @Column('jsonb', { nullable: true })
  metadata: Record<string, any>;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

### 2.3 서비스 구현

#### PermissionService
```typescript
@Injectable()
export class PermissionService {
  constructor(
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    private eventEmitter: EventEmitter2,
    private cacheService: CacheService,
  ) {}

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const permission = this.permissionRepository.create(createPermissionDto);
    await this.permissionRepository.save(permission);
    
    this.eventEmitter.emit('permission.created', permission);
    await this.cacheService.invalidatePermissionCache();
    
    return permission;
  }

  async findAll(query: FindPermissionDto): Promise<Permission[]> {
    const cacheKey = `permissions:${JSON.stringify(query)}`;
    const cached = await this.cacheService.get<Permission[]>(cacheKey);
    
    if (cached) {
      return cached;
    }

    const permissions = await this.permissionRepository.find({
      where: query,
      relations: ['roles'],
    });

    await this.cacheService.set(cacheKey, permissions);
    return permissions;
  }

  async update(id: string, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
    const permission = await this.permissionRepository.findOne({ where: { id } });
    if (!permission) {
      throw new NotFoundException(`Permission with ID "${id}" not found`);
    }

    Object.assign(permission, updatePermissionDto);
    await this.permissionRepository.save(permission);
    
    this.eventEmitter.emit('permission.updated', permission);
    await this.cacheService.invalidatePermissionCache();
    
    return permission;
  }

  async delete(id: string): Promise<void> {
    const permission = await this.permissionRepository.findOne({ where: { id } });
    if (!permission) {
      throw new NotFoundException(`Permission with ID "${id}" not found`);
    }

    await this.permissionRepository.remove(permission);
    this.eventEmitter.emit('permission.deleted', permission);
    await this.cacheService.invalidatePermissionCache();
  }
}
```

#### RoleService
```typescript
@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private eventEmitter: EventEmitter2,
    private cacheService: CacheService,
  ) {}

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const role = this.roleRepository.create(createRoleDto);
    await this.roleRepository.save(role);
    
    this.eventEmitter.emit('role.created', role);
    await this.cacheService.invalidateRoleCache();
    
    return role;
  }

  async findAll(query: FindRoleDto): Promise<Role[]> {
    const cacheKey = `roles:${JSON.stringify(query)}`;
    const cached = await this.cacheService.get<Role[]>(cacheKey);
    
    if (cached) {
      return cached;
    }

    const roles = await this.roleRepository.find({
      where: query,
      relations: ['permissions', 'principals'],
    });

    await this.cacheService.set(cacheKey, roles);
    return roles;
  }

  async assignPermissions(id: string, permissionIds: string[]): Promise<Role> {
    const role = await this.roleRepository.findOne({
      where: { id },
      relations: ['permissions'],
    });
    
    if (!role) {
      throw new NotFoundException(`Role with ID "${id}" not found`);
    }

    const permissions = await this.permissionRepository.findByIds(permissionIds);
    role.permissions = permissions;
    
    await this.roleRepository.save(role);
    this.eventEmitter.emit('role.permissions.updated', role);
    await this.cacheService.invalidateRoleCache();
    
    return role;
  }
}
```

#### PolicyService
```typescript
@Injectable()
export class PolicyService {
  constructor(
    @InjectRepository(Policy)
    private policyRepository: Repository<Policy>,
    private eventEmitter: EventEmitter2,
    private cacheService: CacheService,
  ) {}

  async create(createPolicyDto: CreatePolicyDto): Promise<Policy> {
    const policy = this.policyRepository.create(createPolicyDto);
    await this.policyRepository.save(policy);
    
    this.eventEmitter.emit('policy.created', policy);
    await this.cacheService.invalidatePolicyCache();
    
    return policy;
  }

  async evaluate(context: PolicyEvaluationContext): Promise<PolicyEvaluation> {
    const cacheKey = `policy:evaluation:${JSON.stringify(context)}`;
    const cached = await this.cacheService.get<PolicyEvaluation>(cacheKey);
    
    if (cached) {
      return cached;
    }

    const policies = await this.policyRepository.find({
      order: { priority: 'DESC' },
    });

    for (const policy of policies) {
      const evaluation = await this.evaluatePolicy(policy, context);
      if (evaluation.effect !== PolicyEffect.NEUTRAL) {
        await this.cacheService.set(cacheKey, evaluation);
        return evaluation;
      }
    }

    return { effect: PolicyEffect.DENY };
  }
}
```

### 2.4 컨트롤러 구현

#### PermissionController
```typescript
@Controller('permissions')
@UseGuards(AuthGuard)
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post()
  @UseGuards(AdminGuard)
  async create(@Body() createPermissionDto: CreatePermissionDto): Promise<Permission> {
    return this.permissionService.create(createPermissionDto);
  }

  @Get()
  async findAll(@Query() query: FindPermissionDto): Promise<Permission[]> {
    return this.permissionService.findAll(query);
  }

  @Put(':id')
  @UseGuards(AdminGuard)
  async update(
    @Param('id') id: string,
    @Body() updatePermissionDto: UpdatePermissionDto,
  ): Promise<Permission> {
    return this.permissionService.update(id, updatePermissionDto);
  }

  @Delete(':id')
  @UseGuards(AdminGuard)
  async delete(@Param('id') id: string): Promise<void> {
    return this.permissionService.delete(id);
  }
}
```

### 2.5 미들웨어 구현

#### PermissionGuard
```typescript
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly permissionEvaluationService: PermissionEvaluationService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<string[]>(
      'permissions',
      context.getHandler(),
    );

    if (!requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      return false;
    }

    const hasPermission = await this.permissionEvaluationService.evaluatePermissions(
      user,
      requiredPermissions,
    );

    return hasPermission;
  }
}
```

### 2.6 캐시 구현

#### CacheService
```typescript
@Injectable()
export class CacheService {
  constructor(
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async get<T>(key: string): Promise<T | null> {
    return this.cacheManager.get<T>(key);
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.cacheManager.set(key, value, ttl);
  }

  async invalidatePermissionCache(): Promise<void> {
    const keys = await this.cacheManager.store.keys('permissions:*');
    await Promise.all(keys.map(key => this.cacheManager.del(key)));
  }

  async invalidateRoleCache(): Promise<void> {
    const keys = await this.cacheManager.store.keys('roles:*');
    await Promise.all(keys.map(key => this.cacheManager.del(key)));
  }

  async invalidatePolicyCache(): Promise<void> {
    const keys = await this.cacheManager.store.keys('policy:*');
    await Promise.all(keys.map(key => this.cacheManager.del(key)));
  }
}
```

## 3. 데이터베이스 스키마

### 3.1 Permission 테이블
```sql
CREATE TABLE permission (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  domain VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_permission_domain ON permission(domain);
CREATE INDEX idx_permission_action ON permission(action);
CREATE INDEX idx_permission_resource ON permission(resource);
```

### 3.2 Role 테이블
```sql
CREATE TABLE role (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  parent_role_id UUID REFERENCES role(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permission (
  role_id UUID REFERENCES role(id) ON DELETE CASCADE,
  permission_id UUID REFERENCES permission(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_name ON role(name);
CREATE INDEX idx_role_parent ON role(parent_role_id);
```

### 3.3 Policy 테이블
```sql
CREATE TYPE policy_effect AS ENUM ('allow', 'deny');

CREATE TABLE policy (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  conditions JSONB NOT NULL,
  effect policy_effect NOT NULL DEFAULT 'allow',
  priority INTEGER NOT NULL DEFAULT 0,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policy_priority ON policy(priority DESC);
```

## 4. API 엔드포인트

### 4.1 Permission API
- `POST /permissions`: 새로운 권한 생성
- `GET /permissions`: 권한 목록 조회
- `GET /permissions/:id`: 특정 권한 조회
- `PUT /permissions/:id`: 권한 정보 수정
- `DELETE /permissions/:id`: 권한 삭제

### 4.2 Role API
- `POST /roles`: 새로운 역할 생성
- `GET /roles`: 역할 목록 조회
- `GET /roles/:id`: 특정 역할 조회
- `PUT /roles/:id`: 역할 정보 수정
- `DELETE /roles/:id`: 역할 삭제
- `POST /roles/:id/permissions`: 역할에 권한 할당

### 4.3 Policy API
- `POST /policies`: 새로운 정책 생성
- `GET /policies`: 정책 목록 조회
- `GET /policies/:id`: 특정 정책 조회
- `PUT /policies/:id`: 정책 정보 수정
- `DELETE /policies/:id`: 정책 삭제
- `POST /policies/evaluate`: 정책 평가

## 5. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2024-03-21 | bok@weltcorp.com | 최초 작성 | 