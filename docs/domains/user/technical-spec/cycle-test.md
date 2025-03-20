# 사용자 주기 테스트 명세

## 1. 단위 테스트

### UserCycle 엔티티
```typescript
describe('UserCycle', () => {
  describe('상태 전이 검증', () => {
    it('PENDING에서 ACTIVE로 전환 가능', () => {
      // Arrange
      const cycle = new UserCycle({ status: UserCycleStatus.PENDING });
      
      // Act & Assert
      expect(() => cycle.activate()).not.toThrow();
      expect(cycle.status).toBe(UserCycleStatus.ACTIVE);
    });

    it('ACTIVE에서 COMPLETED로 전환 시 endAt 필수', () => {
      // Arrange
      const cycle = new UserCycle({ status: UserCycleStatus.ACTIVE });
      
      // Act & Assert
      expect(() => cycle.complete()).toThrow();
      expect(() => cycle.complete({ endAt: new Date() })).not.toThrow();
    });

    it('COMPLETED 상태에서 다른 상태로 전환 불가', () => {
      // Arrange
      const cycle = new UserCycle({ status: UserCycleStatus.COMPLETED });
      
      // Act & Assert
      expect(() => cycle.activate()).toThrow();
      expect(() => cycle.suspend()).toThrow();
      expect(() => cycle.cancel()).toThrow();
    });
  });

  describe('일자 계산', () => {
    it('시작일이 미래인 경우 예외 발생', () => {
      // Arrange
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 1);
      
      // Act & Assert
      expect(() => new UserCycle({ startAt: futureDate })).toThrow();
    });

    it('중지 기간을 제외하고 활성 일수 계산', () => {
      // Arrange
      const cycle = new UserCycle({
        startAt: new Date('2024-03-01'),
        status: UserCycleStatus.ACTIVE
      });
      
      // 3일 후 중지
      cycle.suspend('테스트를 위한 중지');
      timeMachine.advanceBy('2d'); // 2일 경과
      cycle.activate();
      
      // Act
      const result = cycle.calculateDayIndex();
      
      // Assert
      expect(result.dayIndex).toBe(4); // 3일 활성 + 1일 재개
      expect(result.suspendedDays).toBe(2);
    });
  });
});
```

### CycleManagementService
```typescript
describe('CycleManagementService', () => {
  describe('createCycle', () => {
    it('동일 사용자/사이트의 활성 주기 존재 시 예외 발생', async () => {
      // Arrange
      const existingCycle = {
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE
      };
      cycleRepository.findActiveCycle.mockResolvedValue(existingCycle);
      
      // Act & Assert
      await expect(service.createCycle({
        userId: 1,
        siteId: 1
      })).rejects.toThrow();
    });

    it('만료된 액세스 코드로 생성 시 예외 발생', async () => {
      // Arrange
      const expiredAccesscode = {
        id: 1,
        expiresAt: new Date('2024-01-01')
      };
      accesscodeRepository.findById.mockResolvedValue(expiredAccesscode);
      
      // Act & Assert
      await expect(service.createCycle({
        accesscodeId: 1
      })).rejects.toThrow();
    });
  });

  describe('changeCycleStatus', () => {
    it('권한 없는 사용자의 상태 변경 시도 시 예외 발생', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        status: UserCycleStatus.ACTIVE
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      
      // Act & Assert
      await expect(service.changeCycleStatus({
        cycleId: 1,
        status: UserCycleStatus.SUSPENDED,
        requestUserId: 2 // 다른 사용자
      })).rejects.toThrow();
    });
  });
});
```

### UserCycleIAMIntegration
```typescript
describe('UserCycleIAMIntegration', () => {
  describe('IAM 역할 할당', () => {
    it('유효한 IAM 역할 할당 성공', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE
      };
      const iamRole = {
        id: 'role-123',
        name: 'CycleManager',
        scope: 'SITE'
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      iamService.getRole.mockResolvedValue(iamRole);
      
      // Act
      const result = await service.assignIAMRole({
        cycleId: 1,
        iamRoleId: 'role-123',
        assignerId: 2
      });
      
      // Assert
      expect(result).toBeDefined();
      expect(result.iamRoleId).toBe('role-123');
      expect(result.iamRoleAssignedAt).toBeDefined();
      expect(result.iamRoleAssignedBy).toBe(2);
    });
    
    it('할당 권한 없는 사용자의 역할 할당 시 예외 발생', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      iamService.checkPermission.mockResolvedValue({
        allowed: false,
        reason: 'PERMISSION_DENIED'
      });
      
      // Act & Assert
      await expect(service.assignIAMRole({
        cycleId: 1,
        iamRoleId: 'role-123',
        assignerId: 3
      })).rejects.toThrow('권한이 없습니다');
    });
    
    it('잘못된 스코프의 역할 할당 시 예외 발생', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE
      };
      const iamRole = {
        id: 'role-123',
        name: 'GlobalAdmin',
        scope: 'GLOBAL'
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      iamService.getRole.mockResolvedValue(iamRole);
      iamService.checkPermission.mockResolvedValue({
        allowed: true
      });
      
      // Act & Assert
      await expect(service.assignIAMRole({
        cycleId: 1,
        iamRoleId: 'role-123',
        assignerId: 2,
        permissionSetId: 'ps-123'
      })).rejects.toThrow('역할 스코프가 일치하지 않습니다');
    });
  });
  
  describe('IAM 역할 회수', () => {
    it('할당된 역할 회수 성공', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE,
        iamRoleId: 'role-123',
        iamRoleAssignedAt: new Date('2025-01-01')
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      iamService.checkPermission.mockResolvedValue({
        allowed: true
      });
      
      // Act
      const result = await service.revokeIAMRole({
        cycleId: 1,
        revokerId: 2,
        reason: '불필요한 권한'
      });
      
      // Assert
      expect(result).toBeDefined();
      expect(result.iamRoleRevokedAt).toBeDefined();
      expect(cycleRepository.save).toHaveBeenCalled();
    });
    
    it('이미 회수된 역할 재회수 시 예외 발생', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE,
        iamRoleId: 'role-123',
        iamRoleAssignedAt: new Date('2025-01-01'),
        iamRoleRevokedAt: new Date('2025-01-10')
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      
      // Act & Assert
      await expect(service.revokeIAMRole({
        cycleId: 1,
        revokerId: 2,
        reason: '이미 회수됨'
      })).rejects.toThrow('이미 회수된 역할입니다');
    });
  });
  
  describe('권한 검증', () => {
    it('할당된 역할로 권한 검증 성공', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE,
        iamRoleId: 'role-123'
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      iamService.checkPermission.mockResolvedValue({
        allowed: true,
        requestId: 'req-123'
      });
      
      // Act
      const result = await service.validatePermission({
        cycleId: 1,
        userId: 1,
        permission: 'cycle:update'
      });
      
      // Assert
      expect(result.allowed).toBe(true);
      expect(result.requestId).toBeDefined();
    });
    
    it('만료된 역할로 권한 검증 실패', async () => {
      // Arrange
      const cycle = {
        id: 1,
        userId: 1,
        siteId: 1,
        status: UserCycleStatus.ACTIVE,
        iamRoleId: 'role-123',
        iamRoleAssignedAt: new Date('2025-01-01'),
        iamRoleRevokedAt: new Date('2025-01-10')
      };
      cycleRepository.findById.mockResolvedValue(cycle);
      
      // Act
      const result = await service.validatePermission({
        cycleId: 1,
        userId: 1,
        permission: 'cycle:update'
      });
      
      // Assert
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('ROLE_REVOKED');
    });
  });
});
```

## 2. 통합 테스트

### API 엔드포인트
```typescript
describe('UserCycleController (e2e)', () => {
  describe('POST /v1/user-cycles', () => {
    it('유효한 요청으로 주기 생성 성공', () => {
      // Arrange
      const payload = {
        userId: 1,
        siteId: 1,
        accesscodeId: 1
      };
      
      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/user-cycles')
        .send(payload)
        .expect(201)
        .expect(res => {
          expect(res.body.data).toHaveProperty('id');
          expect(res.body.data.status).toBe(UserCycleStatus.PENDING);
        });
    });
  });

  describe('PATCH /v1/user-cycles/:id/status', () => {
    it('관리자가 주기 상태 변경 성공', () => {
      // Arrange
      const adminToken = generateAdminToken();
      
      // Act & Assert
      return request(app.getHttpServer())
        .patch('/v1/user-cycles/1/status')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          status: UserCycleStatus.SUSPENDED,
          reason: '테스트를 위한 중지'
        })
        .expect(200)
        .expect(res => {
          expect(res.body.data.status).toBe(UserCycleStatus.SUSPENDED);
          expect(res.body.data).toHaveProperty('lastStatusChangeReason');
        });
    });
  });
});

### IAM 통합 API 엔드포인트
```typescript
describe('UserCycleIAMController (e2e)', () => {
  describe('POST /v1/user-cycles/:id/iam-roles', () => {
    it('관리자가 IAM 역할 할당 성공', () => {
      // Arrange
      const adminToken = generateAdminToken();
      const payload = {
        iamRoleId: 'role-123',
        permissionSetId: 'ps-456',
        reason: '표준 권한 할당'
      };
      
      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/user-cycles/1/iam-roles')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(payload)
        .expect(201)
        .expect(res => {
          expect(res.body.data).toHaveProperty('iamRoleId');
          expect(res.body.data).toHaveProperty('iamRoleAssignedAt');
          expect(res.body.data.iamRoleId).toBe('role-123');
        });
    });
    
    it('권한 없는 사용자의 IAM 역할 할당 시도 실패', () => {
      // Arrange
      const userToken = generateUserToken({ userId: 5 });
      const payload = {
        iamRoleId: 'role-123'
      };
      
      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/user-cycles/1/iam-roles')
        .set('Authorization', `Bearer ${userToken}`)
        .send(payload)
        .expect(403);
    });
  });
  
  describe('DELETE /v1/user-cycles/:id/iam-roles', () => {
    it('관리자가 IAM 역할 회수 성공', () => {
      // Arrange
      const adminToken = generateAdminToken();
      const payload = {
        reason: '사용자 요청에 따른 권한 회수'
      };
      
      // Act & Assert
      return request(app.getHttpServer())
        .delete('/v1/user-cycles/1/iam-roles')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(payload)
        .expect(200)
        .expect(res => {
          expect(res.body.data).toHaveProperty('iamRoleRevokedAt');
        });
    });
  });
  
  describe('POST /v1/user-cycles/:id/permissions/check', () => {
    it('권한 검증 API 응답 확인', () => {
      // Arrange
      const userToken = generateUserToken({ userId: 1 });
      const payload = {
        permission: 'cycle:update',
        resourceId: '1'
      };
      
      // Act & Assert
      return request(app.getHttpServer())
        .post('/v1/user-cycles/1/permissions/check')
        .set('Authorization', `Bearer ${userToken}`)
        .send(payload)
        .expect(200)
        .expect(res => {
          expect(res.body.data).toHaveProperty('allowed');
          expect(res.body.data).toHaveProperty('requestId');
          expect(res.body.data).toHaveProperty('responseTime');
        });
    });
  });
});
```

## 3. 성능 테스트

### 시나리오
1. 주기 생성 성능
```typescript
describe('Cycle Creation Performance', () => {
  it('should handle 100 concurrent cycle creation requests', async () => {
    const concurrentRequests = 100;
    const startTime = Date.now();
    
    // 100개의 동시 요청 생성
    const requests = Array(concurrentRequests).fill().map(() => (
      service.createCycle({
        userId: generateUserId(),
        siteId: 1,
        accesscodeId: generateAccesscodeId()
      })
    ));
    
    // 모든 요청 실행
    await Promise.all(requests);
    
    const duration = Date.now() - startTime;
    expect(duration).toBeLessThan(5000); // 5초 이내 완료
  });
});
```

2. 주기 목록 조회 성능
```typescript
describe('Cycle List Performance', () => {
  it('should efficiently handle pagination with large dataset', async () => {
    // 10만건의 테스트 데이터 생성
    await generateTestCycles(100000);
    
    const startTime = Date.now();
    
    // 페이지네이션 테스트
    const result = await service.getCycles({
      page: 1,
      size: 10
    });
    
    const duration = Date.now() - startTime;
    expect(duration).toBeLessThan(100); // 100ms 이내 응답
    expect(result.items).toHaveLength(10);
  });
});
```

### IAM 권한 검증 성능
```typescript
describe('IAM Permission Check Performance', () => {
  it('고성능 권한 검증 확인', async () => {
    // Arrange
    const iterations = 1000;
    const results = [];
    
    // Act
    const startTime = Date.now();
    
    for(let i = 0; i < iterations; i++) {
      results.push(
        service.validatePermission({
          cycleId: 1,
          userId: 1,
          permission: 'cycle:read'
        })
      );
    }
    
    await Promise.all(results);
    
    const duration = Date.now() - startTime;
    const avgTime = duration / iterations;
    
    // Assert
    expect(avgTime).toBeLessThan(5); // 평균 5ms 이내 응답
  });
  
  it('대량 권한 캐싱 성능 확인', async () => {
    // Arrange
    await generateCacheablePermissions(1000);
    
    // Act
    const startTime = Date.now();
    
    const result = await service.bulkValidatePermissions({
      userId: 1,
      permissions: new Array(100).fill().map((_, idx) => ({
        permission: `cycle:action:${idx}`,
        resourceId: '1'
      }))
    });
    
    const duration = Date.now() - startTime;
    
    // Assert
    expect(duration).toBeLessThan(200); // 200ms 이내 응답
    expect(result.length).toBe(100);
    expect(result.every(r => r.hasOwnProperty('allowed'))).toBe(true);
  });
});
```

## 4. 보안 테스트

### 권한 검증
```typescript
describe('Cycle Security', () => {
  it('should prevent unauthorized access to cycle data', async () => {
    // Arrange
    const cycle = await createTestCycle();
    const unauthorizedToken = generateUserToken({ userId: 999 });
    
    // Act & Assert
    return request(app.getHttpServer())
      .get(`/v1/user-cycles/${cycle.id}`)
      .set('Authorization', `Bearer ${unauthorizedToken}`)
      .expect(403);
  });

  it('should validate input to prevent injection', async () => {
    // Arrange
    const maliciousPayload = {
      userId: '1; DROP TABLE user_cycles;',
      siteId: 1
    };
    
    // Act & Assert
    return request(app.getHttpServer())
      .post('/v1/user-cycles')
      .send(maliciousPayload)
      .expect(400);
  });
});

### IAM 권한 보안 테스트
```typescript
describe('IAM Security', () => {
  it('부여된 권한만 사용 가능 확인', async () => {
    // Arrange
    const cycle = await createTestCycle();
    await assignTestRole(cycle.id, 'cycle:read'); // 읽기 권한만 할당
    const userToken = generateUserToken({ userId: cycle.userId });
    
    // Act & Assert - 읽기 권한 성공
    await request(app.getHttpServer())
      .get(`/v1/user-cycles/${cycle.id}`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);
    
    // Act & Assert - 수정 권한 실패
    await request(app.getHttpServer())
      .patch(`/v1/user-cycles/${cycle.id}/status`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ status: UserCycleStatus.SUSPENDED })
      .expect(403);
  });
  
  it('역할 권한 변경 시 즉시 반영 확인', async () => {
    // Arrange
    const cycle = await createTestCycle();
    const roleId = await assignTestRole(cycle.id, 'cycle:read');
    const userToken = generateUserToken({ userId: cycle.userId });
    
    // 첫 번째 요청 - 권한 있음
    await request(app.getHttpServer())
      .get(`/v1/user-cycles/${cycle.id}`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);
    
    // 권한 회수
    await revokeTestRole(cycle.id, roleId);
    
    // 두 번째 요청 - 권한 없음
    await request(app.getHttpServer())
      .get(`/v1/user-cycles/${cycle.id}`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(403);
  });
  
  it('IAM 역할 할당 엔드포인트 권한 상승 취약점 확인', async () => {
    // Arrange
    const adminRoleId = 'admin-role';
    const userToken = generateUserToken({ userId: 1 });
    
    // Act & Assert
    await request(app.getHttpServer())
      .post('/v1/user-cycles/1/iam-roles')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        iamRoleId: adminRoleId,
        reason: '권한 상승 시도'
      })
      .expect(403);
  });
});
```

## 5. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|------|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-30 | bok@weltcorp.com | IAM 관련 테스트 케이스 추가 |