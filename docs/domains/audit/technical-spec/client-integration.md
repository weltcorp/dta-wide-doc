# 클라이언트 통합 가이드

## 1. 개요
이 문서는 Audit 도메인과 클라이언트 애플리케이션 간의 통합 방법을 설명합니다. 특히, JWT 기반 인증 시스템에서 Mobile 클라이언트가 자체적으로 sessionId를 생성하고 이를 Audit 시스템에 전달하는 방법에 초점을 맞춥니다.

## 2. 세션 관리

### 2.1 JWT 기반 인증과 세션 ID

JWT(JSON Web Token) 기반 인증은 기본적으로 stateless하여 서버 측에서 세션을 관리하지 않습니다. 하지만 감사(Audit) 목적으로 사용자 활동의 연속성을 추적하기 위해 클라이언트 측에서 세션 ID를 생성하고 관리하는 방식을 채택했습니다.

#### 서버 측 세션 관리 없음
- 백엔드는 JWT 토큰을 사용한 stateless 인증 방식을 사용
- 서버에서 발급하는 sessionId가 없음
- 각 요청은 독립적으로 인증됨

#### 클라이언트 측 세션 ID 관리
- 모바일 클라이언트에서 세션 ID를 자체적으로 생성
- 연속된 사용자 활동을 하나의 세션으로 그룹화
- 감사 목적으로 이 정보를 서버에 전송

### 2.2 세션 ID 활용 이점

클라이언트 측 세션 ID를 사용함으로써 다음과 같은 이점을 얻을 수 있습니다:

1. **사용자 활동 추적 개선**: 단일 세션 내의 연속된 활동을 그룹화하여 추적
2. **이상 탐지 강화**: 특정 세션 내에서 비정상적인 패턴 식별 용이
3. **문제 해결 간소화**: 사용자 경험 문제를 특정 세션 단위로 조사 가능
4. **사용성 분석**: 세션별 사용자 행동 패턴 분석 가능

## 3. 클라이언트 구현 가이드

### 3.1 세션 ID 생성 및 관리

#### Swift (iOS)
```swift
import Foundation

class SessionManager {
    static let shared = SessionManager()
    
    private let userDefaults = UserDefaults.standard
    private let sessionIdKey = "sessionId"
    private let sessionStartTimeKey = "sessionStartTime"
    
    private var _sessionId: String?
    private var _sessionStartTime: TimeInterval?
    
    private init() {
        loadOrCreateSession()
    }
    
    var sessionId: String {
        return _sessionId ?? createNewSession()
    }
    
    private func loadOrCreateSession() {
        let savedSession = userDefaults.string(forKey: sessionIdKey)
        let savedStartTime = userDefaults.double(forKey: sessionStartTimeKey)
        let currentTime = Date().timeIntervalSince1970
        
        // 저장된 세션이 없거나 4시간이 지난 경우 새로 생성
        if savedSession == nil || savedStartTime == 0 || (currentTime - savedStartTime > 4 * 60 * 60) {
            _ = createNewSession()
        } else {
            _sessionId = savedSession
            _sessionStartTime = savedStartTime
        }
    }
    
    @discardableResult
    private func createNewSession() -> String {
        let newId = UUID().uuidString
        let currentTime = Date().timeIntervalSince1970
        
        _sessionId = newId
        _sessionStartTime = currentTime
        
        userDefaults.set(newId, forKey: sessionIdKey)
        userDefaults.set(currentTime, forKey: sessionStartTimeKey)
        userDefaults.synchronize()
        
        return newId
    }
    
    func resetSession() {
        _ = createNewSession()
    }
}
```

#### Kotlin (Android)
```kotlin
import android.content.Context
import android.content.SharedPreferences
import java.util.*

class SessionManager private constructor(context: Context) {
    private val sharedPreferences: SharedPreferences
    private val sessionIdKey = "sessionId"
    private val sessionStartTimeKey = "sessionStartTime"
    
    private var _sessionId: String? = null
    private var _sessionStartTime: Long = 0
    
    init {
        sharedPreferences = context.getSharedPreferences("SessionPrefs", Context.MODE_PRIVATE)
        loadOrCreateSession()
    }
    
    val sessionId: String
        get() = _sessionId ?: createNewSession()
    
    private fun loadOrCreateSession() {
        val savedSession = sharedPreferences.getString(sessionIdKey, null)
        val savedStartTime = sharedPreferences.getLong(sessionStartTimeKey, 0L)
        val currentTime = System.currentTimeMillis()
        
        // 저장된 세션이 없거나 4시간이 지난 경우 새로 생성
        if (savedSession == null || savedStartTime == 0L || (currentTime - savedStartTime > 4 * 60 * 60 * 1000)) {
            createNewSession()
        } else {
            _sessionId = savedSession
            _sessionStartTime = savedStartTime
        }
    }
    
    private fun createNewSession(): String {
        val newId = UUID.randomUUID().toString()
        val currentTime = System.currentTimeMillis()
        
        _sessionId = newId
        _sessionStartTime = currentTime
        
        sharedPreferences.edit().apply {
            putString(sessionIdKey, newId)
            putLong(sessionStartTimeKey, currentTime)
            apply()
        }
        
        return newId
    }
    
    fun resetSession() {
        createNewSession()
    }
    
    companion object {
        @Volatile
        private var instance: SessionManager? = null
        
        fun getInstance(context: Context): SessionManager {
            return instance ?: synchronized(this) {
                instance ?: SessionManager(context.applicationContext).also { instance = it }
            }
        }
    }
}
```

### 3.2 세션 ID를 API 요청에 포함

#### Swift (iOS)
```swift
import Foundation

class ApiClient {
    private let baseUrl: String
    private let sessionManager: SessionManager
    
    init(baseUrl: String, sessionManager: SessionManager = SessionManager.shared) {
        self.baseUrl = baseUrl
        self.sessionManager = sessionManager
    }
    
    func request<T: Decodable>(endpoint: String, method: String, body: Any? = nil, completion: @escaping (Result<T, Error>) -> Void) {
        guard let url = URL(string: "\(baseUrl)\(endpoint)") else {
            completion(.failure(NSError(domain: "ApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.addValue("Bearer \(getAuthToken())", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue(sessionManager.sessionId, forHTTPHeaderField: "X-Session-ID")
        
        if let body = body {
            let jsonData = try? JSONSerialization.data(withJSONObject: body)
            request.httpBody = jsonData
        }
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "ApiClient", code: -2, userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }
            
            do {
                let decodedResponse = try JSONDecoder().decode(T.self, from: data)
                completion(.success(decodedResponse))
            } catch {
                completion(.failure(error))
            }
        }
        
        task.resume()
    }
    
    private func getAuthToken() -> String {
        // JWT 토큰 반환 로직
        return "..."
    }
}
```

#### Kotlin (Android)
```kotlin
import okhttp3.*
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.IOException

class ApiClient(
    private val baseUrl: String,
    private val sessionManager: SessionManager
) {
    private val okHttpClient: OkHttpClient
    private val retrofit: Retrofit
    
    init {
        okHttpClient = OkHttpClient.Builder()
            .addInterceptor { chain ->
                val original = chain.request()
                
                // 요청에 헤더 추가
                val request = original.newBuilder()
                    .header("Authorization", "Bearer ${getAuthToken()}")
                    .header("Content-Type", "application/json")
                    .header("X-Session-ID", sessionManager.sessionId)
                    .method(original.method(), original.body())
                    .build()
                
                chain.proceed(request)
            }
            .build()
        
        retrofit = Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }
    
    fun <T> createService(serviceClass: Class<T>): T {
        return retrofit.create(serviceClass)
    }
    
    private fun getAuthToken(): String {
        // JWT 토큰 반환 로직
        return "..."
    }
}

// 사용 예시
interface ApiService {
    // API 메서드 정의
}

// 서비스 생성 및 사용
val apiService = apiClient.createService(ApiService::class.java)
```

### 3.3 세션 수명 주기 관리

- **세션 시작**: 앱 시작 또는 로그인 시 새 세션 ID 생성
- **세션 유지**: 다음 상황에서 동일한 세션 ID 유지
  - 앱 사용 중
  - 앱이 백그라운드로 전환된 후 30분 이내 복귀 시
  - 앱이 백그라운드로 전환된 후 30분~4시간 이내 복귀 시 간편인증(PIN/생체인증) 사용
- **세션 종료**: 다음 상황에서 세션 ID 재생성
  - 로그아웃 시
  - 앱이 백그라운드로 전환된 후 4시간 이상 경과 시
  - 앱이 강제 종료된 경우

## 4. 백엔드 통합

### 4.1 Audit 서비스에서 세션 ID 수신

```typescript
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly auditClient: AuditClient) {}
  
  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const user = request.user; // JWT에서 추출된 사용자 정보
    
    // 클라이언트에서 전송한 세션 ID 추출
    const sessionId = request.headers['x-session-id'];
    
    // 요청 처리 시작 시 감사 이벤트 생성
    if (user && user.id) {
      this.auditClient.logUserActivity(
        user.id,
        user.name || 'unknown',
        `${request.method}_${request.route.path}`,
        null,
        null,
        {
          path: request.path,
          method: request.method,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent']
        },
        sessionId // 클라이언트 세션 ID 전달
      );
    }
    
    return next.handle();
  }
}
```

### 4.2 AuditMetadata에 세션 ID 저장

`AuditMetadata` 엔티티의 `sessionId` 필드는 클라이언트에서 생성한 세션 ID를 저장하는 데 사용됩니다.

```typescript
interface AuditMetadata {
  correlationId?: string;
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string; // 클라이언트에서 생성한 세션 ID
}
```

### 4.3 감사 로그 조회 시 세션 ID 활용

세션 ID를 활용하여 특정 세션의 모든 활동을 조회할 수 있습니다.

```typescript
@Controller('v1/audit-logs')
export class AuditLogsController {
  constructor(private readonly auditService: AuditService) {}
  
  @Get('by-session')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(['AUDIT_VIEWER'])
  async getLogsBySession(
    @Query('sessionId') sessionId: string,
    @Query('page') page: number = 1,
    @Query('size') size: number = 20
  ): Promise<PaginatedResponse<AuditLogDto>> {
    return this.auditService.findBySessionId(sessionId, { page, size });
  }
}
```

## 5. 보안 고려사항

### 5.1 세션 ID 관련 보안

- 세션 ID는 인증에 사용되지 않으며 감사 목적으로만 사용
- UUID v4와 같은 예측 불가능한 형식 사용
- 클라이언트 스토리지에 안전하게 저장 (Android Keystore, iOS Keychain)
- 전송 시 TLS/SSL을 통한 암호화

### 5.2 데이터 보호

- 세션 ID와 연결된 개인 데이터는 필요한 기간만 보존
- GDPR, HIPAA 등 관련 규제 준수
- 민감한 개인 정보를 로그와 연결하지 않음

## 6. 모범 사례

1. **구현 일관성**: 모든 클라이언트 애플리케이션에서 동일한 세션 ID 생성 및 관리 방식 사용
2. **명확한 세션 경계**: 세션 시작 및 종료 조건 명확히 정의
3. **헤더 표준화**: `X-Session-ID`와 같은 일관된 헤더 이름 사용
4. **로깅 감독**: 불필요한 데이터가 세션 로그에 포함되지 않도록 주의
5. **성능 고려**: 세션 ID 기반 쿼리 최적화 (인덱싱 등)

## 7. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-31 | bok@weltcorp.com | 최초 작성 - 클라이언트 세션 ID 통합 가이드 |
| 0.2.0 | 2025-04-01 | bok@weltcorp.com | Swift와 Kotlin 코드 예시 추가 | 