# Device ID 기술 명세

## 1. 개요
Device ID는 클라이언트 장치를 고유하게 식별하고 인증하기 위한 보안 메커니즘입니다. 이 문서는 Device ID의 생성, 암호화, 검증 프로세스에 대한 기술적 명세를 제공합니다.

## 2. Device ID 형식

### 2.1 기본 구조
```typescript
interface DeviceIdentifier {
  uuid: string;          // 장치 고유 식별자
  platform: string;      // 플랫폼 정보 (ios, android, web)
  version: string;       // 클라이언트 앱 버전
  timestamp: number;     // 생성 시간 (Unix timestamp)
  signature: string;     // HMAC 서명
}
```

### 2.2 직렬화 형식
Device ID는 JSON 형식으로 직렬화된 후 Base64URL로 인코딩됩니다:
```typescript
deviceId = base64UrlEncode(JSON.stringify(deviceIdentifier))
```

## 3. 암호화/복호화 프로세스

### 3.1 암호화 스펙
- 알고리즘: ChaCha20-Poly1305
  - 키 길이: 256비트 (32바이트)
  - Nonce: 96비트 (12바이트)
  - 인증 태그: 128비트 (16바이트)
- HMAC: SHA-256
  - 키 길이: 256비트 (32바이트)
  - 출력: 256비트 (32바이트)

### 3.2 암호화 과정 (클라이언트)
1. Device ID 객체 생성
   ```typescript
   const deviceId = {
     uuid: generateUUID(),          // RFC 4122 v4 UUID
     platform: getPlatformInfo(),   // 'ios', 'android', 'web'
     version: getAppVersion(),      // 'x.y.z' 형식
     timestamp: Date.now() / 1000,  // Unix timestamp (초)
   };
   ```

2. HMAC 서명 생성 및 추가
   ```typescript
   // 서명 생성 (Base64 인코딩)
   const signature = base64Encode(
     hmacSHA256(
       JSON.stringify(deviceId),
       HMAC_KEY
     )
   );
   
   // 서명 추가
   const deviceIdWithSignature = {
     ...deviceId,
     signature
   };
   ```

3. JSON 직렬화
   ```typescript
   const jsonData = JSON.stringify(deviceIdWithSignature);
   ```

4. ChaCha20-Poly1305 암호화
   ```typescript
   // 12바이트 nonce 생성
   const nonce = generateSecureRandomBytes(12);
   
   // 암호화 (암호문 + 인증 태그)
   const encrypted = chacha20poly1305Encrypt(
     jsonData,
     ENCRYPTION_KEY,
     nonce
   );
   
   // nonce + 암호화된 데이터 결합
   const finalData = concat(nonce, encrypted);
   ```

5. Base64URL 인코딩
   ```typescript
   const encodedDeviceId = base64UrlEncode(finalData);
   ```

### 3.3 복호화 과정 (서버)
1. Base64URL 디코딩
   ```typescript
   const encryptedData = base64UrlDecode(encodedDeviceId);
   ```

2. Nonce 추출 및 ChaCha20-Poly1305 복호화
   ```typescript
   // Nonce 추출 (처음 12바이트)
   const nonce = encryptedData.slice(0, 12);
   const ciphertext = encryptedData.slice(12);
   
   // 복호화 및 인증 검증
   const jsonData = chacha20poly1305Decrypt(
     ciphertext,
     ENCRYPTION_KEY,
     nonce
   );
   ```

3. JSON 파싱
   ```typescript
   const deviceId = JSON.parse(jsonData);
   ```

4. HMAC 서명 검증
   ```typescript
   const { signature, ...dataWithoutSignature } = deviceId;
   
   const expectedSignature = base64Encode(
     hmacSHA256(
       JSON.stringify(dataWithoutSignature),
       HMAC_KEY
     )
   );
   
   if (signature !== expectedSignature) {
     throw new Error('Invalid signature');
   }
   ```

### 3.4 데이터 형식
1. 암호화된 데이터 구조
   ```
   [12바이트 Nonce][N바이트 암호화된 데이터][16바이트 인증 태그]
   ```

2. Base64URL 인코딩 규칙
   - '+' → '-'
   - '/' → '_'
   - 패딩('=') 제거

### 3.5 보안 고려사항
1. 키 관리
   - ENCRYPTION_KEY와 HMAC_KEY는 별도로 관리
   - HSM 또는 KMS 사용 권장
   - 키 순환 주기: 90일

2. Nonce 관리
   - 매 암호화마다 새로운 난수 생성
   - SecureRandom 또는 이에 준하는 CSPRNG 사용

3. 에러 처리
   - 복호화 실패 시 상세 오류 노출 금지
   - 모든 검증 단계에서 timing attack 방지

## 4. 검증 프로세스

### 4.1 서버 측 검증
1. ChaCha20 복호화
2. JSON 파싱
3. HMAC 서명 검증
4. 타임스탬프 검증 (만료 확인)
5. UUID 유효성 검증
6. 플랫폼 및 버전 검증

### 4.2 검증 규칙
- 타임스탬프 허용 범위: 현재 시간 기준 ±15분
- UUID 형식: RFC 4122 버전 4
- 지원 플랫폼: ios, android, web
- 최소 지원 버전: 설정된 최소 버전 이상

## 5. 앱 토큰 발급을 위한 디바이스 ID 암호화

### 5.1 ChaCha20 암호화 요구사항
앱 토큰 발급 시 디바이스 ID는 ChaCha20 알고리즘을 사용하여 암호화해야 합니다. 이는 로그인 전 API 호출에 필요한 앱 토큰을 발급받기 위한 필수 요구사항입니다.

#### 5.1.1 ChaCha20 알고리즘 개요
ChaCha20은 Daniel J. Bernstein이 설계한 스트림 암호로, 다음과 같은 특징을 가집니다:
- 높은 성능: 소프트웨어 구현에서 매우 빠른 속도
- 강력한 보안: 현재까지 알려진 공격에 대해 안전
- 간단한 구현: 복잡한 룩업 테이블이나 분기 없이 구현 가능
- 병렬 처리 가능: 여러 블록을 동시에 처리 가능

#### 5.1.2 암호화 구현
```typescript
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// 암호화 함수
function encryptDeviceId(deviceId: string, key: Buffer, nonce: Buffer): string {
  const cipher = createCipheriv('chacha20', key, nonce);
  const encrypted = Buffer.concat([cipher.update(deviceId, 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, encrypted]).toString('base64');
}

// 복호화 함수
function decryptDeviceId(encryptedData: string, key: Buffer): string {
  const data = Buffer.from(encryptedData, 'base64');
  const nonce = data.slice(0, 12);
  const encryptedDeviceId = data.slice(12);
  const decipher = createDecipheriv('chacha20', key, nonce);
  return Buffer.concat([decipher.update(encryptedDeviceId), decipher.final()]).toString('utf8');
}

// 사용 예시
const key = Buffer.from('0123456789abcdef0123456789abcdef', 'hex'); // 32바이트 키
const nonce = randomBytes(12); // 12바이트 논스
const deviceId = 'device_123';
const encrypted = encryptDeviceId(deviceId, key, nonce);
const decrypted = decryptDeviceId(encrypted, key);
```

#### 5.1.3 클라이언트 구현 가이드
클라이언트는 다음 단계를 따라 디바이스 ID를 암호화해야 합니다:
1. 서버로부터 공개 키를 받습니다.
2. 디바이스 ID를 ChaCha20 알고리즘으로 암호화합니다.
3. 암호화된 디바이스 ID를 앱 토큰 발급 요청에 포함합니다.

#### 5.1.4 서버 구현 가이드
서버는 다음 단계를 따라 디바이스 ID를 복호화합니다:
1. 암호화된 디바이스 ID를 앱 토큰 발급 요청에서 추출합니다.
2. 비밀 키를 사용하여 디바이스 ID를 복호화합니다.
3. 복호화된 디바이스 ID의 유효성을 검증합니다.
4. 유효한 경우 앱 토큰을 발급합니다.

#### 5.1.5 보안 고려사항
- 키는 안전하게 관리되어야 합니다.
- 논스는 매번 새로 생성해야 합니다.
- 복호화된 디바이스 ID는 로그에 기록하지 않아야 합니다.
- 키 로테이션 정책을 수립하고 주기적으로 키를 변경해야 합니다.

#### 5.1.6 오류 처리
디바이스 ID 복호화 실패 시 다음과 같은 오류 코드를 반환합니다:
- `INVALID_DEVICE_ID`: 유효하지 않은 디바이스 ID 형식
- `DEVICE_ID_DECRYPTION_FAILED`: 디바이스 ID 복호화 실패

## 6. 보안 고려사항

### 6.1 키 관리
- 암호화 키와 HMAC 비밀키는 별도로 관리
- 키 순환 주기: 90일
- HSM 또는 KMS 사용 권장

### 6.2 보안 제한사항
- 동일 Device ID 재사용 제한
- 특정 시간 내 최대 시도 횟수 제한
- IP 기반 접근 제한

## 7. 에러 처리

### 7.1 에러 코드
| 코드 | 메시지 | 설명 | 대응 방법 |
|-----|--------|------|-----------|
| 2009 | INVALID_DEVICE_ID | 유효하지 않은 deviceId | deviceId 재생성 |
| 2010 | DEVICE_ID_DECRYPTION_FAILED | 복호화 실패 | 암호화 설정 확인 |
| 2011 | DEVICE_ID_EXPIRED | 만료된 deviceId | 새로운 deviceId 생성 |
| 2012 | INVALID_SIGNATURE | 잘못된 서명 | HMAC 키 확인 |
| 2013 | UNSUPPORTED_PLATFORM | 지원하지 않는 플랫폼 | 플랫폼 확인 |
| 2014 | VERSION_NOT_SUPPORTED | 지원하지 않는 버전 | 클라이언트 업데이트 |

## 8. 구현 예시

### 8.1 iOS (Swift) 구현
```swift
import Foundation
import CryptoKit

class DeviceIdManager {
    private static let ENCRYPTION_KEY: SymmetricKey = // 256-bit key
    private static let HMAC_KEY: SymmetricKey = // 256-bit key
    
    struct DeviceIdentifier: Codable {
        let uuid: String
        let platform: String
        let version: String
        let timestamp: TimeInterval
        var signature: String?
    }
    
    static func generate() throws -> String {
        // 1. Device ID 생성
        let deviceId = DeviceIdentifier(
            uuid: UUID().uuidString,
            platform: "ios",
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "",
            timestamp: Date().timeIntervalSince1970
        )
        
        // 2. HMAC 서명 생성
        var deviceIdWithSignature = deviceId
        let signature = try generateSignature(for: deviceId)
        deviceIdWithSignature.signature = signature
        
        // 3. ChaCha20 암호화
        let encrypted = try encrypt(deviceIdWithSignature)
        
        // 4. Base64URL 인코딩
        return encrypted.base64URLEncodedString()
    }
    
    private static func generateSignature(for deviceId: DeviceIdentifier) throws -> String {
        let data = try JSONEncoder().encode(deviceId)
        let signature = HMAC<SHA256>.authenticationCode(
            for: data,
            using: HMAC_KEY
        )
        return Data(signature).base64EncodedString()
    }
    
    private static func encrypt(_ deviceId: DeviceIdentifier) throws -> Data {
        let jsonData = try JSONEncoder().encode(deviceId)
        
        let nonce = try ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(
            jsonData,
            using: ENCRYPTION_KEY,
            nonce: nonce
        )
        
        return sealedBox.combined
    }
}

// Base64URL 인코딩 확장
extension Data {
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
```

### 8.2 Android (Kotlin) 구현
```kotlin
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import android.util.Base64

class DeviceIdManager(private val context: Context) {
    companion object {
        private const val ENCRYPTION_KEY = // 256-bit key
        private const val HMAC_KEY = // 256-bit key
        private const val CHACHA20_NONCE_SIZE = 12
    }
    
    data class DeviceIdentifier(
        val uuid: String,
        val platform: String,
        val version: String,
        val timestamp: Long,
        var signature: String? = null
    )
    
    suspend fun generate(): String {
        // 1. Device ID 생성
        val deviceId = DeviceIdentifier(
            uuid = UUID.randomUUID().toString(),
            platform = "android",
            version = getAppVersion(),
            timestamp = System.currentTimeMillis() / 1000
        )
        
        // 2. HMAC 서명 생성
        val signature = generateSignature(deviceId)
        val deviceIdWithSignature = deviceId.copy(signature = signature)
        
        // 3. ChaCha20 암호화
        val encrypted = encrypt(deviceIdWithSignature)
        
        // 4. Base64URL 인코딩
        return Base64.encodeToString(encrypted, Base64.URL_SAFE or Base64.NO_PADDING)
    }
    
    private fun generateSignature(deviceId: DeviceIdentifier): String {
        val jsonString = JSONObject().apply {
            put("uuid", deviceId.uuid)
            put("platform", deviceId.platform)
            put("version", deviceId.version)
            put("timestamp", deviceId.timestamp)
        }.toString()
        
        val mac = Mac.getInstance("HmacSHA256")
        val secretKeySpec = SecretKeySpec(HMAC_KEY.toByteArray(), "HmacSHA256")
        mac.init(secretKeySpec)
        
        val hmac = mac.doFinal(jsonString.toByteArray())
        return Base64.encodeToString(hmac, Base64.NO_WRAP)
    }
    
    private fun encrypt(deviceId: DeviceIdentifier): ByteArray {
        val jsonString = JSONObject().apply {
            put("uuid", deviceId.uuid)
            put("platform", deviceId.platform)
            put("version", deviceId.version)
            put("timestamp", deviceId.timestamp)
            put("signature", deviceId.signature)
        }.toString()
        
        // ChaCha20 암호화 구현
        val nonce = ByteArray(CHACHA20_NONCE_SIZE).apply {
            SecureRandom().nextBytes(this)
        }
        
        val cipher = ChaCha20Cipher(ENCRYPTION_KEY)
        val encrypted = cipher.encrypt(jsonString.toByteArray(), nonce)
        
        // nonce와 암호화된 데이터 결합
        return nonce + encrypted
    }
    
    private fun getAppVersion(): String {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName
        } catch (e: PackageManager.NameNotFoundException) {
            "unknown"
        }
    }
}

// ChaCha20 암호화 구현 (실제로는 보안 라이브러리 사용 권장)
class ChaCha20Cipher(private val key: ByteArray) {
    fun encrypt(data: ByteArray, nonce: ByteArray): ByteArray {
        // ChaCha20 암호화 알고리즘 구현
        // 실제 구현에서는 BouncyCastle 또는 Tink 등의 검증된 라이브러리 사용 권장
        TODO("Implement ChaCha20 encryption")
    }
}
```

### 8.3 TypeScript 구현 (서버 측 복호화)
```typescript
import { createDecipheriv, createHmac } from 'crypto';

interface DeviceIdentifier {
  uuid: string;
  platform: string;
  version: string;
  timestamp: number;
  signature?: string;
}

class DeviceIdValidator {
  private static readonly ENCRYPTION_KEY = Buffer.from('your-256-bit-key', 'hex'); // 32바이트
  private static readonly HMAC_KEY = Buffer.from('your-hmac-key', 'hex');
  private static readonly NONCE_SIZE = 12; // 96비트
  
  /**
   * Device ID 검증
   * @param encryptedDeviceId Base64URL로 인코딩된 암호화된 Device ID
   * @returns 검증 결과
   */
  static async validate(encryptedDeviceId: string): Promise<boolean> {
    try {
      // 1. Base64URL 디코딩
      const encryptedData = Buffer.from(this.base64UrlDecode(encryptedDeviceId), 'base64');
      
      // 2. ChaCha20 복호화
      const deviceId = await this.decrypt(encryptedData);
      
      // 3. 검증
      return this.validateDeviceId(deviceId);
    } catch (error) {
      console.error('Device ID validation failed:', error);
      return false;
    }
  }
  
  /**
   * ChaCha20 복호화
   */
  private static async decrypt(encryptedData: Buffer): Promise<DeviceIdentifier> {
    // Nonce 추출 (처음 12바이트)
    const nonce = encryptedData.subarray(0, this.NONCE_SIZE);
    const ciphertext = encryptedData.subarray(this.NONCE_SIZE);
    
    // ChaCha20 복호화
    const decipher = createDecipheriv('chacha20', this.ENCRYPTION_KEY, nonce);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    
    // JSON 파싱
    return JSON.parse(decrypted.toString());
  }
  
  /**
   * Device ID 검증
   */
  private static validateDeviceId(deviceId: DeviceIdentifier): boolean {
    // 1. 서명 검증
    if (!this.validateSignature(deviceId)) {
      throw new Error('Invalid signature');
    }
    
    // 2. 타임스탬프 검증 (±15분)
    const timeDiff = Math.abs(Date.now() / 1000 - deviceId.timestamp);
    if (timeDiff > 15 * 60) {
      throw new Error('Device ID expired');
    }
    
    // 3. UUID 형식 검증
    if (!this.validateUUID(deviceId.uuid)) {
      throw new Error('Invalid UUID format');
    }
    
    // 4. 플랫폼 검증
    if (!['ios', 'android', 'web'].includes(deviceId.platform)) {
      throw new Error('Unsupported platform');
    }
    
    // 5. 버전 검증
    if (!this.validateVersion(deviceId.version)) {
      throw new Error('Unsupported version');
    }
    
    return true;
  }
  
  /**
   * HMAC 서명 검증
   */
  private static validateSignature(deviceId: DeviceIdentifier): boolean {
    const { signature, ...dataWithoutSignature } = deviceId;
    
    const expectedSignature = createHmac('sha256', this.HMAC_KEY)
      .update(JSON.stringify(dataWithoutSignature))
      .digest('base64');
    
    return signature === expectedSignature;
  }
  
  /**
   * UUID 형식 검증 (RFC 4122 v4)
   */
  private static validateUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }
  
  /**
   * 버전 검증
   */
  private static validateVersion(version: string): boolean {
    // 예: 최소 버전 1.0.0 이상
    const minVersion = '1.0.0';
    return this.compareVersions(version, minVersion) >= 0;
  }
  
  /**
   * 버전 비교
   */
  private static compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < 3; i++) {
      if (parts1[i] > parts2[i]) return 1;
      if (parts1[i] < parts2[i]) return -1;
    }
    
    return 0;
  }
  
  /**
   * Base64URL 디코딩
   */
  private static base64UrlDecode(str: string): string {
    let base64 = str
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    
    // 패딩 추가
    while (base64.length % 4) {
      base64 += '=';
    }
    
    return base64;
  }
}

// 사용 예시
async function validateDeviceId(encryptedDeviceId: string) {
  try {
    const isValid = await DeviceIdValidator.validate(encryptedDeviceId);
    if (isValid) {
      console.log('Device ID is valid');
    } else {
      console.log('Device ID is invalid');
    }
  } catch (error) {
    console.error('Validation error:', error.message);
  }
}
```

## 9. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-17 | bok@weltcorp.com | 최초 작성 |
| 0.2.0 | 2025-03-25 | bok@weltcorp.com | 앱 토큰 발급을 위한 디바이스 ID 암호화 섹션 추가 |