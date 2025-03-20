# ADR 3: TypeScript 사용

## 상태
승인됨 (2024-03-15)

## 컨텍스트
- 타입 안정성이 필요함
- 코드 품질과 유지보수성 향상이 필요함
- 개발자 생산성 향상이 필요함
- IDE 지원과 도구 통합이 중요함

## 결정
TypeScript를 주요 개발 언어로 채택

### 설정
```json
{
  "compilerOptions": {
    "strict": true,
    "target": "ES2022",
    "module": "CommonJS",
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true
  }
}
```

### 코딩 표준
- ESLint + Prettier 사용
- 엄격한 타입 검사 적용
- 명시적 타입 선언 권장
- 인터페이스 기반 설계
- 함수형 프로그래밍 지향

## 결과
### 긍정적
- 타입 안정성 향상
- 리팩토링 용이성
- 자동완성 지원
- 문서화 효과
- 버그 조기 발견

### 부정적
- 초기 설정 복잡도
- 빌드 시간 증가
- 학습 곡선
- 보일러플레이트 코드

## 대안
1. JavaScript + JSDoc
2. JavaScript + Flow
3. Kotlin
4. Go

## 관련 결정
- ADR 1: NX 모노레포 도입
- ADR 5: NestJS 프레임워크 사용 