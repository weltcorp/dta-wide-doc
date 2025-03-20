# 접근 코드 알림 전송 기술 명세

## 1. 알림 구조

### 1.1 알림 타입
```typescript
enum NotificationType {
  CODE_GENERATED = 'CODE_GENERATED',
  CODE_EXPIRED = 'CODE_EXPIRED',
  CODE_USED = 'CODE_USED',
  CODE_REVOKED = 'CODE_REVOKED',
  POLICY_UPDATED = 'POLICY_UPDATED'
}

interface NotificationTemplate {
  type: NotificationType;
  title: string;
  content: string;
  variables: string[];
}

const templates: Record<NotificationType, NotificationTemplate> = {
  [NotificationType.CODE_GENERATED]: {
    type: NotificationType.CODE_GENERATED,
    title: '접근 코드가 생성되었습니다',
    content: '접근 코드: {code}\n유효기간: {expiresAt}\n최대 사용 횟수: {maxUsageCount}',
    variables: ['code', 'expiresAt', 'maxUsageCount']
  },
  // ... 다른 템플릿들
};
```

### 1.2 알림 채널
```typescript
enum NotificationChannel {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  PUSH = 'PUSH',
  WEBHOOK = 'WEBHOOK'
}

interface NotificationConfig {
  channels: NotificationChannel[];
  templates: Record<NotificationChannel, string>;
  retryCount: number;
  retryDelay: number;
}

const defaultConfig: NotificationConfig = {
  channels: [NotificationChannel.EMAIL, NotificationChannel.SMS],
  templates: {
    [NotificationChannel.EMAIL]: 'email-template',
    [NotificationChannel.SMS]: 'sms-template'
  },
  retryCount: 3,
  retryDelay: 5000 // 5초
};
```

## 2. 알림 전송

### 2.1 알림 서비스
```typescript
@Injectable()
class NotificationService {
  constructor(
    private readonly emailService: EmailService,
    private readonly smsService: SmsService,
    private readonly pushService: PushService,
    private readonly webhookService: WebhookService,
    private readonly logger: Logger
  ) {}
  
  async sendNotification(
    type: NotificationType,
    recipient: User,
    data: Record<string, any>
  ): Promise<void> {
    const template = templates[type];
    const config = await this.getNotificationConfig(recipient);
    
    await Promise.all(
      config.channels.map(channel =>
        this.sendToChannel(channel, template, recipient, data)
      )
    );
  }
  
  private async sendToChannel(
    channel: NotificationChannel,
    template: NotificationTemplate,
    recipient: User,
    data: Record<string, any>
  ): Promise<void> {
    const content = this.renderTemplate(template, data);
    const service = this.getServiceForChannel(channel);
    
    await this.retryWithBackoff(
      () => service.send(recipient, content),
      defaultConfig.retryCount,
      defaultConfig.retryDelay
    );
  }
}
```

### 2.2 채널별 구현
```typescript
@Injectable()
class EmailNotificationService implements NotificationChannel {
  constructor(
    private readonly mailer: MailerService,
    private readonly templateEngine: TemplateEngine
  ) {}
  
  async send(recipient: User, content: string): Promise<void> {
    const email = {
      to: recipient.email,
      subject: content.title,
      html: await this.templateEngine.render('email/code', {
        content: content.body,
        recipient
      })
    };
    
    await this.mailer.sendMail(email);
  }
}

@Injectable()
class SmsNotificationService implements NotificationChannel {
  constructor(
    private readonly smsGateway: SmsGateway,
    private readonly phoneValidator: PhoneValidator
  ) {}
  
  async send(recipient: User, content: string): Promise<void> {
    if (!this.phoneValidator.isValid(recipient.phone)) {
      throw new InvalidPhoneNumberException(recipient.phone);
    }
    
    await this.smsGateway.sendSms({
      to: recipient.phone,
      message: content.body
    });
  }
}
```

## 3. 템플릿 관리

### 3.1 템플릿 엔진
```typescript
class TemplateEngine {
  private readonly handlebars = require('handlebars');
  
  constructor() {
    this.registerHelpers();
  }
  
  private registerHelpers(): void {
    this.handlebars.registerHelper('formatDate', (date: Date) => {
      return new Intl.DateTimeFormat('ko-KR', {
        dateStyle: 'medium',
        timeStyle: 'short'
      }).format(date);
    });
    
    this.handlebars.registerHelper('maskCode', (code: string) => {
      return code.substring(0, 3) + '***' + code.slice(-3);
    });
  }
  
  async render(templateName: string, data: any): Promise<string> {
    const template = await this.loadTemplate(templateName);
    return this.handlebars.compile(template)(data);
  }
}
```

### 3.2 다국어 지원
```typescript
class I18nTemplateManager {
  private readonly templates: Map<string, Map<string, string>> = new Map();
  
  constructor(
    private readonly i18n: I18nService,
    private readonly templateEngine: TemplateEngine
  ) {}
  
  async getTemplate(
    type: NotificationType,
    locale: string
  ): Promise<NotificationTemplate> {
    const template = templates[type];
    const localizedContent = await this.i18n.translate(
      `notifications.${type}`,
      locale
    );
    
    return {
      ...template,
      title: localizedContent.title,
      content: localizedContent.content
    };
  }
}
```

## 4. 재시도 전략

### 4.1 재시도 관리자
```typescript
class RetryManager {
  async retryWithBackoff<T>(
    operation: () => Promise<T>,
    maxRetries: number,
    initialDelay: number,
    backoffFactor: number = 2
  ): Promise<T> {
    let lastError: Error;
    let delay = initialDelay;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        this.logger.warn(
          `Attempt ${attempt} failed: ${error.message}. Retrying in ${delay}ms`
        );
        
        await this.sleep(delay);
        delay *= backoffFactor;
      }
    }
    
    throw new MaxRetriesExceededException(lastError);
  }
}
```

### 4.2 실패 처리
```typescript
class FailedNotificationHandler {
  @OnEvent('notification.failed')
  async handleFailedNotification(event: NotificationFailedEvent): Promise<void> {
    await this.notificationRepository.markAsFailed(event.notificationId, {
      error: event.error,
      attemptCount: event.attemptCount
    });
    
    if (this.shouldAlertOperators(event)) {
      await this.alertOperators(event);
    }
  }
  
  private shouldAlertOperators(event: NotificationFailedEvent): boolean {
    return (
      event.attemptCount >= defaultConfig.retryCount ||
      this.isHighPriorityNotification(event.type)
    );
  }
}
```

## 5. 모니터링

### 5.1 메트릭 수집
```typescript
class NotificationMetrics {
  private readonly metrics = {
    attempts: new Counter('notification_attempts_total'),
    success: new Counter('notification_success_total'),
    failure: new Counter('notification_failure_total'),
    latency: new Histogram('notification_duration_seconds')
  };
  
  recordAttempt(
    type: NotificationType,
    channel: NotificationChannel,
    success: boolean,
    duration: number
  ): void {
    const labels = { type, channel };
    
    this.metrics.attempts.inc(labels);
    if (success) {
      this.metrics.success.inc(labels);
    } else {
      this.metrics.failure.inc(labels);
    }
    
    this.metrics.latency.observe(labels, duration);
  }
}
```

### 5.2 알림 상태 모니터링
```typescript
class NotificationHealthCheck {
  @Cron('*/5 * * * *') // 5분마다
  async checkNotificationHealth(): Promise<void> {
    const metrics = await this.collectMetrics();
    
    if (metrics.failureRate > 0.1) {
      this.logger.warn('High notification failure rate', metrics);
    }
    
    if (metrics.averageLatency > 5000) {
      this.logger.warn('High notification latency', metrics);
    }
  }
}
```

## 6. 변경 이력
| 버전 | 날짜 | 작성자 | 변경 내용 |
|-----|------|--------|-----------|
| 0.1.0 | 2025-03-16 | bok@weltcorp.com | 최초 작성 |