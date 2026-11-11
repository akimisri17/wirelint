import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppConfig {
  constructor(private readonly configService: ConfigService) {}

  jwtSecret = this.configService.getOrThrow<string>('JWT_SECRET');
  internalKey = this.configService.getOrThrow<string>('INTERNAL_SERVICE_KEY');
  billingUrl = this.configService.get<string>('BILLING_API_URL');
  mailerUrl = this.configService.get<string>('MAILER_URL');
  logFormat = this.configService.get<string>('LOG_FORMAT', 'json');
  searchUrl = process.env.SEARCH_API_URL ?? 'http://localhost:4010';
  sentry = process.env.SENTRY_DSN;
  databaseUrl = process.env['DATABASE_URL'];
  port = process.env.PORT ?? 4001;
}
