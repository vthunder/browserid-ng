import { test as base, expect } from '@playwright/test';
import { DialogPage } from '../pages/dialog';

// Extend base test with our fixtures
export const test = base.extend<{
  dialogPage: DialogPage;
  brokerApi: BrokerApi;
}>({
  dialogPage: async ({ page }, use) => {
    const dialogPage = new DialogPage(page);
    await use(dialogPage);
  },

  brokerApi: async ({ request }, use) => {
    const api = new BrokerApi(request);
    await use(api);
  },
});

export { expect };

/**
 * API client for interacting with broker directly
 */
class BrokerApi {
  private request: any;
  private baseUrl: string;
  private verificationCodes: Map<string, string> = new Map();

  constructor(request: any) {
    this.request = request;
    this.baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
  }

  /**
   * Stage a new user and capture the verification code
   * Note: In real tests, you'd need a way to capture the email/code
   * For now, we'll use the API directly
   */
  async stageUser(email: string, password: string): Promise<{ success: boolean }> {
    const response = await this.request.post(`${this.baseUrl}/wsapi/stage_user`, {
      data: { email, pass: password },
    });
    return response.json();
  }

  /**
   * Complete user creation with verification code
   */
  async completeUserCreation(token: string): Promise<{ success: boolean }> {
    const response = await this.request.post(`${this.baseUrl}/wsapi/complete_user_creation`, {
      data: { token },
    });
    return response.json();
  }

  /**
   * Authenticate a user
   */
  async authenticate(email: string, password: string): Promise<{ success: boolean }> {
    const response = await this.request.post(`${this.baseUrl}/wsapi/authenticate_user`, {
      data: { email, pass: password },
    });
    return response.json();
  }

  /**
   * Get session context
   */
  async getSessionContext(): Promise<{ authenticated: boolean; csrf_token?: string }> {
    const response = await this.request.get(`${this.baseUrl}/wsapi/session_context`);
    return response.json();
  }

  /**
   * Check address info
   */
  async getAddressInfo(email: string): Promise<{ state: string; type: string }> {
    const response = await this.request.get(
      `${this.baseUrl}/wsapi/address_info?email=${encodeURIComponent(email)}`
    );
    return response.json();
  }

  /**
   * Get user creation status
   */
  async getUserCreationStatus(email: string): Promise<{ status: string }> {
    const response = await this.request.get(
      `${this.baseUrl}/wsapi/user_creation_status?email=${encodeURIComponent(email)}`
    );
    return response.json();
  }

  /**
   * Get pending verification code (for E2E testing)
   */
  async getPendingVerification(
    email: string,
    type: 'new_account' | 'add_email' | 'password_reset' = 'new_account'
  ): Promise<{ success: boolean; code?: string }> {
    const response = await this.request.get(
      `${this.baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=${type}`
    );
    return response.json();
  }

  /**
   * Create a verified user (for testing sign-in flows)
   */
  async createVerifiedUser(email: string, password: string): Promise<boolean> {
    // Stage the user
    const stageResult = await this.stageUser(email, password);
    if (!stageResult.success) {
      return false;
    }

    // Get the verification code
    const pendingResult = await this.getPendingVerification(email, 'new_account');
    if (!pendingResult.success || !pendingResult.code) {
      return false;
    }

    // Complete registration
    const completeResult = await this.completeUserCreation(pendingResult.code);
    return completeResult.success;
  }

  /**
   * Logout
   */
  async logout(): Promise<void> {
    await this.request.post(`${this.baseUrl}/wsapi/logout`);
  }
}

/**
 * Generate a unique test email
 */
export function generateTestEmail(): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `test-${timestamp}-${random}@example.com`;
}

/**
 * Generate a valid test password
 */
export function generateTestPassword(): string {
  return 'TestPassword123!';
}
