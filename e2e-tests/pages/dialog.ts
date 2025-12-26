import { Page, Locator, expect } from '@playwright/test';

/**
 * Page object for the BrowserID dialog
 */
export class DialogPage {
  readonly page: Page;

  // Screens
  readonly loadingScreen: Locator;
  readonly emailScreen: Locator;
  readonly passwordScreen: Locator;
  readonly createScreen: Locator;
  readonly verifyScreen: Locator;
  readonly successScreen: Locator;
  readonly errorScreen: Locator;
  readonly pickEmailScreen: Locator;

  // Email screen elements
  readonly emailInput: Locator;
  readonly emailNextButton: Locator;
  readonly emailError: Locator;

  // Password screen elements (existing user)
  readonly passwordInput: Locator;
  readonly signInButton: Locator;
  readonly passwordError: Locator;
  readonly forgotPasswordLink: Locator;

  // Create account screen (new user)
  readonly createPasswordInput: Locator;
  readonly confirmPasswordInput: Locator;
  readonly createAccountButton: Locator;
  readonly createPasswordError: Locator;

  // Verification screen
  readonly verificationCodeInput: Locator;
  readonly verifyButton: Locator;
  readonly verifyError: Locator;

  // General elements
  readonly cancelButton: Locator;
  readonly backButton: Locator;
  readonly rpName: Locator;

  constructor(page: Page) {
    this.page = page;

    // Screens
    this.loadingScreen = page.locator('#loading.active');
    this.emailScreen = page.locator('#email-screen');
    this.passwordScreen = page.locator('#password-screen');
    this.createScreen = page.locator('#create-screen');
    this.verifyScreen = page.locator('#verify-screen');
    this.successScreen = page.locator('#success-screen');
    this.errorScreen = page.locator('#error-screen');
    this.pickEmailScreen = page.locator('#pick-email-screen');

    // Email screen
    this.emailInput = page.locator('#email');
    this.emailNextButton = page.locator('#email-form button[type="submit"]');
    this.emailError = page.locator('#email-error');

    // Password screen (existing user)
    this.passwordInput = page.locator('#password');
    this.signInButton = page.locator('#password-form button[type="submit"]');
    this.passwordError = page.locator('#password-error');
    this.forgotPasswordLink = page.locator('#forgot-password-link');

    // Create account screen
    this.createPasswordInput = page.locator('#create-password');
    this.confirmPasswordInput = page.locator('#confirm-password');
    this.createAccountButton = page.locator('#create-form button[type="submit"]');
    this.createPasswordError = page.locator('#create-password-error');

    // Verification screen
    this.verificationCodeInput = page.locator('#verification-code');
    this.verifyButton = page.locator('#verify-form button[type="submit"]');
    this.verifyError = page.locator('#verify-error');

    // General - use :visible to only match visible elements
    this.cancelButton = page.locator('button.cancel:visible');
    this.backButton = page.locator('button.back:visible');
    this.rpName = page.locator('.rp-name').first();
  }

  /**
   * Navigate to the dialog and wait for it to initialize
   * @param origin - The RP origin to pass to the dialog
   */
  async goto(origin: string = 'http://example.com') {
    await this.page.goto(`/dialog/dialog.html?origin=${encodeURIComponent(origin)}`);
    // Wait for dialog to initialize (email screen to become active)
    await this.page.waitForSelector('#email-screen.active', { timeout: 10000 });
  }

  /**
   * Wait for a specific screen to become active
   */
  async waitForScreen(screenId: 'email' | 'password' | 'create' | 'verify' | 'success' | 'error' | 'pick-email') {
    await this.page.waitForSelector(`#${screenId}-screen.active`, { timeout: 10000 });
  }

  /**
   * Enter email and click Next
   */
  async enterEmail(email: string) {
    await this.emailInput.fill(email);
    await this.emailNextButton.click();
  }

  /**
   * Sign in as existing user (from email screen)
   */
  async signInExistingUser(email: string, password: string) {
    // Enter email
    await this.enterEmail(email);

    // Wait for password screen
    await this.waitForScreen('password');

    // Enter password and sign in
    await this.passwordInput.fill(password);
    await this.signInButton.click();
  }

  /**
   * Sign up as new user (from email screen, without verification)
   */
  async signUpNewUser(email: string, password: string) {
    // Enter email
    await this.enterEmail(email);

    // Wait for create screen
    await this.waitForScreen('create');

    // Enter passwords
    await this.createPasswordInput.fill(password);
    await this.confirmPasswordInput.fill(password);
    await this.createAccountButton.click();
  }

  /**
   * Enter verification code
   */
  async enterVerificationCode(code: string) {
    await this.verificationCodeInput.fill(code);
    await this.verifyButton.click();
  }

  /**
   * Full new user registration with verification
   */
  async registerNewUser(email: string, password: string, verificationCode: string) {
    await this.signUpNewUser(email, password);
    await this.waitForScreen('verify');
    await this.enterVerificationCode(verificationCode);
  }

  /**
   * Wait for sign-in to complete (success screen)
   */
  async waitForSuccess() {
    await this.waitForScreen('success');
  }

  /**
   * Check if we're on the success screen
   */
  async isOnSuccessScreen(): Promise<boolean> {
    return this.successScreen.isVisible();
  }

  /**
   * Check if we're on the error screen
   */
  async isOnErrorScreen(): Promise<boolean> {
    return this.errorScreen.isVisible();
  }

  /**
   * Get the error message displayed on the password screen
   */
  async getPasswordError(): Promise<string> {
    return await this.passwordError.textContent() || '';
  }

  /**
   * Get the error message displayed on the verify screen
   */
  async getVerifyError(): Promise<string> {
    return await this.verifyError.textContent() || '';
  }

  /**
   * Click cancel button
   */
  async cancel() {
    await this.cancelButton.first().click();
  }
}
