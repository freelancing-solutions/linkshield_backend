# Implementation Plan

## 1. Project Setup and Core Infrastructure

- [ ] 1.1 Set up authentication module structure
  - Create `src/features/auth` directory with subdirectories: `components`, `hooks`, `api`, `types`, `utils`
  - Create `src/features/auth/pages` for page components
  - Set up barrel exports in index files
  - _Requirements: All authentication requirements_

- [ ] 1.2 Configure API client with interceptors
  - Create `src/lib/api-client.ts` with axios instance
  - Implement request interceptor to add Bearer token from auth store
  - Implement response interceptor for 401 handling and automatic logout
  - Add error response transformation utility
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12_

- [ ] 1.3 Set up Zustand auth store
  - Create `src/stores/auth-store.ts` with AuthStore interface
  - Implement state: user, token, isAuthenticated, isLoading
  - Implement actions: setUser, setToken, clearAuth, setLoading
  - Add persist middleware for token (memory only, not localStorage)
  - _Requirements: 1.12_

## 2. Type Definitions and Data Models

- [ ] 2.1 Create TypeScript interfaces for authentication
  - Create `src/features/auth/types/index.ts`
  - Define User, SubscriptionPlan, Session interfaces
  - Define LoginResponse, RegisterFormData, LoginFormData interfaces
  - Define ProfileUpdateData, PasswordChangeData interfaces
  - Define API error response types
  - _Requirements: All authentication requirements_

- [ ] 2.2 Create validation schemas with Zod
  - Create `src/features/auth/utils/validation.ts`
  - Define registerSchema with email, password, full_name, company, accept_terms, marketing_consent
  - Define loginSchema with email, password, remember_me
  - Define profileUpdateSchema with editable fields
  - Define passwordChangeSchema with current_password and new_password
  - Define passwordResetSchema with token and new_password
  - _Requirements: 1.1, 1.2, 1.7, 1.8, 1.11_

## 3. API Integration Layer

- [ ] 3.1 Implement authentication API methods
  - Create `src/features/auth/api/auth-api.ts`
  - Implement register(data: RegisterFormData): Promise<User>
  - Implement login(data: LoginFormData): Promise<LoginResponse>
  - Implement logout(): Promise<void>
  - Implement verifyEmail(token: string): Promise<User>
  - Implement resendVerification(email: string): Promise<void>
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 3.2 Implement profile and session API methods
  - Add to `src/features/auth/api/auth-api.ts`
  - Implement getProfile(): Promise<User>
  - Implement updateProfile(data: Partial<User>): Promise<User>
  - Implement changePassword(data: PasswordChangeData): Promise<void>
  - Implement forgotPassword(email: string): Promise<void>
  - Implement resetPassword(data: ResetPasswordData): Promise<void>
  - Implement getSessions(): Promise<Session[]>
  - Implement revokeSession(sessionId: string): Promise<void>
  - Implement terminateAllSessions(): Promise<void>
  - _Requirements: 1.6, 1.7, 1.8, 1.9, 1.10, 1.11_

## 4. React Query Hooks

- [ ] 4.1 Create authentication mutation hooks
  - Create `src/features/auth/hooks/use-auth-mutations.ts`
  - Implement useLogin hook with mutation, success/error handling, and auth store updates
  - Implement useRegister hook with mutation and success message
  - Implement useLogout hook with mutation and auth store clearing
  - Implement useVerifyEmail hook with automatic execution on mount
  - Implement useResendVerification hook with rate limit handling
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 4.2 Create profile and password mutation hooks
  - Create `src/features/auth/hooks/use-profile-mutations.ts`
  - Implement useUpdateProfile hook with optimistic updates
  - Implement useChangePassword hook with session invalidation warning
  - Implement useForgotPassword hook
  - Implement useResetPassword hook
  - _Requirements: 1.7, 1.8, 1.10, 1.11_

- [ ] 4.3 Create session management hooks
  - Create `src/features/auth/hooks/use-sessions.ts`
  - Implement useSessions query hook with auto-refresh
  - Implement useRevokeSession mutation hook
  - Implement useTerminateAllSessions mutation hook with confirmation
  - _Requirements: 1.9_

- [ ] 4.4 Create profile query hook
  - Create `src/features/auth/hooks/use-profile.ts`
  - Implement useProfile query hook with caching (5 min stale time)
  - Add enabled condition based on auth token presence
  - Implement automatic profile refresh after updates
  - _Requirements: 1.6, 1.7_

## 5. Shared Utility Components

- [ ] 5.1 Create PasswordStrengthIndicator component
  - Create `src/features/auth/components/PasswordStrengthIndicator.tsx`
  - Implement password strength calculation (0-100%)
  - Display visual indicator with color coding (red/orange/yellow/green)
  - Show criteria checklist: length, uppercase, lowercase, digit, special char
  - Write unit tests for strength calculation
  - _Requirements: 1.1, 1.8, 1.11_

- [ ] 5.2 Create RequireAuth route wrapper component
  - Create `src/features/auth/components/RequireAuth.tsx`
  - Check authentication state from auth store
  - Redirect to /login with return URL if not authenticated
  - Show loading spinner while checking auth
  - Write tests for redirect behavior
  - _Requirements: 1.12_

- [ ] 5.3 Create AuthProvider context component
  - Create `src/features/auth/components/AuthProvider.tsx`
  - Provide auth context with user, token, isAuthenticated, isLoading
  - Provide login, logout, register, updateUser, clearAuth methods
  - Implement token validation on mount
  - Handle automatic logout on token expiration
  - _Requirements: 1.12_

## 6. Registration Feature

- [ ] 6.1 Create RegisterForm component
  - Create `src/features/auth/components/RegisterForm.tsx`
  - Implement form with react-hook-form and Zod validation
  - Add fields: email, password, confirmPassword, full_name, company (optional)
  - Add checkboxes: accept_terms (required), marketing_consent (optional)
  - Integrate PasswordStrengthIndicator for password field
  - Add password visibility toggle
  - Display validation errors inline
  - _Requirements: 1.1_

- [ ] 6.2 Create RegisterPage component
  - Create `src/features/auth/pages/RegisterPage.tsx`
  - Render RegisterForm component
  - Use useRegister hook for form submission
  - Display loading state during registration
  - Show success message and redirect to login on success
  - Handle and display API errors (409 for duplicate email, 400 for validation)
  - Add link to login page
  - _Requirements: 1.1_

## 7. Login Feature

- [ ] 7.1 Create LoginForm component
  - Create `src/features/auth/components/LoginForm.tsx`
  - Implement form with react-hook-form and Zod validation
  - Add fields: email, password
  - Add remember_me checkbox
  - Add password visibility toggle
  - Display validation errors inline
  - Add "Forgot Password?" link
  - _Requirements: 1.2_

- [ ] 7.2 Create LoginPage component
  - Create `src/features/auth/pages/LoginPage.tsx`
  - Render LoginForm component
  - Use useLogin hook for form submission
  - Collect device info (browser, OS) and include in login request
  - Display loading state during login
  - Redirect to dashboard or return URL on success
  - Handle and display API errors (401, 423, 403 with EMAIL_NOT_VERIFIED)
  - Show resend verification option for unverified accounts
  - Add link to registration page
  - _Requirements: 1.2_

## 8. Email Verification Feature

- [ ] 8.1 Create VerifyEmailPage component
  - Create `src/features/auth/pages/VerifyEmailPage.tsx`
  - Extract token from URL params using useParams or useSearchParams
  - Use useVerifyEmail hook to automatically verify on mount
  - Display loading state: "Verifying your email..."
  - Display success state: "Email verified successfully! Redirecting to login..."
  - Implement 3-second countdown and redirect to login on success
  - Display error state with resend verification option
  - Handle 400 error for invalid/expired token
  - _Requirements: 1.3_

- [ ] 8.2 Create ResendVerification component
  - Create `src/features/auth/components/ResendVerification.tsx`
  - Implement form with email input
  - Use useResendVerification hook
  - Display success message: "Verification email sent. Please check your inbox"
  - Handle rate limiting (429) with appropriate message
  - Show as modal or inline component
  - _Requirements: 1.4_

## 9. Password Reset Feature

- [ ] 9.1 Create ForgotPasswordPage component
  - Create `src/features/auth/pages/ForgotPasswordPage.tsx`
  - Implement form with email input
  - Use useForgotPassword hook
  - Display success message (always shown for security)
  - Handle rate limiting (429)
  - Add link back to login
  - _Requirements: 1.10_

- [ ] 9.2 Create ResetPasswordPage component
  - Create `src/features/auth/pages/ResetPasswordPage.tsx`
  - Extract token from URL params
  - Implement form with new_password and confirm_password fields
  - Integrate PasswordStrengthIndicator
  - Use useResetPassword hook
  - Display success message with 3-second countdown
  - Redirect to login on success
  - Handle 400 error for invalid/expired token
  - Provide option to request new reset link
  - _Requirements: 1.11_

## 10. Profile Management Feature

- [ ] 10.1 Create ProfilePage component
  - Create `src/features/auth/pages/ProfilePage.tsx`
  - Use useProfile hook to fetch profile data
  - Display loading skeleton while fetching
  - Show account information section (read-only): email, role, created_at, is_verified
  - Show verification badge if email verified
  - Show subscription information: plan name, price, status
  - Add upgrade CTA if on free plan
  - _Requirements: 1.6_

- [ ] 10.2 Create ProfileEditForm component
  - Create `src/features/auth/components/ProfileEditForm.tsx`
  - Implement form with editable fields: full_name, company, profile_picture_url, timezone, language, marketing_consent
  - Use useUpdateProfile hook
  - Implement edit/save mode toggle
  - Display validation errors inline
  - Show success toast on save
  - Implement optimistic UI updates
  - _Requirements: 1.7_

- [ ] 10.3 Create ChangePasswordModal component
  - Create `src/features/auth/components/ChangePasswordModal.tsx`
  - Implement form with current_password, new_password, confirm_password
  - Integrate PasswordStrengthIndicator for new password
  - Use useChangePassword hook
  - Display warning: "All sessions will be invalidated"
  - Show success message and redirect to login after 3 seconds
  - Handle errors: incorrect current password, weak new password, same password
  - _Requirements: 1.8_

## 11. Session Management Feature

- [ ] 11.1 Create SessionsTable component
  - Create `src/features/auth/components/SessionsTable.tsx`
  - Display table columns: Device Info, IP Address, Last Activity, Created At, Status, Actions
  - Mark current session with badge
  - Disable revoke button for current session
  - Implement sort functionality
  - Show loading skeleton while fetching
  - Display empty state if no sessions
  - _Requirements: 1.9_

- [ ] 11.2 Create SessionsPage component
  - Create `src/features/auth/pages/SessionsPage.tsx`
  - Use useSessions hook to fetch sessions
  - Render SessionsTable component
  - Add "Terminate All Sessions" button
  - Implement confirmation modal for terminate all
  - Use useRevokeSession hook for individual revocation
  - Use useTerminateAllSessions hook for bulk termination
  - Show success toast after operations
  - Handle 404 error for session not found
  - _Requirements: 1.9_

## 12. Routing and Navigation

- [ ] 12.1 Set up authentication routes
  - Configure routes in main router: /login, /register, /verify-email, /forgot-password, /reset-password
  - Configure protected routes: /profile, /sessions
  - Wrap protected routes with RequireAuth component
  - Implement redirect logic with return URL preservation
  - _Requirements: 1.12_

- [ ] 12.2 Implement navigation guards
  - Add route guard to redirect authenticated users away from login/register
  - Implement automatic redirect to login for 401 responses
  - Preserve intended destination URL for post-login redirect
  - _Requirements: 1.12_

## 13. Error Handling and User Feedback

- [ ] 13.1 Create error message mapping utility
  - Create `src/features/auth/utils/error-messages.ts`
  - Map backend error codes to user-friendly messages
  - Include all error codes from requirements
  - Export getErrorMessage(code: string): string function
  - _Requirements: All authentication requirements_

- [ ] 13.2 Implement toast notification system
  - Set up toast library (react-hot-toast or similar)
  - Create toast wrapper utilities for success, error, info
  - Implement auto-dismiss for success messages (5 seconds)
  - Keep error messages until user dismisses
  - _Requirements: All authentication requirements_

- [ ] 13.3 Implement loading states
  - Add loading spinners to all form submit buttons
  - Add skeleton loaders for data fetching (profile, sessions)
  - Implement page-level loading indicators
  - Disable form inputs during submission
  - _Requirements: All authentication requirements_

## 14. Testing

- [ ] 14.1 Write unit tests for validation schemas
  - Test registerSchema with valid and invalid data
  - Test loginSchema validation
  - Test password strength calculation
  - Test error message mapping
  - _Requirements: 1.1, 1.2, 1.7, 1.8, 1.11_

- [ ] 14.2 Write unit tests for components
  - Test RegisterForm validation and submission
  - Test LoginForm validation and submission
  - Test PasswordStrengthIndicator display logic
  - Test RequireAuth redirect behavior
  - _Requirements: 1.1, 1.2, 1.12_

- [ ] 14.3 Write integration tests for authentication flows
  - Test complete registration flow
  - Test login flow with remember me
  - Test email verification flow
  - Test password reset flow
  - Test profile update flow
  - Test session management operations
  - _Requirements: All authentication requirements_

- [ ] 14.4 Write E2E tests for critical paths
  - Test user registration and email verification
  - Test login and logout
  - Test password change with session invalidation
  - Test session revocation
  - _Requirements: 1.1, 1.2, 1.5, 1.8, 1.9_

## 15. Accessibility and Polish

- [ ] 15.1 Implement keyboard navigation
  - Ensure all forms are fully keyboard accessible
  - Implement logical tab order
  - Add visible focus indicators
  - Test with keyboard only
  - _Requirements: All authentication requirements_

- [ ] 15.2 Add ARIA labels and screen reader support
  - Add aria-labels to all form inputs
  - Implement aria-live regions for error messages
  - Add aria-describedby for validation errors
  - Test with screen reader (NVDA/JAWS)
  - _Requirements: All authentication requirements_

- [ ] 15.3 Implement responsive design
  - Test all pages on mobile, tablet, desktop
  - Ensure forms are usable on small screens
  - Implement mobile-friendly navigation
  - Test touch interactions
  - _Requirements: All authentication requirements_

- [ ] 15.4 Add loading and empty states
  - Design and implement loading skeletons
  - Create empty state illustrations/messages
  - Add error state illustrations
  - Implement retry buttons for failed requests
  - _Requirements: All authentication requirements_

## 16. Documentation

- [ ] 16.1 Document component APIs
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - Document hooks and their return values
  - _Requirements: All authentication requirements_

- [ ] 16.2 Create developer documentation
  - Document authentication flow
  - Document state management approach
  - Document API integration patterns
  - Create troubleshooting guide
  - _Requirements: All authentication requirements_

- [ ] 16.3 Create user-facing help content
  - Write help text for password requirements
  - Create FAQ for common auth issues
  - Document session management features
  - Create email templates documentation
  - _Requirements: All authentication requirements_