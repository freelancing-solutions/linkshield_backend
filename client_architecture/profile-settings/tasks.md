# Implementation Plan

## 1. Project Setup

- [ ] 1.1 Create profile settings module structure
  - Create `src/features/profile-settings` directory
  - Create subdirectories: `components`, `hooks`, `api`, `types`, `utils`, `pages`
  - Create `src/features/profile-settings/index.ts` for barrel exports
  - _Requirements: All profile settings requirements_

- [ ] 1.2 Create TypeScript interfaces
  - Create `src/features/profile-settings/types/index.ts`
  - Define UserProfile, ProfileUpdateRequest, PasswordChangeRequest interfaces
  - Define NotificationPreferences, ExportOptions interfaces
  - Define SubscriptionPlan interface
  - Export all types
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10_

## 2. API Integration

- [ ] 2.1 Create profile API client
  - Create `src/features/profile-settings/api/profile-api.ts`
  - Implement getProfile(): Promise<UserProfile>
  - Implement updateProfile(data: ProfileUpdateRequest): Promise<UserProfile>
  - Implement changePassword(data: PasswordChangeRequest): Promise<void>
  - Implement deleteAccount(): Promise<void>
  - Implement exportData(options: ExportOptions): Promise<Blob>
  - _Requirements: 1.1, 1.2, 1.5, 1.9, 1.10_

- [ ] 2.2 Create image upload service
  - Create `src/services/upload-service.ts`
  - Implement uploadImage(file: File): Promise<string>
  - Handle file validation (size, type, dimensions)
  - Return uploaded image URL
  - _Requirements: 1.3_

## 3. React Query Hooks

- [ ] 3.1 Create profile query hook
  - Create `src/features/profile-settings/hooks/use-profile.ts`
  - Implement useProfile() query hook with 5-minute stale time
  - Enable only when user is authenticated
  - _Requirements: 1.1_

- [ ] 3.2 Create profile mutation hooks
  - Create `src/features/profile-settings/hooks/use-profile-mutations.ts`
  - Implement useUpdateProfile() mutation hook with optimistic updates
  - Implement useChangePassword() mutation hook
  - Implement useDeleteAccount() mutation hook with confirmation
  - Implement useExportData() mutation hook
  - _Requirements: 1.2, 1.5, 1.9, 1.10_

- [ ] 3.3 Create avatar upload hook
  - Create `src/features/profile-settings/hooks/use-avatar-upload.ts`
  - Implement useUploadAvatar() mutation hook
  - Chain with useUpdateProfile to update profile_picture_url
  - Handle upload progress
  - _Requirements: 1.3_

## 4. Profile Settings Page Layout

- [ ] 4.1 Create ProfileSettingsPage component
  - Create `src/features/profile-settings/pages/ProfileSettingsPage.tsx`
  - Use useProfile hook to fetch profile data
  - Implement tab navigation (General, Preferences, Security, Data)
  - Handle loading state with skeleton loaders
  - Handle error state with retry button
  - _Requirements: All profile settings requirements_

- [ ] 4.2 Create ProfileHeader component
  - Create `src/features/profile-settings/components/ProfileHeader.tsx`
  - Display user avatar with upload button
  - Show user name and email
  - Display account badges (Verified, Active, Role)
  - _Requirements: 1.1, 1.3, 1.6_

- [ ] 4.3 Create ProfileTabs component
  - Create `src/features/profile-settings/components/ProfileTabs.tsx`
  - Implement tab navigation
  - Render active tab content
  - Persist active tab in URL query param
  - _Requirements: All profile settings requirements_

## 5. General Tab

- [ ] 5.1 Create GeneralTab component
  - Create `src/features/profile-settings/components/GeneralTab.tsx`
  - Render ProfileInformationSection, AccountInformationSection, SubscriptionSection
  - _Requirements: 1.1, 1.2, 1.6, 1.7_

- [ ] 5.2 Create ProfileInformationSection component
  - Create `src/features/profile-settings/components/ProfileInformationSection.tsx`
  - Display full_name, company, profile_picture_url
  - Add "Edit" button to open EditProfileModal
  - Show read-only view by default
  - _Requirements: 1.1, 1.2_

- [ ] 5.3 Create AccountInformationSection component
  - Create `src/features/profile-settings/components/AccountInformationSection.tsx`
  - Display email (read-only) with verification badge
  - Display role badge
  - Display account status (Active/Inactive)
  - Display "Member since" date
  - _Requirements: 1.6_

- [ ] 5.4 Create SubscriptionSection component
  - Create `src/features/profile-settings/components/SubscriptionSection.tsx`
  - Display current plan name and price
  - Show renewal/cancellation date
  - Display usage summary
  - Add "Manage Subscription" button linking to subscriptions page
  - Add "Upgrade Plan" button for Free users
  - _Requirements: 1.7_

## 6. Edit Profile Feature

- [ ] 6.1 Create EditProfileModal component
  - Create `src/features/profile-settings/components/EditProfileModal.tsx`
  - Implement modal with form fields
  - Pre-fill form with current profile data
  - Use react-hook-form with Zod validation
  - Use useUpdateProfile hook
  - _Requirements: 1.2_

- [ ] 6.2 Implement profile form validation
  - Create validation schema with Zod
  - Validate full_name: required, 1-100 characters
  - Validate company: optional, max 100 characters
  - Validate profile_picture_url: optional, valid URL, max 500 characters
  - Display validation errors inline
  - _Requirements: 1.2_

- [ ] 6.3 Implement optimistic updates
  - Update UI immediately on form submission
  - Rollback changes if API call fails
  - Show loading state during API call
  - Display success toast on completion
  - _Requirements: 1.2_

## 7. Avatar Upload Feature

- [ ] 7.1 Create AvatarUpload component
  - Create `src/features/profile-settings/components/AvatarUpload.tsx`
  - Display current avatar or default placeholder
  - Add upload button overlay on hover
  - Open AvatarUploadModal on click
  - _Requirements: 1.3_

- [ ] 7.2 Create AvatarUploadModal component
  - Create `src/features/profile-settings/components/AvatarUploadModal.tsx`
  - Display options: Upload Image, Enter URL, Remove Picture
  - Implement file picker for Upload Image
  - Implement URL input for Enter URL
  - Use useUploadAvatar hook
  - _Requirements: 1.3_

- [ ] 7.3 Implement image validation
  - Create `src/features/profile-settings/utils/image-validation.ts`
  - Validate file size (max 5MB)
  - Validate file type (jpg, png, gif)
  - Validate dimensions (max 2000x2000px)
  - Display validation errors
  - _Requirements: 1.3_

- [ ] 7.4 Implement image upload with progress
  - Show upload progress bar
  - Display preview before upload
  - Handle upload errors
  - Update profile with new image URL on success
  - _Requirements: 1.3_

## 8. Preferences Tab

- [ ] 8.1 Create PreferencesTab component
  - Create `src/features/profile-settings/components/PreferencesTab.tsx`
  - Render LocalizationSection and NotificationPreferencesSection
  - _Requirements: 1.4, 1.8_

- [ ] 8.2 Create LocalizationSection component
  - Create `src/features/profile-settings/components/LocalizationSection.tsx`
  - Add timezone dropdown with searchable list
  - Add language dropdown with supported languages
  - Use useUpdateProfile hook for changes
  - Display current timezone and language
  - _Requirements: 1.4_

- [ ] 8.3 Create NotificationPreferencesSection component
  - Create `src/features/profile-settings/components/NotificationPreferencesSection.tsx`
  - Display toggles for: Security Alerts, URL Check Results, Team Invitations, Product Updates, Marketing Emails
  - Use useUpdateProfile hook for changes
  - Show warning for disabling Security Alerts
  - Implement optimistic updates
  - _Requirements: 1.8_

- [ ] 8.4 Implement unsaved changes detection
  - Track form dirty state
  - Show "Save Changes" button when form is dirty
  - Display confirmation dialog on navigation with unsaved changes
  - _Requirements: 1.4_

## 9. Security Tab

- [ ] 9.1 Create SecurityTab component
  - Create `src/features/profile-settings/components/SecurityTab.tsx`
  - Render PasswordSection and SessionsSection
  - _Requirements: 1.5_

- [ ] 9.2 Create PasswordSection component
  - Create `src/features/profile-settings/components/PasswordSection.tsx`
  - Display last password change date
  - Add "Change Password" button
  - Open ChangePasswordModal on click
  - _Requirements: 1.5_

- [ ] 9.3 Create ChangePasswordModal component
  - Create `src/features/profile-settings/components/ChangePasswordModal.tsx`
  - Implement form with current_password, new_password, confirm_password fields
  - Add password visibility toggles
  - Integrate PasswordStrengthIndicator for new password
  - Use react-hook-form with Zod validation
  - Use useChangePassword hook
  - _Requirements: 1.5_

- [ ] 9.4 Implement password change flow
  - Validate current password is not empty
  - Validate new password meets requirements
  - Validate confirm password matches new password
  - Submit to API on validation success
  - Display success message: "Password changed. All sessions will be invalidated."
  - Redirect to login page after 3 seconds
  - Handle errors: incorrect password, weak password, same password
  - _Requirements: 1.5_

- [ ] 9.5 Create PasswordStrengthIndicator component
  - Create `src/features/profile-settings/components/PasswordStrengthIndicator.tsx`
  - Calculate password strength (0-100)
  - Display progress bar with color coding
  - Show strength label (Weak/Fair/Good/Strong)
  - Display requirements checklist with checkmarks
  - _Requirements: 1.5_

- [ ] 9.6 Create SessionsSection component
  - Create `src/features/profile-settings/components/SessionsSection.tsx`
  - Display active sessions count
  - Add "Manage Sessions" button linking to sessions page
  - Show last login information
  - _Requirements: 1.5_

## 10. Data Tab

- [ ] 10.1 Create DataTab component
  - Create `src/features/profile-settings/components/DataTab.tsx`
  - Render ExportDataSection and DeleteAccountSection
  - _Requirements: 1.9, 1.10_

- [ ] 10.2 Create ExportDataSection component
  - Create `src/features/profile-settings/components/ExportDataSection.tsx`
  - Display "Export Your Data" heading and description
  - Add "Export Data" button
  - Open ExportDataModal on click
  - _Requirements: 1.10_

- [ ] 10.3 Create ExportDataModal component
  - Create `src/features/profile-settings/components/ExportDataModal.tsx`
  - Display data type checkboxes: Profile, URL Checks, AI Analyses, Reports
  - Add format selector: JSON, CSV
  - Use useExportData hook
  - Show progress indicator during export
  - Trigger file download on completion
  - _Requirements: 1.10_

- [ ] 10.4 Implement data export
  - Validate at least one data type selected
  - Call export API with selected options
  - Generate filename: linkshield-data-{date}.{format}
  - Handle large exports with progress indicator
  - Display success message on download
  - Handle errors with retry option
  - _Requirements: 1.10_

- [ ] 10.5 Create DeleteAccountSection component
  - Create `src/features/profile-settings/components/DeleteAccountSection.tsx`
  - Display "Delete Account" heading with warning
  - Add "Delete My Account" button (red, destructive style)
  - Open DeleteAccountDialog on click
  - _Requirements: 1.9_

- [ ] 10.6 Create DeleteAccountDialog component
  - Create `src/features/profile-settings/components/DeleteAccountDialog.tsx`
  - Display warning about permanent data deletion
  - Require typing "DELETE" to confirm
  - Check for active subscription and require cancellation first
  - Use useDeleteAccount hook
  - Redirect to homepage on success
  - _Requirements: 1.9_

## 11. Shared Components

- [ ] 11.1 Create AccountBadges component
  - Create `src/features/profile-settings/components/AccountBadges.tsx`
  - Display verification badge (Verified/Unverified)
  - Display active status badge
  - Display role badge (User/Admin)
  - Use color coding and icons
  - _Requirements: 1.6_

- [ ] 11.2 Create FormSection component
  - Create `src/features/profile-settings/components/FormSection.tsx`
  - Reusable section wrapper with title and description
  - Consistent spacing and styling
  - _Requirements: All profile settings requirements_

- [ ] 11.3 Create LoadingStates components
  - Create skeleton loaders for profile sections
  - Create loading spinner for modals
  - Create progress bar for uploads
  - _Requirements: All profile settings requirements_

## 12. Validation and Error Handling

- [ ] 12.1 Create validation utilities
  - Create `src/features/profile-settings/utils/validation.ts`
  - Implement validateFullName(name: string): boolean
  - Implement validateCompany(company: string): boolean
  - Implement validateProfilePictureUrl(url: string): boolean
  - Implement validatePassword(password: string): PasswordValidation
  - _Requirements: 1.2, 1.5_

- [ ] 12.2 Create error message mapping
  - Create `src/features/profile-settings/utils/error-messages.ts`
  - Map all error codes to user-friendly messages
  - Include dynamic values (field names, limits)
  - Export getErrorMessage(code: string, context?: any): string
  - _Requirements: All profile settings requirements_

- [ ] 12.3 Implement error display
  - Show inline errors for form validation
  - Show toast notifications for API errors
  - Display error states in sections
  - Add retry buttons for failed requests
  - _Requirements: All profile settings requirements_

## 13. Timezone and Language Support

- [ ] 13.1 Create timezone selector
  - Create `src/features/profile-settings/components/TimezoneSelector.tsx`
  - Provide searchable dropdown with all timezones
  - Group timezones by region
  - Display current timezone prominently
  - _Requirements: 1.4_

- [ ] 13.2 Create language selector
  - Create `src/features/profile-settings/components/LanguageSelector.tsx`
  - Provide dropdown with supported languages
  - Display language names in native script
  - Show current language
  - _Requirements: 1.4_

- [ ] 13.3 Implement timezone data
  - Create `src/features/profile-settings/utils/timezones.ts`
  - Export list of standard timezones
  - Include timezone offsets
  - Group by region (Americas, Europe, Asia, etc.)
  - _Requirements: 1.4_

- [ ] 13.4 Implement language data
  - Create `src/features/profile-settings/utils/languages.ts`
  - Export list of supported languages
  - Include language codes and native names
  - _Requirements: 1.4_

## 14. Notification Preferences

- [ ] 14.1 Create NotificationToggle component
  - Create `src/features/profile-settings/components/NotificationToggle.tsx`
  - Implement toggle switch with label and description
  - Show warning for critical notifications
  - Use optimistic updates
  - _Requirements: 1.8_

- [ ] 14.2 Implement notification preferences logic
  - Define notification types and defaults
  - Handle preference updates via profile API
  - Show success feedback
  - _Requirements: 1.8_

## 15. Testing

- [ ] 15.1 Write unit tests for validation
  - Test full_name validation
  - Test company validation
  - Test profile_picture_url validation
  - Test password validation
  - Test password strength calculation
  - _Requirements: 1.2, 1.5_

- [ ] 15.2 Write component tests
  - Test ProfileSettingsPage rendering
  - Test EditProfileModal submission
  - Test ChangePasswordModal flow
  - Test AvatarUpload functionality
  - Test NotificationPreferences toggles
  - _Requirements: All profile settings requirements_

- [ ] 15.3 Write integration tests
  - Test complete profile update flow
  - Test password change with session invalidation
  - Test avatar upload and profile update
  - Test preferences update
  - Test error handling scenarios
  - _Requirements: All profile settings requirements_

- [ ] 15.4 Write E2E tests
  - Test navigate to profile settings
  - Test update profile information
  - Test change password and re-login
  - Test upload avatar
  - Test export data
  - Test delete account flow
  - _Requirements: All profile settings requirements_

## 16. Accessibility

- [ ] 16.1 Implement keyboard navigation
  - Ensure all forms are keyboard accessible
  - Implement logical tab order
  - Add keyboard shortcuts for save (Ctrl+S)
  - Test with keyboard only
  - _Requirements: All profile settings requirements_

- [ ] 16.2 Add ARIA labels and roles
  - Add proper labels to all form inputs
  - Add ARIA labels to buttons and toggles
  - Implement ARIA live regions for success/error messages
  - Add screen reader descriptions for sections
  - Test with screen readers (NVDA/JAWS)
  - _Requirements: All profile settings requirements_

- [ ] 16.3 Ensure color accessibility
  - Use WCAG AA compliant color contrast
  - Don't rely solely on color for validation states
  - Add icons in addition to color coding
  - Test with color blindness simulators
  - _Requirements: All profile settings requirements_

## 17. Performance Optimization

- [ ] 17.1 Optimize data fetching
  - Cache profile data for 5 minutes
  - Implement optimistic updates for better UX
  - Debounce form inputs (300ms)
  - Cancel pending requests on unmount
  - _Requirements: All profile settings requirements_

- [ ] 17.2 Optimize image uploads
  - Compress images before upload
  - Show upload progress
  - Implement retry logic for failed uploads
  - Cache uploaded image URLs
  - _Requirements: 1.3_

- [ ] 17.3 Implement code splitting
  - Lazy load modals
  - Lazy load tabs
  - Use React.lazy and Suspense
  - _Requirements: All profile settings requirements_

## 18. Security Implementation

- [ ] 18.1 Implement secure password handling
  - Never log password values
  - Clear password fields after submission
  - Use autocomplete attributes correctly
  - Implement password visibility toggle
  - _Requirements: 1.5_

- [ ] 18.2 Implement URL sanitization
  - Create `src/features/profile-settings/utils/sanitize.ts`
  - Sanitize profile_picture_url to prevent XSS
  - Validate URL protocol (https only)
  - Strip potentially dangerous characters
  - _Requirements: 1.2, 1.3_

- [ ] 18.3 Implement session invalidation handling
  - Handle 401 responses after password change
  - Clear auth state
  - Redirect to login with message
  - _Requirements: 1.5_

## 19. Documentation

- [ ] 19.1 Add component documentation
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - Document validation rules
  - _Requirements: All profile settings requirements_

- [ ] 19.2 Create user documentation
  - Document how to update profile
  - Document how to change password
  - Document notification preferences
  - Create FAQ for common issues
  - Document data export process
  - _Requirements: All profile settings requirements_