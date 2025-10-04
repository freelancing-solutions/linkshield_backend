# Implementation Plan

## 1. Project Setup

- [ ] 1.1 Create API keys module structure
  - Create `src/features/api-keys` directory with subdirectories: `components`, `hooks`, `api`, `types`, `utils`
  - Set up barrel exports in index files
  - _Requirements: All API key requirements_

- [ ] 1.2 Create TypeScript interfaces
  - Create `src/features/api-keys/types/index.ts`
  - Define ApiKey, ApiKeyResponse, CreateApiKeyRequest interfaces
  - Define Permission type and permission options
  - _Requirements: 1.1, 1.2, 1.6_

## 2. API Integration

- [ ] 2.1 Implement API client methods
  - Create `src/features/api-keys/api/api-keys-api.ts`
  - Implement getApiKeys(): Promise<ApiKey[]>
  - Implement createApiKey(data): Promise<ApiKeyResponse>
  - Implement deleteApiKey(keyId): Promise<void>
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 2.2 Create React Query hooks
  - Create `src/features/api-keys/hooks/use-api-keys.ts`
  - Implement useApiKeys query hook with 2-minute stale time
  - Implement useCreateApiKey mutation hook with cache invalidation
  - Implement useDeleteApiKey mutation hook with cache invalidation
  - _Requirements: 1.1, 1.2, 1.3_

## 3. Core Components

- [ ] 3.1 Create ApiKeysPage component
  - Create `src/features/api-keys/pages/ApiKeysPage.tsx`
  - Implement page layout with header and list
  - Manage modal state (create, reveal, delete)
  - Use useApiKeys hook to fetch data
  - Handle loading and error states
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 3.2 Create ApiKeysList component
  - Create `src/features/api-keys/components/ApiKeysList.tsx`
  - Display table with columns: name, key_preview, permissions, status, last_used, expires, actions
  - Implement empty state when no keys exist
  - Add sorting functionality
  - _Requirements: 1.1, 1.5_

- [ ] 3.3 Create ApiKeyRow component
  - Create `src/features/api-keys/components/ApiKeyRow.tsx`
  - Implement expandable row for details
  - Display status badges (Active, Expired, Inactive, Expiring Soon)
  - Show delete button with confirmation
  - _Requirements: 1.1, 1.5_

## 4. Create API Key Feature

- [ ] 4.1 Create CreateApiKeyModal component
  - Create `src/features/api-keys/components/CreateApiKeyModal.tsx`
  - Implement modal with form fields
  - Add name, description, expires_at, permissions fields
  - Use react-hook-form with Zod validation
  - _Requirements: 1.2_

- [ ] 4.2 Create PermissionSelector component
  - Create `src/features/api-keys/components/PermissionSelector.tsx`
  - Implement multi-select checkboxes for permissions
  - Display permission descriptions
  - Validate at least one permission selected
  - _Requirements: 1.2, 1.6_

- [ ] 4.3 Implement form validation
  - Create validation schema with Zod
  - Validate name: required, 3-50 characters
  - Validate description: optional, max 200 characters
  - Validate expires_at: optional, must be future date
  - Validate permissions: at least one required
  - _Requirements: 1.2, 1.6_

- [ ] 4.4 Handle API key creation
  - Use useCreateApiKey hook for submission
  - Handle success: show reveal modal with full key
  - Handle errors: display appropriate error messages
  - Handle rate limiting (429)
  - Handle limit reached (400)
  - _Requirements: 1.2_

## 5. Reveal API Key Feature

- [ ] 5.1 Create ApiKeyRevealModal component
  - Create `src/features/api-keys/components/ApiKeyRevealModal.tsx`
  - Display full API key in monospace font
  - Show warning: "This is the only time you will see this key"
  - Add copy to clipboard button
  - Implement secure key handling (no logging, clear on close)
  - _Requirements: 1.2, 1.4_

- [ ] 5.2 Implement secure clipboard functionality
  - Create `src/features/api-keys/utils/clipboard.ts`
  - Implement copyToClipboard using Clipboard API
  - Add fallback for browsers without Clipboard API
  - Show success toast on copy
  - Handle copy failures gracefully
  - _Requirements: 1.4_

- [ ] 5.3 Implement key memory management
  - Clear revealed key from state on modal close
  - Prevent key from being stored in localStorage
  - Ensure key is not logged to console
  - Add confirmation before closing reveal modal
  - _Requirements: 1.2, 1.4_

## 6. Delete API Key Feature

- [ ] 6.1 Create DeleteApiKeyDialog component
  - Create `src/features/api-keys/components/DeleteApiKeyDialog.tsx`
  - Display confirmation dialog with key name
  - Show warning about immediate access revocation
  - Add "I understand" confirmation checkbox
  - Implement cancel and delete buttons
  - _Requirements: 1.3_

- [ ] 6.2 Handle API key deletion
  - Use useDeleteApiKey hook
  - Show confirmation dialog before deletion
  - Handle success: remove from list, show toast
  - Handle errors: 404 (not found), 403 (forbidden)
  - Refresh API keys list after deletion
  - _Requirements: 1.3_

## 7. UI Components and Styling

- [ ] 7.1 Create status badge component
  - Implement getStatusBadge utility function
  - Display "Active" badge for active keys
  - Display "Expired" badge for expired keys
  - Display "Expiring Soon" badge for keys expiring within 7 days
  - Display "Inactive" badge for inactive keys
  - _Requirements: 1.1, 1.5_

- [ ] 7.2 Create empty state component
  - Design empty state with icon and message
  - Add "Create your first API key" CTA button
  - Display when no API keys exist
  - _Requirements: 1.1_

- [ ] 7.3 Implement loading states
  - Add skeleton loaders for table
  - Add loading spinner for modal submissions
  - Disable form inputs during submission
  - _Requirements: 1.1, 1.2, 1.3_

## 8. Error Handling

- [ ] 8.1 Create error message mapping
  - Create `src/features/api-keys/utils/error-messages.ts`
  - Map API_KEY_LIMIT_REACHED to user message with upgrade CTA
  - Map INVALID_PERMISSION to validation error
  - Map API_KEY_NOT_FOUND to not found message
  - Map UNAUTHORIZED to session expired message
  - Map FORBIDDEN to permission denied message
  - _Requirements: All requirements_

- [ ] 8.2 Implement error display
  - Show inline errors for form validation
  - Show toast notifications for API errors
  - Display upgrade CTA when limit reached
  - Handle network errors with retry option
  - _Requirements: All requirements_

## 9. Plan-Based Limits

- [ ] 9.1 Implement plan limit checking
  - Check user's subscription plan from auth context
  - Enforce 3 key limit for Free tier
  - Enforce 10 key limit for Premium tier
  - Display current usage vs limit
  - _Requirements: 1.2_

- [ ] 9.2 Add upgrade CTA
  - Show upgrade button when limit reached
  - Link to subscriptions page
  - Display plan comparison
  - _Requirements: 1.2_

## 10. Testing

- [ ] 10.1 Write unit tests for components
  - Test ApiKeysList displays keys correctly
  - Test empty state when no keys
  - Test status badge logic
  - Test form validation
  - Test permission selector
  - Test clipboard copy functionality
  - _Requirements: All requirements_

- [ ] 10.2 Write integration tests
  - Test create API key flow end-to-end
  - Test reveal modal displays key once
  - Test delete API key with confirmation
  - Test error handling scenarios
  - Test plan limit enforcement
  - _Requirements: All requirements_

- [ ] 10.3 Write E2E tests
  - Test complete API key lifecycle
  - Test copy to clipboard and verify
  - Test deletion and list refresh
  - Test error states
  - _Requirements: All requirements_

## 11. Accessibility

- [ ] 11.1 Implement keyboard navigation
  - Ensure all interactive elements are keyboard accessible
  - Implement logical tab order
  - Add visible focus indicators
  - Test with keyboard only
  - _Requirements: All requirements_

- [ ] 11.2 Add ARIA labels
  - Add aria-labels to all buttons
  - Add aria-describedby for form fields
  - Implement aria-live regions for notifications
  - Add proper table headers and structure
  - _Requirements: All requirements_

- [ ] 11.3 Test with screen readers
  - Test with NVDA/JAWS
  - Ensure all actions are announced
  - Verify form errors are announced
  - Test modal focus management
  - _Requirements: All requirements_

## 12. Documentation

- [ ] 12.1 Add component documentation
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - Document security considerations
  - _Requirements: All requirements_

- [ ] 12.2 Create user documentation
  - Document how to create API keys
  - Document permission types
  - Document security best practices
  - Create troubleshooting guide
  - _Requirements: All requirements_
