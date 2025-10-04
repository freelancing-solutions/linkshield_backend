# Implementation Plan

## 1. Project Setup

- [ ] 1.1 Create homepage module structure
  - Create `src/features/homepage` directory
  - Create subdirectories: `components`, `hooks`, `api`, `types`, `utils`
  - Create `src/features/homepage/index.ts` for barrel exports
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 1.2 Create TypeScript interfaces
  - Create `src/features/homepage/types/index.ts`
  - Define URLCheckRequest, URLCheckResponse, ScanType interfaces
  - Define DomainReputation, ExtensionStatus, AlgorithmHealth interfaces
  - Define SubscriptionInfo interface
  - Export all types
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

## 2. API Integration

- [ ] 2.1 Create URL check API methods
  - Create `src/features/homepage/api/url-check-api.ts`
  - Implement checkURL(url, scanType): Promise<URLCheckResponse>
  - Implement getDomainReputation(domain): Promise<DomainReputation>
  - Handle anonymous vs authenticated requests
  - _Requirements: 1.1, 1.4_

- [ ] 2.2 Create Social Protection API methods
  - Create `src/features/homepage/api/social-protection-api.ts`
  - Implement getExtensionStatus(): Promise<ExtensionStatus>
  - Implement getExtensionAnalytics(timeRange): Promise<ExtensionAnalytics>
  - Implement getAlgorithmHealth(): Promise<AlgorithmHealth>
  - Implement analyzeVisibility(): Promise<VisibilityAnalysis>
  - Implement analyzeEngagement(): Promise<EngagementAnalysis>
  - Implement detectPenalties(): Promise<PenaltyDetection>
  - _Requirements: 1.5, 1.6, 1.7_

- [ ] 2.3 Create subscriptions API methods
  - Create `src/features/homepage/api/subscriptions-api.ts`
  - Implement getSubscriptions(): Promise<Subscription[]>
  - Implement getSubscriptionUsage(id): Promise<UsageStats>
  - _Requirements: 1.8_

## 3. React Query Hooks

- [ ] 3.1 Create URL check hooks
  - Create `src/features/homepage/hooks/use-url-check.ts`
  - Implement useCheckURL() mutation hook
  - Implement useDomainReputation(domain) query hook with enabled condition
  - _Requirements: 1.1, 1.4_

- [ ] 3.2 Create Social Protection hooks
  - Create `src/features/homepage/hooks/use-social-protection.ts`
  - Implement useExtensionStatus() query hook (auth required)
  - Implement useAlgorithmHealth() query hook (auth required)
  - Implement useAnalyzeVisibility() mutation hook
  - Implement useAnalyzeEngagement() mutation hook
  - Implement useDetectPenalties() mutation hook
  - _Requirements: 1.5, 1.6, 1.7_

- [ ] 3.3 Create subscription hooks
  - Create `src/features/homepage/hooks/use-subscription.ts`
  - Implement useSubscriptions() query hook (auth required)
  - Implement useSubscriptionUsage(id) query hook (auth required)
  - _Requirements: 1.8_

## 4. Homepage Layout

- [ ] 4.1 Create HomePage component
  - Create `src/features/homepage/pages/HomePage.tsx`
  - Implement responsive layout with hero section and sidebars
  - Add conditional rendering based on auth state
  - Use CSS Grid for layout
  - _Requirements: All homepage requirements_

- [ ] 4.2 Create HeroSection component
  - Create `src/features/homepage/components/HeroSection.tsx`
  - Display headline and subheadline
  - Render URLCheckerForm
  - Add trust indicators (e.g., "X URLs checked today")
  - _Requirements: 1.1_

## 5. URL Checker Form

- [ ] 5.1 Create URLCheckerForm component
  - Create `src/features/homepage/components/URLCheckerForm.tsx`
  - Implement URL input field with validation
  - Add scan type selector (Quick/Comprehensive/Deep)
  - Use react-hook-form with Zod validation
  - Use useCheckURL hook
  - Display loading state during check
  - _Requirements: 1.1, 1.2_

- [ ] 5.2 Implement URL validation
  - Create `src/features/homepage/utils/validation.ts`
  - Validate URL format (1-2048 characters)
  - Check for valid protocol (http/https)
  - Sanitize input
  - _Requirements: 1.1_

- [ ] 5.3 Create ScanTypeSelector component
  - Create `src/features/homepage/components/ScanTypeSelector.tsx`
  - Display Quick, Comprehensive, Deep options as tabs or radio buttons
  - Show scan type descriptions
  - Display estimated scan time for each type
  - Implement plan-based gating (Deep requires Pro+)
  - Show "Upgrade" badge for gated options
  - _Requirements: 1.2_

- [ ] 5.4 Implement scan type gating
  - Check user authentication status
  - Check user subscription plan
  - Disable Deep scan for anonymous users
  - Disable Deep scan for Free/Basic plans
  - Show upgrade CTA when Deep is selected but not available
  - _Requirements: 1.2_

## 6. Results Display

- [ ] 6.1 Create ScanResults component
  - Create `src/features/homepage/components/ScanResults.tsx`
  - Display risk score gauge (0-100)
  - Show threat level badge (Safe/Suspicious/Malicious)
  - Render provider results accordion
  - Add action buttons (Save, Report, Analyze with AI)
  - _Requirements: 1.3_

- [ ] 6.2 Create RiskScoreGauge component
  - Create `src/features/homepage/components/RiskScoreGauge.tsx`
  - Implement circular gauge visualization
  - Color code based on score (green/yellow/orange/red)
  - Display score number prominently
  - Add animation on load
  - _Requirements: 1.3_

- [ ] 6.3 Create ThreatLevelBadge component
  - Create `src/features/homepage/components/ThreatLevelBadge.tsx`
  - Display badge with icon and label
  - Color code: green (Safe), yellow (Suspicious), red (Malicious)
  - Add tooltip with explanation
  - _Requirements: 1.3_

- [ ] 6.4 Create ProviderResultsAccordion component
  - Create `src/features/homepage/components/ProviderResultsAccordion.tsx`
  - Display sections for VirusTotal, Google Safe Browsing, URLVoid
  - Implement expand/collapse functionality
  - Show provider logos
  - Display findings and confidence scores
  - For anonymous users, show limited details with "Sign up for full report" CTA
  - _Requirements: 1.3_

- [ ] 6.5 Create BrokenLinksTab component
  - Create `src/features/homepage/components/BrokenLinksTab.tsx`
  - Display broken links count badge
  - Show table with URL, status code, depth
  - Only show if broken links scan was performed
  - _Requirements: 1.3_

- [ ] 6.6 Create ResultActions component
  - Create `src/features/homepage/components/ResultActions.tsx`
  - Add "Save to History" button (authenticated only)
  - Add "Report URL" button
  - Add "Analyze with AI" button
  - Implement button click handlers
  - _Requirements: 1.3, 1.10_

## 7. Domain Reputation

- [ ] 7.1 Create DomainReputationBadge component
  - Create `src/features/homepage/components/DomainReputationBadge.tsx`
  - Use useDomainReputation hook
  - Extract domain from entered URL
  - Display reputation badge (Trusted/Neutral/Suspicious/Malicious)
  - Show reputation score (0-100)
  - Display check history summary
  - Hide if reputation data unavailable
  - _Requirements: 1.4_

## 8. Social Protection Integration (Authenticated)

- [ ] 8.1 Create SocialProtectionPanel component
  - Create `src/features/homepage/components/SocialProtectionPanel.tsx`
  - Check authentication status
  - Render only for authenticated users
  - Display ExtensionStatusCard, AlgorithmHealthSummary, SocialAccountScan sections
  - Use grid layout for cards
  - _Requirements: 1.5_

- [ ] 8.2 Create ExtensionStatusCard component
  - Create `src/features/homepage/components/ExtensionStatusCard.tsx`
  - Use useExtensionStatus hook
  - Display connection status badge (Connected/Disconnected)
  - Show last activity timestamp
  - Display today's protection count
  - Add "View Analytics" link
  - Show "Install Extension" CTA if disconnected
  - Handle loading and error states
  - _Requirements: 1.5, 1.6_

- [ ] 8.3 Create AlgorithmHealthSummary component
  - Create `src/features/homepage/components/AlgorithmHealthSummary.tsx`
  - Use useAlgorithmHealth hook
  - Display visibility, engagement, and penalty scores
  - Show trend indicators (up/down/stable)
  - Display warning badge if penalty detected
  - Add "Analyze Visibility" button
  - Add "Analyze Engagement" button
  - Add "Detect Penalties" button
  - Show processing status during analysis
  - _Requirements: 1.5, 1.7_

- [ ] 8.4 Implement algorithm health analyses
  - Use useAnalyzeVisibility, useAnalyzeEngagement, useDetectPenalties hooks
  - Show loading spinner during analysis
  - Display results in modal or navigate to results page
  - Handle errors with retry option
  - _Requirements: 1.7_

- [ ] 8.5 Create SocialAccountScan component
  - Create `src/features/homepage/components/SocialAccountScan.tsx`
  - Display "Scan Account" button for connected platforms
  - Show platform icons (Twitter, Facebook, Instagram, etc.)
  - Navigate to Social Protection user analyze on click
  - _Requirements: 1.5_

## 9. Subscription Display (Authenticated)

- [ ] 9.1 Create SubscriptionPlanCard component
  - Create `src/features/homepage/components/SubscriptionPlanCard.tsx`
  - Use useSubscriptions and useSubscriptionUsage hooks
  - Display current plan name and price
  - Show usage summary with progress bar
  - Display renewal date
  - Show warning if usage > 80%
  - Show "Limit reached" message if usage >= 100%
  - Add "Upgrade to Pro" CTA for Free plan users
  - Link to subscriptions page
  - _Requirements: 1.8_

## 10. Quick Actions (Authenticated)

- [ ] 10.1 Create QuickActionsPanel component
  - Create `src/features/homepage/components/QuickActionsPanel.tsx`
  - Check authentication status
  - Display quick action buttons: Bulk URL Check, AI Analysis, View Reports, API Keys
  - Use icon buttons with labels
  - Implement navigation on click
  - _Requirements: 1.9_

## 11. Save to History (Authenticated)

- [ ] 11.1 Implement auto-save functionality
  - Automatically save check to history when user is authenticated
  - Show "Saved to history" toast on success
  - Handle save errors gracefully
  - _Requirements: 1.10_

- [ ] 11.2 Create ViewInHistoryButton component
  - Create `src/features/homepage/components/ViewInHistoryButton.tsx`
  - Display "View in History" button after save
  - Navigate to URL analysis history page with check highlighted
  - _Requirements: 1.10_

## 12. Anonymous User Experience

- [ ] 12.1 Create SignUpCTA component
  - Create `src/features/homepage/components/SignUpCTA.tsx`
  - Display "Sign up for detailed analysis" message
  - Show benefits of signing up
  - Add "Sign Up" button linking to registration
  - Use different variants (banner, modal, inline)
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 12.2 Implement rate limit handling
  - Create `src/features/homepage/components/RateLimitNotice.tsx`
  - Parse X-RateLimit-* headers from response
  - Display remaining checks and reset time
  - Show "Sign up for 100 checks/hour" CTA when limit reached
  - _Requirements: 1.1_

## 13. Error Handling

- [ ] 13.1 Create error handling utilities
  - Create `src/features/homepage/utils/error-handling.ts`
  - Map error codes to user-friendly messages
  - Handle network errors
  - Handle validation errors
  - Handle rate limit errors (429)
  - Handle feature not available errors (402)
  - _Requirements: All homepage requirements_

- [ ] 13.2 Create ErrorDisplay component
  - Create `src/features/homepage/components/ErrorDisplay.tsx`
  - Display error message with icon
  - Show retry button for recoverable errors
  - Show upgrade CTA for feature not available errors
  - _Requirements: All homepage requirements_

## 14. Loading States

- [ ] 14.1 Create LoadingSpinner component
  - Create `src/features/homepage/components/LoadingSpinner.tsx`
  - Display during URL check
  - Show estimated time remaining
  - Add progress indicator
  - _Requirements: 1.1, 1.2_

- [ ] 14.2 Create SkeletonLoaders
  - Create skeleton loaders for: results, cards, charts
  - Match actual component layouts
  - Use shimmer animation
  - _Requirements: All homepage requirements_

## 15. Responsive Design

- [ ] 15.1 Implement mobile layout
  - Stack components vertically on mobile
  - Adjust font sizes and spacing
  - Make buttons touch-friendly (min 44x44px)
  - Test on various screen sizes
  - _Requirements: All homepage requirements_

- [ ] 15.2 Implement tablet layout
  - Use 2-column layout for cards
  - Adjust sidebar placement
  - Optimize for landscape and portrait
  - _Requirements: All homepage requirements_

- [ ] 15.3 Implement desktop layout
  - Use 3-column layout with sidebars
  - Maximize use of screen space
  - Implement hover states
  - _Requirements: All homepage requirements_

## 16. Testing

- [ ] 16.1 Write unit tests for validation
  - Test URL validation logic
  - Test scan type gating logic
  - Test error message mapping
  - _Requirements: 1.1, 1.2_

- [ ] 16.2 Write component tests
  - Test URLCheckerForm submission
  - Test ScanResults rendering
  - Test ExtensionStatusCard states
  - Test AlgorithmHealthSummary actions
  - Test SubscriptionPlanCard display
  - _Requirements: All homepage requirements_

- [ ] 16.3 Write integration tests
  - Test complete URL check flow
  - Test anonymous vs authenticated experience
  - Test Social Protection integration
  - Test plan-based feature gating
  - _Requirements: All homepage requirements_

- [ ] 16.4 Write E2E tests
  - Test homepage load and URL check
  - Test scan type selection
  - Test results display
  - Test Social Protection features
  - Test quick actions navigation
  - _Requirements: All homepage requirements_

## 17. Accessibility

- [ ] 17.1 Implement keyboard navigation
  - Ensure all interactive elements are keyboard accessible
  - Implement logical tab order
  - Add keyboard shortcuts (e.g., Enter to submit)
  - Test with keyboard only
  - _Requirements: All homepage requirements_

- [ ] 17.2 Add ARIA labels
  - Add proper labels to form inputs
  - Add ARIA labels to buttons and links
  - Implement ARIA live regions for dynamic updates
  - Add screen reader descriptions
  - _Requirements: All homepage requirements_

- [ ] 17.3 Ensure color accessibility
  - Use WCAG AA compliant color contrast
  - Don't rely solely on color for threat levels
  - Add icons in addition to color coding
  - Test with color blindness simulators
  - _Requirements: All homepage requirements_

## 18. Performance Optimization

- [ ] 18.1 Optimize initial load
  - Lazy load Social Protection components
  - Defer non-critical scripts
  - Optimize images and icons
  - Implement code splitting
  - _Requirements: All homepage requirements_

- [ ] 18.2 Optimize data fetching
  - Cache domain reputation lookups
  - Debounce URL input (300ms)
  - Cancel pending requests on new submission
  - Prefetch extension status for authenticated users
  - _Requirements: All homepage requirements_

## 19. Documentation

- [ ] 19.1 Add component documentation
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - Document scan types and limitations
  - _Requirements: All homepage requirements_

- [ ] 19.2 Create user documentation
  - Document how to use URL checker
  - Explain scan types
  - Document Social Protection features
  - Create FAQ for common issues
  - _Requirements: All homepage requirements_