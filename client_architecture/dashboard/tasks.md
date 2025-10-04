# Implementation Plan

## 1. Project Setup and Module Structure

- [ ] 1.1 Create dashboard module structure
  - Create `src/features/dashboard` directory
  - Create subdirectories: `components`, `hooks`, `api`, `types`, `utils`, `pages`
  - Create `src/features/dashboard/index.ts` for barrel exports
  - _Requirements: All dashboard requirements_

- [ ] 1.2 Create TypeScript interfaces
  - Create `src/features/dashboard/types/index.ts`
  - Define DashboardOverview, Project, TeamMember, Alert interfaces
  - Define SocialProtectionOverview, ExtensionStatus, AlgorithmHealth interfaces
  - Define CrisisAlert, BotHealth, SubscriptionInfo interfaces
  - Export all types from index
  - _Requirements: All dashboard requirements_

## 2. API Integration Layer

- [ ] 2.1 Create dashboard API client
  - Create `src/features/dashboard/api/dashboard-api.ts`
  - Implement getOverview(): Promise<DashboardOverview>
  - Implement getProjects(params): Promise<ProjectsResponse>
  - Implement createProject(data): Promise<Project>
  - Implement getProject(id): Promise<Project>
  - Implement updateProject(id, data): Promise<Project>
  - Implement deleteProject(id): Promise<void>
  - Implement toggleMonitoring(projectId, enabled): Promise<void>
  - _Requirements: Dashboard overview, projects management_

- [ ] 2.2 Create team management API methods
  - Add to `src/features/dashboard/api/dashboard-api.ts`
  - Implement getTeamMembers(projectId): Promise<TeamMember[]>
  - Implement inviteTeamMember(projectId, data): Promise<TeamMember>
  - _Requirements: Team management_

- [ ] 2.3 Create alerts API methods
  - Add to `src/features/dashboard/api/dashboard-api.ts`
  - Implement getAlerts(projectId, filters): Promise<AlertsResponse>
  - Implement getAlert(projectId, alertId): Promise<Alert>
  - Implement resolveAlert(projectId, alertId): Promise<void>
  - _Requirements: Alerts management_

- [ ] 2.4 Create Social Protection API methods
  - Create `src/features/dashboard/api/social-protection-api.ts`
  - Implement getSocialProtectionOverview(projectId?): Promise<SocialProtectionOverview>
  - Implement getExtensionStatus(): Promise<ExtensionStatus>
  - Implement getExtensionAnalytics(timeRange): Promise<ExtensionAnalytics>
  - Implement getExtensionSettings(): Promise<ExtensionSettings>
  - Implement getAlgorithmHealth(): Promise<AlgorithmHealth>
  - Implement analyzeVisibility(): Promise<VisibilityAnalysis>
  - Implement analyzeEngagement(): Promise<EngagementAnalysis>
  - Implement detectPenalties(): Promise<PenaltyDetection>
  - Implement batchAnalyze(data): Promise<BatchAnalysisResult>
  - Implement getCrisisAlerts(filters): Promise<CrisisAlert[]>
  - Implement resolveCrisisAlert(alertId, data): Promise<void>
  - Implement getCrisisRecommendations(alertId): Promise<Recommendation[]>
  - Implement getCrisisStats(timeRange): Promise<CrisisStats>
  - Implement getBotHealth(): Promise<BotHealth>
  - _Requirements: Social Protection features_

## 3. React Query Hooks

- [ ] 3.1 Create dashboard overview hooks
  - Create `src/features/dashboard/hooks/use-dashboard.ts`
  - Implement useDashboardOverview() query hook with 5-minute stale time
  - _Requirements: Dashboard overview_

- [ ] 3.2 Create projects hooks
  - Create `src/features/dashboard/hooks/use-projects.ts`
  - Implement useProjects(filters) query hook with keepPreviousData
  - Implement useProject(id) query hook
  - Implement useCreateProject() mutation hook with cache invalidation
  - Implement useUpdateProject() mutation hook with optimistic updates
  - Implement useDeleteProject() mutation hook with cache invalidation
  - Implement useToggleMonitoring() mutation hook with optimistic updates
  - _Requirements: Projects management_

- [ ] 3.3 Create team hooks
  - Create `src/features/dashboard/hooks/use-team.ts`
  - Implement useTeamMembers(projectId) query hook
  - Implement useInviteTeamMember() mutation hook
  - _Requirements: Team management_

- [ ] 3.4 Create alerts hooks
  - Create `src/features/dashboard/hooks/use-alerts.ts`
  - Implement useAlerts(projectId, filters) query hook
  - Implement useAlert(projectId, alertId) query hook
  - Implement useResolveAlert() mutation hook with optimistic updates
  - _Requirements: Alerts management_

- [ ] 3.5 Create Social Protection hooks
  - Create `src/features/dashboard/hooks/use-social-protection.ts`
  - Implement useSocialProtectionOverview(projectId?) query hook
  - Implement useExtensionStatus() query hook with 1-minute refetch
  - Implement useExtensionAnalytics(timeRange) query hook
  - Implement useAlgorithmHealth() query hook
  - Implement useAnalyzeVisibility() mutation hook
  - Implement useAnalyzeEngagement() mutation hook
  - Implement useDetectPenalties() mutation hook
  - Implement useBatchAnalyze() mutation hook (plan-gated)
  - Implement useCrisisAlerts(filters) query hook
  - Implement useResolveCrisisAlert() mutation hook
  - Implement useCrisisRecommendations(alertId) query hook
  - Implement useCrisisStats(timeRange) query hook
  - Implement useBotHealth() query hook with 5-minute refetch
  - _Requirements: Social Protection features_

## 4. Dashboard Overview Page

- [ ] 4.1 Create DashboardOverviewPage component
  - Create `src/features/dashboard/pages/DashboardOverviewPage.tsx`
  - Use useDashboardOverview hook
  - Implement page layout with grid for KPI cards and activity list
  - Handle loading state with skeleton loaders
  - Handle error state with retry button
  - _Requirements: Dashboard overview_

- [ ] 4.2 Create KPI Cards component
  - Create `src/features/dashboard/components/KPICards.tsx`
  - Display total projects, active alerts, recent scans cards
  - Add icons and color coding for each metric
  - Implement click navigation to relevant sections
  - _Requirements: Dashboard overview_

- [ ] 4.3 Create RecentActivity component
  - Create `src/features/dashboard/components/RecentActivity.tsx`
  - Display list of recent activities with timestamps
  - Group activities by date
  - Add activity type icons
  - Implement "View All" link
  - _Requirements: Dashboard overview_

## 5. Projects Management

- [ ] 5.1 Create ProjectsListPage component
  - Create `src/features/dashboard/pages/ProjectsListPage.tsx`
  - Use useProjects hook with filters
  - Implement search input with debounce (300ms)
  - Add "Create Project" button
  - Display projects table with pagination
  - _Requirements: Projects management_

- [ ] 5.2 Create ProjectsTable component
  - Create `src/features/dashboard/components/ProjectsTable.tsx`
  - Display columns: name, status, monitoring, team size, alerts, created date, actions
  - Implement sortable columns
  - Add row click to navigate to project detail
  - Show monitoring toggle switch inline
  - Add actions dropdown (Edit, Delete)
  - _Requirements: Projects management_

- [ ] 5.3 Create CreateProjectModal component
  - Create `src/features/dashboard/components/CreateProjectModal.tsx`
  - Implement form with name, description, settings fields
  - Use react-hook-form with Zod validation
  - Use useCreateProject hook
  - Show success toast and navigate to project detail on success
  - _Requirements: Projects management_

- [ ] 5.4 Create ProjectDetailPage component
  - Create `src/features/dashboard/pages/ProjectDetailPage.tsx`
  - Use useProject hook
  - Implement tabs: Overview, Team, Alerts, Settings
  - Display project info and stats
  - Add Edit and Delete buttons
  - _Requirements: Projects management_

- [ ] 5.5 Create MonitoringToggle component
  - Create `src/features/dashboard/components/MonitoringToggle.tsx`
  - Implement toggle switch
  - Use useToggleMonitoring hook with optimistic updates
  - Show loading state during toggle
  - Display confirmation dialog for disabling
  - _Requirements: Projects management_

- [ ] 5.6 Create EditProjectModal component
  - Create `src/features/dashboard/components/EditProjectModal.tsx`
  - Pre-fill form with current project data
  - Use useUpdateProject hook
  - Implement optimistic updates
  - _Requirements: Projects management_

- [ ] 5.7 Create DeleteProjectDialog component
  - Create `src/features/dashboard/components/DeleteProjectDialog.tsx`
  - Show confirmation with project name
  - Require typing project name to confirm
  - Use useDeleteProject hook
  - Navigate to projects list on success
  - _Requirements: Projects management_

## 6. Team Management

- [ ] 6.1 Create TeamTab component
  - Create `src/features/dashboard/components/TeamTab.tsx`
  - Use useTeamMembers hook
  - Display team members table
  - Add "Invite Member" button
  - Show member roles and permissions
  - _Requirements: Team management_

- [ ] 6.2 Create TeamMembersTable component
  - Create `src/features/dashboard/components/TeamMembersTable.tsx`
  - Display columns: name, email, role, joined date, actions
  - Show member avatars
  - Add role badges
  - Implement remove member action (if permitted)
  - _Requirements: Team management_

- [ ] 6.3 Create InviteMemberModal component
  - Create `src/features/dashboard/components/InviteMemberModal.tsx`
  - Implement form with email and role fields
  - Use useInviteTeamMember hook
  - Validate email format
  - Show success message with invitation sent
  - _Requirements: Team management_

## 7. Alerts Management

- [ ] 7.1 Create AlertsTab component
  - Create `src/features/dashboard/components/AlertsTab.tsx`
  - Use useAlerts hook with filters
  - Implement filters: status, severity, date range
  - Display alerts list
  - Add "Resolve All" button for bulk actions
  - _Requirements: Alerts management_

- [ ] 7.2 Create AlertsList component
  - Create `src/features/dashboard/components/AlertsList.tsx`
  - Display alerts with severity badges
  - Show alert type icons
  - Implement click to open detail drawer
  - Add quick resolve button
  - Group by severity
  - _Requirements: Alerts management_

- [ ] 7.3 Create AlertDetailDrawer component
  - Create `src/features/dashboard/components/AlertDetailDrawer.tsx`
  - Use useAlert hook
  - Display full alert details
  - Show alert timeline
  - Add resolve button with notes field
  - Implement slide-in animation
  - _Requirements: Alerts management_

- [ ] 7.4 Implement alert resolution
  - Use useResolveAlert hook with optimistic updates
  - Update alert status immediately in UI
  - Show success toast
  - Refresh alerts list
  - _Requirements: Alerts management_

## 8. Social Protection Overview

- [ ] 8.1 Create SocialProtectionOverviewPanel component
  - Create `src/features/dashboard/components/SocialProtectionOverviewPanel.tsx`
  - Use useSocialProtectionOverview hook
  - Display metrics summary
  - Add project filter dropdown (optional)
  - Show loading skeleton
  - _Requirements: Social Protection overview_

- [ ] 8.2 Create ExtensionStatusCard component
  - Create `src/features/dashboard/components/ExtensionStatusCard.tsx`
  - Use useExtensionStatus hook
  - Display connection status badge (Connected/Disconnected)
  - Show last activity timestamp
  - Display features by plan
  - Add "View Analytics" link
  - Show "Install Extension" CTA if disconnected
  - _Requirements: Extension monitoring_

- [ ] 8.3 Create ExtensionAnalyticsPanel component
  - Create `src/features/dashboard/components/ExtensionAnalyticsPanel.tsx`
  - Use useExtensionAnalytics hook
  - Implement time range selector (1h, 24h, 7d, 30d)
  - Display analytics chart with platform breakdown
  - Show protection count metrics
  - Add export data button
  - _Requirements: Extension analytics_

- [ ] 8.4 Create AlgorithmHealthPanel component
  - Create `src/features/dashboard/components/AlgorithmHealthPanel.tsx`
  - Use useAlgorithmHealth hook
  - Display mini cards for Visibility, Engagement, Penalties
  - Show trend arrows (up/down/stable)
  - Add "Run Analysis" buttons for each metric
  - Display health badge (Good/Warning/Critical)
  - Add link to full analysis view
  - _Requirements: Algorithm health_

- [ ] 8.5 Implement algorithm health analyses
  - Use useAnalyzeVisibility, useAnalyzeEngagement, useDetectPenalties hooks
  - Show processing status during analysis
  - Display results in modal or navigate to results page
  - Handle errors gracefully
  - _Requirements: Algorithm health_

- [ ] 8.6 Create BatchAnalysisButton component (Plan-gated)
  - Create `src/features/dashboard/components/BatchAnalysisButton.tsx`
  - Check user's subscription plan
  - Show button only for Pro+ plans
  - Show "Upgrade to Pro" CTA for Free/Basic plans
  - Use useBatchAnalyze hook
  - Display batch analysis form modal
  - _Requirements: Algorithm health batch analysis_

- [ ] 8.7 Create CrisisAlertsPanel component
  - Create `src/features/dashboard/components/CrisisAlertsPanel.tsx`
  - Use useCrisisAlerts hook
  - Display severity distribution chart
  - Show crisis alerts list
  - Add quick resolve actions
  - Implement "View Recommendations" button
  - _Requirements: Crisis alerts_

- [ ] 8.8 Create CrisisRecommendationsDrawer component
  - Create `src/features/dashboard/components/CrisisRecommendationsDrawer.tsx`
  - Use useCrisisRecommendations hook
  - Display recommendations list
  - Show priority badges
  - Add action buttons for each recommendation
  - _Requirements: Crisis alerts_

- [ ] 8.9 Create CrisisStatsChart component
  - Create `src/features/dashboard/components/CrisisStatsChart.tsx`
  - Use useCrisisStats hook
  - Implement time range selector
  - Display line chart showing crisis trends
  - Show breakdown by type
  - _Requirements: Crisis alerts_

- [ ] 8.10 Create BotHealthBadge component
  - Create `src/features/dashboard/components/BotHealthBadge.tsx`
  - Use useBotHealth hook
  - Display health status badge (Healthy/Degraded/Down)
  - Show service names and statuses
  - Add link to detailed logs (if available)
  - Auto-refresh every 5 minutes
  - _Requirements: Bot/webhook health_

## 9. Subscription Integration

- [ ] 9.1 Create SubscriptionPlanCard component
  - Create `src/features/dashboard/components/SubscriptionPlanCard.tsx`
  - Fetch subscription data from subscriptions API
  - Display current plan name and price
  - Show usage bar with percentage
  - Display renewal/cancel state
  - Add "Upgrade" button linking to subscriptions page
  - Show warning if usage > 80%
  - _Requirements: Subscription integration_

## 10. Plan-Based Feature Gating

- [ ] 10.1 Create feature gating utility
  - Create `src/features/dashboard/utils/feature-gating.ts`
  - Implement hasFeatureAccess(feature, plan) function
  - Define feature requirements per plan
  - Export feature flags constants
  - _Requirements: Feature gating_

- [ ] 10.2 Create UpgradeCTA component
  - Create `src/features/dashboard/components/UpgradeCTA.tsx`
  - Display upgrade message with benefits
  - Show plan comparison
  - Add "Upgrade Now" button
  - Implement different variants (banner, modal, inline)
  - _Requirements: Feature gating_

- [ ] 10.3 Implement feature gating in components
  - Wrap gated features with feature check
  - Show UpgradeCTA for unavailable features
  - Disable buttons for gated actions
  - Add tooltips explaining plan requirements
  - _Requirements: Feature gating_

## 11. Shared Components

- [ ] 11.1 Create StatusBadge component
  - Create `src/features/dashboard/components/StatusBadge.tsx`
  - Implement color-coded badges for different statuses
  - Support variants: success, warning, error, info
  - Add icons
  - _Requirements: All dashboard features_

- [ ] 11.2 Create TrendIndicator component
  - Create `src/features/dashboard/components/TrendIndicator.tsx`
  - Display trend arrows (up/down/stable)
  - Show percentage change
  - Color code based on positive/negative trend
  - _Requirements: Dashboard overview, algorithm health_

- [ ] 11.3 Create EmptyState component
  - Create `src/features/dashboard/components/EmptyState.tsx`
  - Display when no data available
  - Show relevant icon and message
  - Add action button (e.g., "Create Project")
  - _Requirements: All dashboard features_

- [ ] 11.4 Create LoadingSkeleton components
  - Create `src/features/dashboard/components/LoadingSkeleton.tsx`
  - Implement skeletons for: cards, tables, charts, lists
  - Match actual component layouts
  - _Requirements: All dashboard features_

## 12. Error Handling

- [ ] 12.1 Create error handling utilities
  - Create `src/features/dashboard/utils/error-handling.ts`
  - Implement error message mapping
  - Create error toast helper
  - Handle network errors
  - Handle authentication errors (401 → redirect to login)
  - _Requirements: All dashboard features_

- [ ] 12.2 Implement error boundaries
  - Create `src/features/dashboard/components/DashboardErrorBoundary.tsx`
  - Catch and display component errors
  - Provide retry functionality
  - Log errors for debugging
  - _Requirements: All dashboard features_

## 13. Testing

- [ ] 13.1 Write unit tests for API client
  - Test all API methods
  - Mock axios responses
  - Test error handling
  - _Requirements: All dashboard features_

- [ ] 13.2 Write unit tests for hooks
  - Test React Query hooks
  - Test optimistic updates
  - Test cache invalidation
  - _Requirements: All dashboard features_

- [ ] 13.3 Write component tests
  - Test rendering with different data states
  - Test user interactions
  - Test form submissions
  - Test error states
  - _Requirements: All dashboard features_

- [ ] 13.4 Write integration tests
  - Test complete workflows (create project, invite member, resolve alert)
  - Test navigation between pages
  - Test feature gating
  - _Requirements: All dashboard features_

- [ ] 13.5 Write E2E tests
  - Test dashboard overview loading
  - Test project CRUD operations
  - Test team invitation flow
  - Test alert resolution
  - Test Social Protection features
  - _Requirements: All dashboard features_

## 14. Accessibility

- [ ] 14.1 Implement keyboard navigation
  - Ensure all interactive elements are keyboard accessible
  - Implement logical tab order
  - Add keyboard shortcuts for common actions
  - Test with keyboard only
  - _Requirements: All dashboard features_

- [ ] 14.2 Add ARIA labels and roles
  - Add proper ARIA labels to all components
  - Implement ARIA live regions for dynamic updates
  - Add screen reader descriptions
  - Test with screen readers (NVDA/JAWS)
  - _Requirements: All dashboard features_

- [ ] 14.3 Ensure color accessibility
  - Use WCAG AA compliant color contrast
  - Don't rely solely on color for information
  - Add patterns or icons in addition to colors
  - Test with color blindness simulators
  - _Requirements: All dashboard features_

## 15. Performance Optimization

- [ ] 15.1 Implement code splitting
  - Lazy load dashboard pages
  - Lazy load heavy components (charts, analytics)
  - Use React.lazy and Suspense
  - _Requirements: All dashboard features_

- [ ] 15.2 Optimize data fetching
  - Implement proper caching strategies
  - Use staleTime and cacheTime appropriately
  - Prefetch data for likely navigation
  - Cancel requests on unmount
  - _Requirements: All dashboard features_

- [ ] 15.3 Optimize rendering
  - Memoize expensive computations
  - Use React.memo for pure components
  - Implement virtual scrolling for long lists
  - Debounce search inputs
  - _Requirements: All dashboard features_

## 16. Documentation

- [ ] 16.1 Add component documentation
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - Document feature gating logic
  - _Requirements: All dashboard features_

- [ ] 16.2 Create user documentation
  - Document dashboard features
  - Create user guide for projects management
  - Document Social Protection features
  - Create troubleshooting guide
  - _Requirements: All dashboard features_