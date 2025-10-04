# Implementation Plan

## 1. Project Setup

- [ ] 1.1 Create URL analysis module structure
  - Create `src/features/url-analysis` directory with subdirectories: `components`, `hooks`, `api`, `types`, `utils`, `pages`
  - Set up barrel exports in index files
  - _Requirements: All URL analysis requirements_

- [ ] 1.2 Create TypeScript interfaces
  - Create `src/features/url-analysis/types/index.ts`
  - Define UrlCheck, UrlCheckDetail, ScanResult, BrokenLink interfaces
  - Define HistoryFilters, BulkAnalysisFormData, BulkAnalysisResult interfaces
  - Define DomainReputation, UrlCheckStats interfaces
  - Define ThreatLevel and CheckStatus enums
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

## 2. API Integration

- [ ] 2.1 Implement history API methods
  - Create `src/features/url-analysis/api/url-analysis-api.ts`
  - Implement getHistory(filters): Promise<UrlHistoryResponse>
  - Handle query parameter building for filters
  - _Requirements: 1.1_

- [ ] 2.2 Implement check detail API methods
  - Add getCheckDetail(checkId): Promise<UrlCheckDetail>
  - Add getScanResults(checkId): Promise<ScanResult[]>
  - Add getBrokenLinks(checkId): Promise<BrokenLink[]>
  - _Requirements: 1.2_

- [ ] 2.3 Implement bulk analysis API method
  - Add bulkCheck(data): Promise<BulkAnalysisResult>
  - Handle progress tracking if supported by backend
  - _Requirements: 1.3_

- [ ] 2.4 Implement reputation and stats API methods
  - Add getDomainReputation(domain): Promise<DomainReputation>
  - Add getStats(days): Promise<UrlCheckStats>
  - _Requirements: 1.4, 1.5_

## 3. React Query Hooks

- [ ] 3.1 Create history hooks
  - Create `src/features/url-analysis/hooks/use-url-history.ts`
  - Implement useUrlHistory hook with filters parameter
  - Enable keepPreviousData for smooth pagination
  - _Requirements: 1.1_

- [ ] 3.2 Create check detail hooks
  - Create `src/features/url-analysis/hooks/use-check-detail.ts`
  - Implement useCheckDetail hook
  - Implement useScanResults hook
  - Implement useBrokenLinks hook with enabled: false (lazy load)
  - _Requirements: 1.2_

- [ ] 3.3 Create bulk analysis hook
  - Create `src/features/url-analysis/hooks/use-bulk-analysis.ts`
  - Implement useBulkAnalysis mutation hook
  - Handle progress updates
  - _Requirements: 1.3_

- [ ] 3.4 Create reputation and stats hooks
  - Create `src/features/url-analysis/hooks/use-reputation.ts`
  - Implement useDomainReputation hook
  - Create `src/features/url-analysis/hooks/use-stats.ts`
  - Implement useUrlCheckStats hook with 5-minute stale time
  - _Requirements: 1.4, 1.5_

## 4. URL History Feature

- [ ] 4.1 Create UrlHistoryPage component
  - Create `src/features/url-analysis/pages/UrlHistoryPage.tsx`
  - Implement page layout with filters, table, and pagination
  - Use useUrlHistory hook
  - Handle loading and error states
  - _Requirements: 1.1_

- [ ] 4.2 Create HistoryFilters component
  - Create `src/features/url-analysis/components/HistoryFilters.tsx`
  - Implement domain search input with debounce (300ms)
  - Add threat level dropdown
  - Add status dropdown
  - Add date range picker
  - Add reset filters button
  - Persist filters in URL query params
  - _Requirements: 1.1_

- [ ] 4.3 Create UrlHistoryTable component
  - Create `src/features/url-analysis/components/UrlHistoryTable.tsx`
  - Display columns: URL, domain, threat level, risk score, status, checked date, actions
  - Implement row click to navigate to detail page
  - Add threat level badges with colors
  - Truncate long URLs with tooltip
  - _Requirements: 1.1_

- [ ] 4.4 Implement pagination
  - Create pagination controls component
  - Handle page and page_size parameters
  - Display total count and current range
  - Add page size selector (20, 50, 100)
  - _Requirements: 1.1_

- [ ] 4.5 Implement empty state
  - Create empty state component for no results
  - Display different messages for filtered vs no checks
  - Add "Clear filters" action for filtered empty state
  - _Requirements: 1.1_

## 5. Check Detail Feature

- [ ] 5.1 Create CheckDetailPage component
  - Create `src/features/url-analysis/pages/CheckDetailPage.tsx`
  - Use useCheckDetail, useScanResults, useBrokenLinks hooks
  - Implement tabs: Overview, Provider Results, Broken Links
  - Handle loading and error states
  - _Requirements: 1.2_

- [ ] 5.2 Create CheckSummary component
  - Create `src/features/url-analysis/components/CheckSummary.tsx`
  - Display URL, domain, threat level, risk score
  - Show scan type and timestamps
  - Display status with appropriate styling
  - Add back to history button
  - _Requirements: 1.2_

- [ ] 5.3 Create ProviderResults component
  - Create `src/features/url-analysis/components/ProviderResults.tsx`
  - Implement accordion for each provider (VirusTotal, Google Safe Browsing, URLVoid)
  - Display threat detected status, threat types, confidence score
  - Show detailed findings in expandable sections
  - Handle missing provider data gracefully
  - _Requirements: 1.2_

- [ ] 5.4 Create BrokenLinksTab component
  - Create `src/features/url-analysis/components/BrokenLinksTab.tsx`
  - Display table with URL, status code, error message, depth
  - Lazy load data when tab is opened
  - Show empty state if no broken links
  - Add export broken links option
  - _Requirements: 1.2_

## 6. Bulk Analysis Feature

- [ ] 6.1 Create BulkAnalysisPage component
  - Create `src/features/url-analysis/pages/BulkAnalysisPage.tsx`
  - Implement input form and results display
  - Use useBulkAnalysis hook
  - Handle different states: input, analyzing, results
  - _Requirements: 1.3_

- [ ] 6.2 Create BulkInputForm component
  - Create `src/features/url-analysis/components/BulkInputForm.tsx`
  - Add textarea input (one URL per line)
  - Add file upload option (txt, csv)
  - Validate URLs before submission
  - Display URL count and plan limit
  - Show validation errors inline
  - _Requirements: 1.3_

- [ ] 6.3 Implement URL validation
  - Create validation utility for URL format
  - Check for duplicate URLs
  - Validate against plan limits (Free: 10, Pro: 50, Enterprise: 100)
  - Display validation errors with specific messages
  - _Requirements: 1.3_

- [ ] 6.4 Create ProgressIndicator component
  - Create `src/features/url-analysis/components/ProgressIndicator.tsx`
  - Display progress bar showing X of Y URLs analyzed
  - Show real-time status updates
  - Add cancel analysis option if supported
  - _Requirements: 1.3_

- [ ] 6.5 Create BulkResultsTable component
  - Create `src/features/url-analysis/components/BulkResultsTable.tsx`
  - Display summary cards: total, safe, suspicious, malicious, errors
  - Show results table with URL, threat level, view details link
  - Add export results option
  - Add "Analyze More URLs" button
  - _Requirements: 1.3_

## 7. Reputation Lookup Feature

- [ ] 7.1 Create ReputationLookupPage component
  - Create `src/features/url-analysis/pages/ReputationLookupPage.tsx`
  - Implement domain input and results display
  - Use useDomainReputation hook
  - Handle loading and error states
  - _Requirements: 1.4_

- [ ] 7.2 Create DomainInput component
  - Create `src/features/url-analysis/components/DomainInput.tsx`
  - Add domain input field with validation
  - Validate domain format
  - Add lookup button
  - Show recent lookups list
  - _Requirements: 1.4_

- [ ] 7.3 Create ReputationPanel component
  - Create `src/features/url-analysis/components/ReputationPanel.tsx`
  - Display reputation score with visual indicator
  - Show trust level badge
  - Display check statistics (total, safe, malicious)
  - Show historical data chart
  - Display community reports count with link
  - Handle no data state
  - _Requirements: 1.4_

## 8. Statistics Feature

- [ ] 8.1 Create StatsPage component
  - Create `src/features/url-analysis/pages/StatsPage.tsx`
  - Implement time range selector (7d, 30d, 90d, 365d)
  - Use useUrlCheckStats hook
  - Display charts and metrics
  - _Requirements: 1.5_

- [ ] 8.2 Create StatsOverview component
  - Create `src/features/url-analysis/components/StatsOverview.tsx`
  - Display metric cards: total checks, safe, suspicious, malicious
  - Show percentage changes from previous period
  - Add plan usage progress bar
  - Display warning if approaching limit
  - _Requirements: 1.5_

- [ ] 8.3 Create StatsCharts component
  - Create `src/features/url-analysis/components/StatsCharts.tsx`
  - Implement line chart for checks over time
  - Implement pie chart for threat distribution
  - Implement bar chart for scan type distribution
  - Use charting library (recharts or chart.js)
  - Add chart legends and tooltips
  - _Requirements: 1.5_

## 9. Export Functionality

- [ ] 9.1 Create export utility
  - Create `src/features/url-analysis/utils/export.ts`
  - Implement exportToCSV function
  - Implement exportToJSON function
  - Handle large datasets efficiently
  - _Requirements: 1.6_

- [ ] 9.2 Create ExportModal component
  - Create `src/features/url-analysis/components/ExportModal.tsx`
  - Display format options (CSV, JSON)
  - Add date range selector
  - Show estimated file size
  - Add export button with loading state
  - _Requirements: 1.6_

- [ ] 9.3 Implement export triggers
  - Add export button to history page
  - Add export button to bulk results
  - Add export button to broken links tab
  - Trigger file download on export complete
  - _Requirements: 1.6_

## 10. Shared Components

- [ ] 10.1 Create ThreatLevelBadge component
  - Create `src/features/url-analysis/components/ThreatLevelBadge.tsx`
  - Implement color-coded badges (green, yellow, red, gray)
  - Add icons for each threat level
  - Ensure accessibility with ARIA labels
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 10.2 Create RiskScoreDisplay component
  - Create `src/features/url-analysis/components/RiskScoreDisplay.tsx`
  - Display risk score (0-100) with color coding
  - Add progress bar visualization
  - Show risk level label (Low, Medium, High, Critical)
  - _Requirements: 1.1, 1.2_

- [ ] 10.3 Create LoadingStates components
  - Create skeleton loaders for tables
  - Create skeleton loaders for charts
  - Create loading spinners for actions
  - _Requirements: All requirements_

## 11. Error Handling

- [ ] 11.1 Create error message mapping
  - Create `src/features/url-analysis/utils/error-messages.ts`
  - Map all error codes to user-friendly messages
  - Include dynamic values (limits, retry times)
  - _Requirements: All requirements_

- [ ] 11.2 Implement error display
  - Show inline errors for form validation
  - Show toast notifications for API errors
  - Display error states in tables and charts
  - Add retry buttons for failed requests
  - _Requirements: All requirements_

- [ ] 11.3 Handle plan limit errors
  - Display upgrade CTA when limits reached
  - Show current plan and limits
  - Link to subscriptions page
  - _Requirements: 1.3, 1.5_

## 12. Testing

- [ ] 12.1 Write unit tests
  - Test filter logic and URL validation
  - Test threat level badge rendering
  - Test risk score calculations
  - Test export utilities
  - Test date formatting
  - _Requirements: All requirements_

- [ ] 12.2 Write integration tests
  - Test history page with filters and pagination
  - Test check detail page with provider results
  - Test bulk analysis flow
  - Test reputation lookup
  - Test stats page with charts
  - _Requirements: All requirements_

- [ ] 12.3 Write E2E tests
  - Test complete URL analysis workflow
  - Test filter and search history
  - Test view detailed results
  - Test perform bulk analysis
  - Test export history data
  - _Requirements: All requirements_

## 13. Accessibility

- [ ] 13.1 Implement keyboard navigation
  - Ensure all filters are keyboard accessible
  - Implement table keyboard navigation
  - Add keyboard shortcuts for common actions
  - Test with keyboard only
  - _Requirements: All requirements_

- [ ] 13.2 Add ARIA labels and roles
  - Add proper table headers and structure
  - Add ARIA labels to charts
  - Implement aria-live regions for updates
  - Add screen reader descriptions
  - _Requirements: All requirements_

- [ ] 13.3 Ensure color accessibility
  - Use color-blind friendly palette
  - Don't rely solely on color for threat levels
  - Add patterns or icons in addition to colors
  - Test with color blindness simulators
  - _Requirements: All requirements_

## 14. Performance Optimization

- [ ] 14.1 Implement virtual scrolling
  - Add virtual scrolling to history table for large datasets
  - Use react-window or similar library
  - _Requirements: 1.1_

- [ ] 14.2 Optimize filtering and search
  - Debounce search inputs (300ms)
  - Implement client-side filtering for small datasets
  - Cache filter results
  - _Requirements: 1.1_

- [ ] 14.3 Optimize chart rendering
  - Memoize chart data transformations
  - Lazy load charts when visible
  - Use canvas-based charts for large datasets
  - _Requirements: 1.5_

## 15. Documentation

- [ ] 15.1 Add component documentation
  - Add JSDoc comments to all components
  - Document props interfaces
  - Add usage examples
  - _Requirements: All requirements_

- [ ] 15.2 Create user documentation
  - Document how to use filters
  - Document bulk analysis process
  - Document export functionality
  - Create troubleshooting guide
  - _Requirements: All requirements_
