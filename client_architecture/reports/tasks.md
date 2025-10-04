# Implementation Plan

## 1. Project Setup

- [ ] 1.1 Create reports module structure
  - Create `src/features/reports` directory with subdirectories
  - Set up barrel exports
  - _Requirements: All reports requirements_

- [ ] 1.2 Create TypeScript interfaces
  - Define Report, Evidence, ReportTemplate, ReportStats interfaces
  - Define ReportType enum and filters
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

## 2. API Integration

- [ ] 2.1 Implement reports API methods
  - Create `src/features/reports/api/reports-api.ts`
  - Implement submitReport, getReports, getReport methods
  - Implement voteReport, getTemplates, getStats methods
  - _Requirements: All requirements_

- [ ] 2.2 Create React Query hooks
  - Implement useSubmitReport mutation hook
  - Implement useReports query hook with filters
  - Implement useReport, useVoteReport hooks
  - Implement useReportTemplates, useReportStats hooks
  - _Requirements: All requirements_

## 3. Submit Report Feature

- [ ] 3.1 Create SubmitReportPage component
  - Create page layout with form and template selector
  - Use useSubmitReport and useReportTemplates hooks
  - Handle success and error states
  - _Requirements: 1.1, 1.5_

- [ ] 3.2 Create ReportForm component
  - Add URL input with validation
  - Add report type selector
  - Add title and description fields
  - Add evidence section
  - Implement form validation with Zod
  - _Requirements: 1.1_

- [ ] 3.3 Create TemplateSelector component
  - Display templates by report type
  - Allow template selection
  - Pre-fill form with template content
  - _Requirements: 1.5_

- [ ] 3.4 Create EvidenceUploader component
  - Support multiple evidence types
  - Add file upload functionality
  - Display evidence checklist
  - _Requirements: 1.1_

## 4. Reports List Feature

- [ ] 4.1 Create ReportsListPage component
  - Implement filters, table, and pagination
  - Use useReports hook
  - Handle loading and error states
  - _Requirements: 1.2_

- [ ] 4.2 Create ReportsFilters component
  - Add report type filter
  - Add status, priority, domain filters
  - Add date range picker
  - Persist filters in URL
  - _Requirements: 1.2_

- [ ] 4.3 Create ReportsTable component
  - Display columns: URL, type, priority, status, votes, date
  - Add type and priority badges
  - Implement row click navigation
  - Show empty state
  - _Requirements: 1.2_

## 5. Report Detail Feature

- [ ] 5.1 Create ReportDetailPage component
  - Use useReport hook
  - Display complete report information
  - Show voting panel
  - _Requirements: 1.3, 1.4_

- [ ] 5.2 Create ReportSummary component
  - Display URL, type, priority, status
  - Show title and description
  - Display metadata
  - _Requirements: 1.3_

- [ ] 5.3 Create EvidenceSection component
  - Display all evidence items
  - Support different evidence types
  - Show evidence descriptions
  - _Requirements: 1.3_

- [ ] 5.4 Create VotingPanel component
  - Display vote buttons (Helpful, Not Helpful)
  - Show vote counts
  - Highlight user's vote
  - Use useVoteReport hook
  - Implement optimistic updates
  - _Requirements: 1.4_

- [ ] 5.5 Create ModerationStatus component
  - Display moderation status badge
  - Show moderation notes
  - Display verified/dismissed badges
  - _Requirements: 1.3_

## 6. Statistics Feature

- [ ] 6.1 Create ReportsStatsPage component
  - Use useReportStats hook
  - Display stats overview and charts
  - _Requirements: 1.6_

- [ ] 6.2 Create StatsCharts component
  - Implement pie chart for type distribution
  - Implement bar chart for priority distribution
  - Implement line chart for trends
  - Display top domains list
  - _Requirements: 1.6_

## 7. Shared Components

- [ ] 7.1 Create ReportTypeBadge component
  - Implement color-coded badges with icons
  - Ensure accessibility
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 7.2 Create PriorityBadge component
  - Implement priority badges
  - Add color coding
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 7.3 Create StatusBadge component
  - Display status badges
  - Add appropriate colors
  - _Requirements: 1.2, 1.3_

## 8. Error Handling and Testing

- [ ] 8.1 Implement error handling
  - Create error message mapping
  - Handle duplicate reports
  - Handle validation errors
  - _Requirements: All requirements_

- [ ] 8.2 Write tests
  - Unit tests for form validation
  - Integration tests for submit and vote flows
  - E2E tests for complete workflows
  - _Requirements: All requirements_

## 9. Accessibility and Documentation

- [ ] 9.1 Implement accessibility
  - Keyboard navigation
  - ARIA labels
  - Screen reader support
  - _Requirements: All requirements_

- [ ] 9.2 Create documentation
  - Component documentation
  - User guide
  - _Requirements: All requirements_
