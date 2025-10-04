# Design Document

## Overview

The Community Reports feature provides a collaborative security platform where users can submit, view, and vote on security reports. The design emphasizes ease of reporting, clear visualization of threat information, and community-driven validation through voting.

## Architecture

### Component Hierarchy

```
ReportsLayout
├── SubmitReportPage
│   ├── ReportForm
│   ├── TemplateSelector
│   └── EvidenceUploader
├── ReportsListPage
│   ├── ReportsFilters
│   ├── ReportsTable
│   └── ReportsPagination
├── ReportDetailPage
│   ├── ReportSummary
│   ├── EvidenceSection
│   ├── VotingPanel
│   └── ModerationStatus
└── ReportsStatsPage
    └── StatsCharts
```

## Components and Interfaces

### Data Models

```typescript
interface Report {
  id: string;
  url: string;
  domain: string;
  report_type: ReportType;
  title: string;
  description: string;
  evidence: Evidence[];
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'PENDING' | 'VERIFIED' | 'DISMISSED' | 'INVESTIGATING';
  votes: {
    helpful: number;
    not_helpful: number;
    user_vote?: 'helpful' | 'not_helpful';
  };
  tags: string[];
  reporter_id?: string;
  created_at: string;
  updated_at: string;
  moderation_notes?: string;
}

type ReportType = 'PHISHING' | 'MALWARE' | 'SPAM' | 'SCAM' | 'INAPPROPRIATE' | 'COPYRIGHT' | 'OTHER';

interface Evidence {
  type: 'screenshot' | 'url' | 'text' | 'file';
  content: string;
  description?: string;
}

interface ReportTemplate {
  id: string;
  report_type: ReportType;
  title: string;
  description_template: string;
  evidence_checklist: string[];
}

interface ReportStats {
  total_reports: number;
  pending: number;
  verified: number;
  dismissed: number;
  type_distribution: { type: string; count: number }[];
  priority_distribution: { priority: string; count: number }[];
  trends: { date: string; count: number }[];
  top_domains: { domain: string; count: number }[];
}
```

### State Management

```typescript
// Submit Report
const useSubmitReport = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: ReportFormData) => reportsAPI.submitReport(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
  });
};

// List Reports
const useReports = (filters: ReportsFilters) => {
  return useQuery({
    queryKey: ['reports', filters],
    queryFn: () => reportsAPI.getReports(filters),
    keepPreviousData: true,
  });
};

// Report Detail
const useReport = (reportId: string) => {
  return useQuery({
    queryKey: ['report', reportId],
    queryFn: () => reportsAPI.getReport(reportId),
  });
};

// Vote on Report
const useVoteReport = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ reportId, voteType }: { reportId: string; voteType: string }) =>
      reportsAPI.voteReport(reportId, voteType),
    onSuccess: (_, { reportId }) => {
      queryClient.invalidateQueries({ queryKey: ['report', reportId] });
    },
  });
};

// Templates
const useReportTemplates = () => {
  return useQuery({
    queryKey: ['report-templates'],
    queryFn: reportsAPI.getTemplates,
    staleTime: 10 * 60 * 1000, // 10 minutes
  });
};

// Stats
const useReportStats = () => {
  return useQuery({
    queryKey: ['report-stats'],
    queryFn: reportsAPI.getStats,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};
```

## API Client

```typescript
export const reportsAPI = {
  submitReport: async (data: ReportFormData): Promise<Report> => {
    const response = await apiClient.post('/reports/', data);
    return response.data;
  },
  
  getReports: async (filters: ReportsFilters): Promise<ReportsResponse> => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined) params.append(key, String(value));
    });
    const response = await apiClient.get(`/reports/?${params}`);
    return response.data;
  },
  
  getReport: async (reportId: string): Promise<Report> => {
    const response = await apiClient.get(`/reports/${reportId}`);
    return response.data;
  },
  
  voteReport: async (reportId: string, voteType: string): Promise<void> => {
    await apiClient.post(`/reports/${reportId}/vote`, { vote_type: voteType });
  },
  
  getTemplates: async (): Promise<ReportTemplate[]> => {
    const response = await apiClient.get('/reports/templates/');
    return response.data;
  },
  
  getStats: async (): Promise<ReportStats> => {
    const response = await apiClient.get('/reports/stats/overview');
    return response.data;
  },
};
```

## UI/UX Design

### Report Type Badges

```typescript
const getReportTypeConfig = (type: ReportType) => {
  const config = {
    PHISHING: { color: 'red', icon: 'fish', label: 'Phishing' },
    MALWARE: { color: 'purple', icon: 'bug', label: 'Malware' },
    SPAM: { color: 'yellow', icon: 'mail', label: 'Spam' },
    SCAM: { color: 'orange', icon: 'alert-triangle', label: 'Scam' },
    INAPPROPRIATE: { color: 'pink', icon: 'eye-off', label: 'Inappropriate' },
    COPYRIGHT: { color: 'blue', icon: 'copyright', label: 'Copyright' },
    OTHER: { color: 'gray', icon: 'help-circle', label: 'Other' },
  };
  return config[type];
};
```

### Priority Badges

```typescript
const getPriorityConfig = (priority: string) => {
  const config = {
    LOW: { color: 'green', label: 'Low Priority' },
    MEDIUM: { color: 'yellow', label: 'Medium Priority' },
    HIGH: { color: 'orange', label: 'High Priority' },
    CRITICAL: { color: 'red', label: 'Critical' },
  };
  return config[priority];
};
```

## Testing Strategy

### Unit Tests
- Form validation
- Vote logic
- Template selection
- Filter logic

### Integration Tests
- Submit report flow
- View and filter reports
- Vote on report
- Use template

### E2E Tests
- Complete report submission
- Browse and filter reports
- Vote and see updates
- View statistics

## Accessibility

- Forms with proper labels
- Vote buttons with ARIA labels
- Report types with descriptions
- Charts with text alternatives
- Keyboard navigation

## Performance

- Cached templates (10 minutes)
- Cached stats (5 minutes)
- Optimistic vote updates
- Debounced search (300ms)
- Pagination with keepPreviousData
