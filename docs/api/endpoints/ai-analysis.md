# AI-Powered Content Analysis Endpoints

LinkShield's AI analysis system provides comprehensive content analysis capabilities including quality scoring, topic classification, sentiment analysis, and threat detection. This guide covers all AI analysis endpoints, analysis types, processing workflows, and integration patterns.

## Overview

The AI analysis system performs intelligent content evaluation using machine learning models:

- **Content Quality Scoring**: Comprehensive quality metrics and readability analysis
- **Topic Classification**: Automatic categorization and keyword extraction
- **Sentiment Analysis**: Emotional tone and sentiment scoring
- **Threat Detection**: AI-powered phishing and malware detection
- **Content Similarity**: Vector-based similarity matching and duplicate detection
- **SEO Analysis**: Search engine optimization metrics and recommendations

## Base URL

```
https://api.linkshield.com/api/v1/ai-analysis
```

## Authentication

AI analysis endpoints support multiple authentication methods:

- **JWT Token**: `Authorization: Bearer <token>` (recommended for web apps)
- **API Key**: `X-API-Key: <api_key>` (recommended for server integrations)
- **Anonymous**: Limited functionality for public content analysis

## Analysis Types

The system supports the following analysis types:

| Type | Description | Processing Time | Model Used |
|------|-------------|-----------------|------------|
| `CONTENT_SUMMARY` | Generate concise content summaries | ~2-5s | GPT-4 Turbo |
| `QUALITY_SCORING` | Comprehensive quality metrics | ~1-3s | Custom ML Model |
| `TOPIC_CLASSIFICATION` | Categorize content by topics | ~1-2s | BERT-based Classifier |
| `CONTENT_SIMILARITY` | Vector-based similarity matching | ~0.5-1s | Sentence Transformers |
| `LANGUAGE_DETECTION` | Detect content language | ~0.1-0.5s | FastText |
| `SEO_ANALYSIS` | SEO optimization recommendations | ~2-4s | Custom Analyzer |
| `SENTIMENT_ANALYSIS` | Emotional tone analysis | ~1-2s | RoBERTa Sentiment |
| `THREAT_ANALYSIS` | Phishing and malware detection | ~3-6s | Ensemble Model |

## Processing Status

AI analyses follow a structured processing workflow:

```
PENDING → PROCESSING → [COMPLETED/FAILED] → [CACHED]
```

| Status | Description | Typical Duration |
|--------|-------------|------------------|
| `PENDING` | Queued for processing | 0-30s |
| `PROCESSING` | Currently being analyzed | 1-10s |
| `COMPLETED` | Analysis completed successfully | N/A |
| `FAILED` | Analysis failed with error | N/A |
| `CACHED` | Results served from cache | <100ms |

## Endpoints

### 1. Analyze Content

Perform comprehensive AI analysis on web content.

**Endpoint:** `POST /analyze`

**Authentication:** Optional (enhanced features with authentication)

**Rate Limit:** 10 requests per minute

**Request Body:**
```json
{
  "url": "https://example.com/article",
  "content": "<html><body><h1>Article Title</h1><p>Article content goes here...</p></body></html>",
  "analysis_types": [
    "CONTENT_SUMMARY",
    "QUALITY_SCORING",
    "TOPIC_CLASSIFICATION",
    "SENTIMENT_ANALYSIS"
  ]
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Source URL of the content |
| `content` | string | Yes | HTML or text content to analyze (10-50,000 chars) |
| `analysis_types` | array | No | Specific analysis types to perform (default: all) |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com/article",
  "domain": "example.com",
  "content_summary": "This article discusses the latest developments in artificial intelligence and machine learning, focusing on practical applications in business environments.",
  "quality_metrics": {
    "grammar_score": 95,
    "coherence_score": 88,
    "structure_score": 92,
    "originality_score": 85,
    "depth_score": 78
  },
  "topic_categories": {
    "primary_category": "Technology",
    "secondary_categories": ["Artificial Intelligence", "Business", "Innovation"],
    "confidence_scores": {
      "Technology": 0.92,
      "Artificial Intelligence": 0.87,
      "Business": 0.73
    },
    "keywords": [
      {"keyword": "artificial intelligence", "relevance": 0.95, "frequency": 12},
      {"keyword": "machine learning", "relevance": 0.89, "frequency": 8},
      {"keyword": "business applications", "relevance": 0.76, "frequency": 5}
    ]
  },
  "sentiment_analysis": {
    "overall_sentiment": "positive",
    "sentiment_score": 0.72,
    "confidence": 0.89,
    "emotional_tone": {
      "optimism": 0.78,
      "professionalism": 0.85,
      "enthusiasm": 0.65,
      "neutrality": 0.23
    }
  },
  "seo_metrics": {
    "title_optimization": 85,
    "meta_description_score": 78,
    "heading_structure_score": 92,
    "keyword_density": 2.3,
    "readability_score": 88,
    "internal_links": 5,
    "external_links": 12,
    "image_alt_tags": 8
  },
  "content_length": 2847,
  "language": "en",
  "reading_level": "college",
  "overall_quality_score": 87,
  "readability_score": 88,
  "trustworthiness_score": 82,
  "professionalism_score": 91,
  "processing_status": "COMPLETED",
  "processing_time_ms": 3420,
  "created_at": "2024-01-15T10:30:00Z",
  "processed_at": "2024-01-15T10:30:03Z"
}
```

**Status Codes:**
- `201 Created`: Analysis initiated successfully
- `400 Bad Request`: Invalid input data
- `422 Unprocessable Entity`: Content validation errors
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Analysis processing failed

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/ai-analysis/analyze" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/article",
    "content": "<html><body><h1>AI in Business</h1><p>Artificial intelligence is transforming...</p></body></html>",
    "analysis_types": ["CONTENT_SUMMARY", "QUALITY_SCORING", "TOPIC_CLASSIFICATION"]
  }'
```

### 2. Get Analysis Results

Retrieve AI analysis results by analysis ID.

**Endpoint:** `GET /analysis/{analysis_id}`

**Authentication:** Optional (enhanced access with authentication)

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `analysis_id` | UUID | Yes | Analysis ID |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com/article",
  "domain": "example.com",
  "content_summary": "This article discusses the latest developments in artificial intelligence...",
  "quality_metrics": {
    "grammar_score": 95,
    "coherence_score": 88,
    "structure_score": 92,
    "originality_score": 85,
    "depth_score": 78
  },
  "topic_categories": {
    "primary_category": "Technology",
    "secondary_categories": ["Artificial Intelligence", "Business"],
    "confidence_scores": {
      "Technology": 0.92,
      "Artificial Intelligence": 0.87
    }
  },
  "sentiment_analysis": {
    "overall_sentiment": "positive",
    "sentiment_score": 0.72,
    "confidence": 0.89
  },
  "seo_metrics": {
    "title_optimization": 85,
    "meta_description_score": 78,
    "heading_structure_score": 92
  },
  "content_length": 2847,
  "language": "en",
  "reading_level": "college",
  "overall_quality_score": 87,
  "readability_score": 88,
  "trustworthiness_score": 82,
  "professionalism_score": 91,
  "processing_status": "COMPLETED",
  "processing_time_ms": 3420,
  "created_at": "2024-01-15T10:30:00Z",
  "processed_at": "2024-01-15T10:30:03Z"
}
```

**Status Codes:**
- `200 OK`: Analysis retrieved successfully
- `400 Bad Request`: Invalid analysis ID format
- `403 Forbidden`: Access denied to private analysis
- `404 Not Found`: Analysis not found

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/ai-analysis/analysis/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <jwt_token>"
```

### 3. Find Similar Content

Find content similar to the analyzed content using vector similarity.

**Endpoint:** `GET /analysis/{analysis_id}/similar`

**Authentication:** Optional (enhanced results with authentication)

**Rate Limit:** 20 requests per minute

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `similarity_threshold` | float | Minimum similarity score (0.0-1.0, default: 0.8) |
| `limit` | integer | Maximum number of results (1-50, default: 10) |

**Response:**
```json
[
  {
    "id": "789e0123-e89b-12d3-a456-426614174002",
    "target_analysis": {
      "id": "456e7890-e89b-12d3-a456-426614174001",
      "url": "https://similar-site.com/related-article",
      "domain": "similar-site.com",
      "content_summary": "A related article about AI applications in healthcare...",
      "overall_quality_score": 84,
      "processing_status": "COMPLETED",
      "created_at": "2024-01-14T15:20:00Z"
    },
    "similarity_score": 0.87,
    "similarity_type": "semantic",
    "confidence_score": 92,
    "matching_elements": {
      "common_topics": ["artificial intelligence", "machine learning", "healthcare"],
      "semantic_overlap": 0.85,
      "structural_similarity": 0.72,
      "keyword_overlap": 0.68
    }
  },
  {
    "id": "abc1234-e89b-12d3-a456-426614174003",
    "target_analysis": {
      "id": "def5678-e89b-12d3-a456-426614174004",
      "url": "https://another-site.com/ai-trends",
      "domain": "another-site.com",
      "content_summary": "An analysis of current AI trends and future predictions...",
      "overall_quality_score": 79,
      "processing_status": "COMPLETED",
      "created_at": "2024-01-13T09:45:00Z"
    },
    "similarity_score": 0.82,
    "similarity_type": "topical",
    "confidence_score": 88,
    "matching_elements": {
      "common_topics": ["artificial intelligence", "technology trends"],
      "semantic_overlap": 0.79,
      "structural_similarity": 0.65,
      "keyword_overlap": 0.71
    }
  }
]
```

**Status Codes:**
- `200 OK`: Similar content retrieved successfully
- `400 Bad Request`: Invalid analysis ID or parameters
- `403 Forbidden`: Access denied to private analysis
- `404 Not Found`: Analysis not found
- `500 Internal Server Error`: Similarity search failed

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/ai-analysis/analysis/550e8400-e29b-41d4-a716-446655440000/similar?similarity_threshold=0.75&limit=5" \
  -H "Authorization: Bearer <jwt_token>"
```

### 4. Get Analysis History

Retrieve user's AI analysis history with pagination.

**Endpoint:** `GET /history`

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (default: 1) |
| `page_size` | integer | Items per page (1-100, default: 20) |

**Response:**
```json
{
  "analyses": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "url": "https://example.com/article",
      "domain": "example.com",
      "content_summary": "This article discusses the latest developments...",
      "overall_quality_score": 87,
      "processing_status": "COMPLETED",
      "created_at": "2024-01-15T10:30:00Z",
      "processed_at": "2024-01-15T10:30:03Z"
    },
    {
      "id": "456e7890-e89b-12d3-a456-426614174001",
      "url": "https://another-example.com/blog-post",
      "domain": "another-example.com",
      "content_summary": "A comprehensive guide to content marketing...",
      "overall_quality_score": 82,
      "processing_status": "COMPLETED",
      "created_at": "2024-01-14T16:45:00Z",
      "processed_at": "2024-01-14T16:45:04Z"
    }
  ],
  "total_count": 47,
  "page": 1,
  "page_size": 20,
  "has_next": true
}
```

**Status Codes:**
- `200 OK`: History retrieved successfully
- `401 Unauthorized`: Authentication required
- `500 Internal Server Error`: Failed to retrieve history

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/ai-analysis/history?page=1&page_size=10" \
  -H "Authorization: Bearer <jwt_token>"
```

### 5. Get Domain Analysis Statistics

Retrieve analysis statistics for a specific domain.

**Endpoint:** `GET /domain/{domain}/stats`

**Authentication:** Not required

**Rate Limit:** 30 requests per minute

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | Yes | Domain name (e.g., "example.com") |

**Response:**
```json
{
  "domain": "example.com",
  "total_analyses": 156,
  "avg_quality_score": 84.7,
  "avg_trustworthiness_score": 78.3,
  "completed_analyses": 152,
  "success_rate": 97.4,
  "analysis_breakdown": {
    "CONTENT_SUMMARY": 145,
    "QUALITY_SCORING": 156,
    "TOPIC_CLASSIFICATION": 134,
    "SENTIMENT_ANALYSIS": 128,
    "SEO_ANALYSIS": 89,
    "THREAT_ANALYSIS": 156
  },
  "quality_distribution": {
    "excellent": 45,
    "good": 67,
    "average": 32,
    "poor": 8,
    "very_poor": 4
  },
  "common_topics": [
    {"topic": "Technology", "frequency": 89, "avg_score": 87.2},
    {"topic": "Business", "frequency": 67, "avg_score": 82.1},
    {"topic": "Education", "frequency": 34, "avg_score": 85.6}
  ],
  "language_distribution": {
    "en": 142,
    "es": 8,
    "fr": 4,
    "de": 2
  },
  "last_updated": "2024-01-15T18:30:00Z"
}
```

**Status Codes:**
- `200 OK`: Statistics retrieved successfully
- `400 Bad Request`: Invalid domain format
- `500 Internal Server Error`: Failed to retrieve statistics

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/ai-analysis/domain/example.com/stats"
```

### 6. Retry Failed Analysis

Retry a failed AI analysis.

**Endpoint:** `POST /analysis/{analysis_id}/retry`

**Authentication:** Required

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `analysis_id` | UUID | Yes | Analysis ID to retry |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com/article",
  "domain": "example.com",
  "processing_status": "PROCESSING",
  "retry_count": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T11:15:00Z"
}
```

**Status Codes:**
- `200 OK`: Analysis retry initiated successfully
- `400 Bad Request`: Invalid analysis ID or analysis cannot be retried
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Access denied to analysis
- `404 Not Found`: Analysis not found
- `500 Internal Server Error`: Retry failed

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/ai-analysis/analysis/550e8400-e29b-41d4-a716-446655440000/retry" \
  -H "Authorization: Bearer <jwt_token>"
```

### 7. Get Service Status

Get the current status of AI analysis models and services.

**Endpoint:** `GET /status`

**Authentication:** Not required

**Response:**
```json
{
  "status": "operational",
  "initialized": true,
  "models": {
    "content_summarizer": {
      "name": "GPT-4 Turbo",
      "version": "gpt-4-1106-preview",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 2340,
      "success_rate": 99.2
    },
    "quality_scorer": {
      "name": "Custom Quality Model",
      "version": "v2.1.0",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 890,
      "success_rate": 99.8
    },
    "topic_classifier": {
      "name": "BERT Topic Classifier",
      "version": "bert-base-uncased-v1.2",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 1250,
      "success_rate": 99.5
    },
    "similarity_matcher": {
      "name": "Sentence Transformers",
      "version": "all-MiniLM-L6-v2",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 450,
      "success_rate": 99.9
    },
    "sentiment_analyzer": {
      "name": "RoBERTa Sentiment",
      "version": "cardiffnlp/twitter-roberta-base-sentiment-latest",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 680,
      "success_rate": 99.7
    },
    "threat_detector": {
      "name": "Ensemble Threat Model",
      "version": "v3.0.1",
      "status": "active",
      "last_health_check": "2024-01-15T18:25:00Z",
      "avg_response_time_ms": 3200,
      "success_rate": 98.9
    }
  },
  "system_metrics": {
    "total_analyses_today": 2847,
    "avg_processing_time_ms": 2150,
    "queue_length": 3,
    "cache_hit_rate": 0.34
  },
  "timestamp": "2024-01-15T18:30:00Z"
}
```

**Status Codes:**
- `200 OK`: Service status retrieved successfully

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/ai-analysis/status"
```

## Quality Scoring Metrics

The AI analysis system provides comprehensive quality metrics:

### Overall Quality Score (0-100)
Composite score based on multiple factors:
- **Grammar and Language** (25%): Grammar accuracy, spelling, language usage
- **Content Structure** (20%): Organization, headings, logical flow
- **Depth and Substance** (20%): Content depth, expertise, value
- **Originality** (15%): Uniqueness, plagiarism detection
- **Readability** (10%): Reading level, sentence complexity
- **Technical Quality** (10%): HTML structure, accessibility

### Specialized Scores

| Score Type | Range | Description |
|------------|-------|-------------|
| **Readability Score** | 0-100 | Based on Flesch-Kincaid and other readability metrics |
| **Trustworthiness Score** | 0-100 | Authority indicators, source credibility, fact-checking |
| **Professionalism Score** | 0-100 | Tone, formatting, presentation quality |
| **SEO Score** | 0-100 | Search engine optimization factors |

### Reading Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `elementary` | 0-30 | 5th grade and below |
| `middle_school` | 31-50 | 6th-8th grade |
| `high_school` | 51-70 | 9th-12th grade |
| `college` | 71-85 | College level |
| `graduate` | 86-100 | Graduate/professional level |

## Content Similarity

The similarity system uses advanced vector embeddings to find related content:

### Similarity Types

| Type | Description | Use Case |
|------|-------------|----------|
| `semantic` | Meaning-based similarity | Finding conceptually related content |
| `topical` | Topic-based similarity | Content in the same subject area |
| `structural` | Format and structure similarity | Similar document types |
| `lexical` | Word-based similarity | Similar vocabulary and terminology |

### Similarity Scores

- **Similarity Score** (0.0-1.0): Overall similarity between content pieces
- **Confidence Score** (0-100): Confidence in the similarity assessment
- **Matching Elements**: Detailed breakdown of similarity factors

## Rate Limits

AI analysis endpoints have specific rate limits:

| Endpoint | Limit | Scope | Window |
|----------|-------|-------|--------|
| Analyze Content | 10 requests | Per user/IP | 1 minute |
| Get Analysis | 100 requests | Per IP | 1 minute |
| Find Similar | 20 requests | Per user/IP | 1 minute |
| Get History | 50 requests | Per user | 1 minute |
| Domain Stats | 30 requests | Per IP | 1 minute |
| Retry Analysis | 5 requests | Per user | 1 minute |
| Service Status | 60 requests | Per IP | 1 minute |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642262400
X-RateLimit-Scope: user
```

## Caching Strategy

The AI analysis system implements intelligent caching:

### Cache Keys
- **Content Hash**: SHA-256 hash of normalized content
- **URL + Analysis Types**: Specific analysis configuration
- **Domain Statistics**: Cached for 1 hour

### Cache Duration
- **Analysis Results**: 24 hours for completed analyses
- **Similar Content**: 6 hours for similarity results
- **Domain Statistics**: 1 hour for aggregate stats
- **Service Status**: 5 minutes for model status

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CONTENT` | 400 | Content is too short, too long, or invalid format |
| `UNSUPPORTED_LANGUAGE` | 422 | Content language not supported by AI models |
| `ANALYSIS_TIMEOUT` | 408 | Analysis processing timed out |
| `MODEL_UNAVAILABLE` | 503 | AI model temporarily unavailable |
| `INSUFFICIENT_CONTENT` | 422 | Not enough content for meaningful analysis |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `ANALYSIS_NOT_FOUND` | 404 | Analysis does not exist |
| `PROCESSING_FAILED` | 500 | Analysis processing failed |
| `SIMILARITY_SEARCH_FAILED` | 500 | Similarity search encountered an error |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_CONTENT",
    "message": "Content is too short for meaningful analysis",
    "details": {
      "content_length": 45,
      "minimum_required": 100,
      "suggestion": "Please provide at least 100 characters of content for analysis"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Code Examples

### JavaScript/TypeScript

```typescript
interface AIAnalysisRequest {
  url: string;
  content: string;
  analysis_types?: string[];
}

interface AIAnalysisResponse {
  id: string;
  url: string;
  domain: string;
  content_summary?: string;
  quality_metrics?: {
    grammar_score: number;
    coherence_score: number;
    structure_score: number;
    originality_score: number;
    depth_score: number;
  };
  topic_categories?: {
    primary_category: string;
    secondary_categories: string[];
    confidence_scores: Record<string, number>;
    keywords: Array<{
      keyword: string;
      relevance: number;
      frequency: number;
    }>;
  };
  sentiment_analysis?: {
    overall_sentiment: string;
    sentiment_score: number;
    confidence: number;
    emotional_tone: Record<string, number>;
  };
  seo_metrics?: {
    title_optimization: number;
    meta_description_score: number;
    heading_structure_score: number;
    keyword_density: number;
    readability_score: number;
  };
  content_length?: number;
  language?: string;
  reading_level?: string;
  overall_quality_score?: number;
  readability_score?: number;
  trustworthiness_score?: number;
  professionalism_score?: number;
  processing_status: string;
  processing_time_ms?: number;
  created_at: string;
  processed_at?: string;
}

class AIAnalysisClient {
  private baseUrl: string;
  private token?: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setToken(token: string): void {
    this.token = token;
  }

  async analyzeContent(analysisData: AIAnalysisRequest): Promise<AIAnalysisResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/analyze`, {
      method: 'POST',
      headers,
      body: JSON.stringify(analysisData)
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Analysis failed: ${error.error?.message || response.statusText}`);
    }

    return response.json();
  }

  async getAnalysis(analysisId: string): Promise<AIAnalysisResponse> {
    const headers: Record<string, string> = {};
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/analysis/${analysisId}`, {
      headers
    });

    if (!response.ok) {
      throw new Error(`Failed to get analysis: ${response.statusText}`);
    }

    return response.json();
  }

  async findSimilarContent(
    analysisId: string, 
    options: {
      similarity_threshold?: number;
      limit?: number;
    } = {}
  ): Promise<any[]> {
    const params = new URLSearchParams();
    
    if (options.similarity_threshold !== undefined) {
      params.append('similarity_threshold', options.similarity_threshold.toString());
    }
    if (options.limit !== undefined) {
      params.append('limit', options.limit.toString());
    }

    const headers: Record<string, string> = {};
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const url = `${this.baseUrl}/api/v1/ai-analysis/analysis/${analysisId}/similar?${params.toString()}`;
    const response = await fetch(url, { headers });

    if (!response.ok) {
      throw new Error(`Failed to find similar content: ${response.statusText}`);
    }

    return response.json();
  }

  async getAnalysisHistory(page: number = 1, pageSize: number = 20): Promise<any> {
    if (!this.token) {
      throw new Error('Authentication required for analysis history');
    }

    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString()
    });

    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/history?${params.toString()}`, {
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get analysis history: ${response.statusText}`);
    }

    return response.json();
  }

  async getDomainStats(domain: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/domain/${encodeURIComponent(domain)}/stats`);

    if (!response.ok) {
      throw new Error(`Failed to get domain stats: ${response.statusText}`);
    }

    return response.json();
  }

  async retryAnalysis(analysisId: string): Promise<AIAnalysisResponse> {
    if (!this.token) {
      throw new Error('Authentication required for retry');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/analysis/${analysisId}/retry`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Retry failed: ${error.error?.message || response.statusText}`);
    }

    return response.json();
  }

  async getServiceStatus(): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/v1/ai-analysis/status`);

    if (!response.ok) {
      throw new Error(`Failed to get service status: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage example
const client = new AIAnalysisClient('https://api.linkshield.com');
client.setToken('your-jwt-token');

// Analyze content
const analysis = await client.analyzeContent({
  url: 'https://example.com/article',
  content: '<html><body><h1>AI in Business</h1><p>Artificial intelligence is transforming...</p></body></html>',
  analysis_types: ['CONTENT_SUMMARY', 'QUALITY_SCORING', 'TOPIC_CLASSIFICATION']
});

console.log(`Analysis ID: ${analysis.id}`);
console.log(`Quality Score: ${analysis.overall_quality_score}`);
console.log(`Primary Topic: ${analysis.topic_categories?.primary_category}`);

// Find similar content
const similarContent = await client.findSimilarContent(analysis.id, {
  similarity_threshold: 0.75,
  limit: 5
});

console.log(`Found ${similarContent.length} similar articles`);

// Get domain statistics
const domainStats = await client.getDomainStats('example.com');
console.log(`Domain average quality: ${domainStats.avg_quality_score}`);
```

### Python

```python
import requests
from typing import Dict, Any, Optional, List

class AIAnalysisClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()

    def set_token(self, token: str) -> None:
        """Set authentication token."""
        self.token = token
        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })

    def analyze_content(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content with AI."""
        response = self.session.post(
            f'{self.base_url}/api/v1/ai-analysis/analyze',
            json=analysis_data
        )
        response.raise_for_status()
        return response.json()

    def get_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis results by ID."""
        response = self.session.get(
            f'{self.base_url}/api/v1/ai-analysis/analysis/{analysis_id}'
        )
        response.raise_for_status()
        return response.json()

    def find_similar_content(
        self, 
        analysis_id: str, 
        similarity_threshold: float = 0.8,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Find similar content."""
        params = {
            'similarity_threshold': similarity_threshold,
            'limit': limit
        }
        
        response = self.session.get(
            f'{self.base_url}/api/v1/ai-analysis/analysis/{analysis_id}/similar',
            params=params
        )
        response.raise_for_status()
        return response.json()

    def get_analysis_history(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """Get user's analysis history."""
        if not self.token:
            raise ValueError('Authentication required for analysis history')
        
        params = {
            'page': page,
            'page_size': page_size
        }
        
        response = self.session.get(
            f'{self.base_url}/api/v1/ai-analysis/history',
            params=params
        )
        response.raise_for_status()
        return response.json()

    def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Get domain analysis statistics."""
        response = self.session.get(
            f'{self.base_url}/api/v1/ai-analysis/domain/{domain}/stats'
        )
        response.raise_for_status()
        return response.json()

    def retry_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """Retry a failed analysis."""
        if not self.token:
            raise ValueError('Authentication required for retry')
        
        response = self.session.post(
            f'{self.base_url}/api/v1/ai-analysis/analysis/{analysis_id}/retry'
        )
        response.raise_for_status()
        return response.json()

    def get_service_status(self) -> Dict[str, Any]:
        """Get AI service status."""
        response = self.session.get(
            f'{self.base_url}/api/v1/ai-analysis/status'
        )
        response.raise_for_status()
        return response.json()

# Usage example
client = AIAnalysisClient('https://api.linkshield.com')
client.set_token('your-jwt-token')

# Analyze content
analysis = client.analyze_content({
    'url': 'https://example.com/article',
    'content': '<html><body><h1>AI in Business</h1><p>Artificial intelligence is transforming...</p></body></html>',
    'analysis_types': ['CONTENT_SUMMARY', 'QUALITY_SCORING', 'TOPIC_CLASSIFICATION']
})

print(f"Analysis ID: {analysis['id']}")
print(f"Quality Score: {analysis['overall_quality_score']}")
print(f"Processing Status: {analysis['processing_status']}")

# Wait for completion if still processing
import time
while analysis['processing_status'] == 'PROCESSING':
    time.sleep(2)
    analysis = client.get_analysis(analysis['id'])
    print(f"Status: {analysis['processing_status']}")

if analysis['processing_status'] == 'COMPLETED':
    print(f"Content Summary: {analysis['content_summary']}")
    print(f"Primary Topic: {analysis['topic_categories']['primary_category']}")
    
    # Find similar content
    similar = client.find_similar_content(
        analysis['id'], 
        similarity_threshold=0.75, 
        limit=3
    )
    
    print(f"Found {len(similar)} similar articles:")
    for item in similar:
        print(f"  - {item['target_analysis']['url']} (similarity: {item['similarity_score']:.2f})")

# Get domain statistics
domain_stats = client.get_domain_stats('example.com')
print(f"Domain '{domain_stats['domain']}' statistics:")
print(f"  Total analyses: {domain_stats['total_analyses']}")
print(f"  Average quality: {domain_stats['avg_quality_score']:.1f}")
print(f"  Success rate: {domain_stats['success_rate']:.1f}%")

# Check service status
status = client.get_service_status()
print(f"AI Service Status: {status['status']}")
print(f"Models active: {len([m for m in status['models'].values() if m['status'] == 'active'])}")
```

## Best Practices

### For Content Analysis
1. **Provide sufficient content** (minimum 100 characters for meaningful analysis)
2. **Include context** with proper URL and metadata
3. **Choose appropriate analysis types** based on your needs
4. **Handle processing delays** gracefully with status polling
5. **Cache results** to avoid redundant analysis

### For Integration
1. **Implement proper error handling** for all scenarios
2. **Use rate limiting** with exponential backoff
3. **Monitor service status** before making requests
4. **Leverage caching** for frequently accessed content
5. **Use webhooks** for long-running analyses (if available)

### For Performance
1. **Batch similar requests** when possible
2. **Use similarity search** to find existing analyses
3. **Monitor processing times** and adjust timeouts
4. **Implement client-side caching** for repeated requests
5. **Use appropriate analysis types** to minimize processing time

---

**Next Steps:**
- Review [URL Analysis Endpoints](./url-analysis.md) for security scanning integration
- Check [User Management](./user-management.md) for authentication details
- See [Rate Limiting](../rate-limiting.md) for quota management
- Review [Error Handling](../error-handling.md) for comprehensive error reference