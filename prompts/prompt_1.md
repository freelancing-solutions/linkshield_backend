I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

The LinkShield backend has a well-structured URL analysis system with multiple security providers, subscription-based limits, and project monitoring capabilities. The system uses async SQLAlchemy with PostgreSQL, follows clean architecture patterns, and has comprehensive error handling. The subscription model already includes scan depth and link count limits, and the project monitoring system has a boolean flag for broken link checking. The alert system already includes BROKEN_LINKS as an alert type, indicating this feature was planned.

### Approach

I'll extend the URL analysis system to include broken link detection by adding BROKEN_LINKS to the ScanType enum, implementing comprehensive link crawling and validation logic in URLAnalysisService, updating the URLCheckController to handle broken link scans with proper subscription limit enforcement, and enhancing response models to include broken link results. The implementation will respect subscription plan limits for scan depth and link count, integrate with the existing project monitoring system, and provide detailed broken link analysis results.

### Reasoning

I explored the LinkShield backend codebase and examined the URL check models, routes, services, and controllers. I analyzed the subscription system to understand how limits are enforced, reviewed the project models to see monitoring configuration, and studied the analysis results structure. I identified that the system already has infrastructure for different scan types, subscription limit enforcement, and alert systems, but lacks broken link detection capabilities.

## Mermaid Diagram

sequenceDiagram
    participant Client
    participant URLCheckRoutes
    participant URLCheckController
    participant SubscriptionPlan
    participant URLAnalysisService
    participant Database

    Note over Client,Database: Broken Link Scan Flow
    Client->>URLCheckRoutes: POST /api/v1/url-check/check
    Note right of Client: scan_types: [BROKEN_LINKS]<br/>scan_depth: 3<br/>max_links: 50
    
    URLCheckRoutes->>URLCheckController: check_url(url, scan_types, scan_depth, max_links)
    URLCheckController->>SubscriptionPlan: validate_scan_depth(3)
    SubscriptionPlan-->>URLCheckController: clamped_depth = 2 (plan limit)
    URLCheckController->>SubscriptionPlan: get_max_links_for_scan(50)
    SubscriptionPlan-->>URLCheckController: clamped_links = 30 (plan limit)
    
    URLCheckController->>Database: Create URLCheck record
    URLCheckController->>URLAnalysisService: analyze_url(url, [BROKEN_LINKS], depth=2, max_links=30)
    
    Note over URLAnalysisService: Link Crawling Process
    URLAnalysisService->>URLAnalysisService: _scan_broken_links(url, depth=2, max_links=30)
    URLAnalysisService->>URLAnalysisService: _extract_links_from_html(html, base_url)
    URLAnalysisService->>URLAnalysisService: _check_link_status(link) for each link
    
    Note over URLAnalysisService: Concurrent Link Validation
    loop For each discovered link
        URLAnalysisService->>URLAnalysisService: HTTP request to validate link
        URLAnalysisService->>URLAnalysisService: Record status (200, 404, timeout, etc.)
    end
    
    URLAnalysisService-->>URLCheckController: AnalysisResults with broken link data
    URLCheckController->>Database: Update URLCheck with results
    Note right of Database: broken_links_count: 5<br/>total_links_checked: 28<br/>scan_depth_used: 2
    
    URLCheckController-->>URLCheckRoutes: URLCheck with broken link results
    URLCheckRoutes-->>Client: URLCheckResponse with broken link details
    Note left of Client: Response includes:<br/>- broken_links_count<br/>- broken_links_details<br/>- scan_depth_used<br/>- total_links_checked

## Proposed File Changes

### src\models\url_check.py(MODIFY)

References: 

- src\models\analysis_results.py(MODIFY)

Add BROKEN_LINKS to the ScanType enumeration:

**Add new enum value:**
- Add `BROKEN_LINKS = "broken_links"` to the ScanType enum after the existing values
- This will enable broken link detection as a distinct scan type alongside SECURITY, REPUTATION, and CONTENT

**Update docstring:**
- Update the ScanType enum docstring to include description of BROKEN_LINKS scan type
- Document that BROKEN_LINKS performs link crawling and validation to detect broken or inaccessible links

The change should be minimal and follow the existing pattern of other scan types in the enum.
Update the URLCheck model to properly handle broken link scan results:

**Add broken link specific fields:**
- Add `broken_links_count = Column(Integer, nullable=True, default=0)` to track number of broken links found
- Add `total_links_checked = Column(Integer, nullable=True, default=0)` to track total links validated
- Add `scan_depth_used = Column(Integer, nullable=True)` to record actual scan depth used
- Add `max_links_used = Column(Integer, nullable=True)` to record link limit applied

**Update the to_dict method:**
- Include broken link statistics in the dictionary representation
- Extract broken link details from analysis_results JSON when available
- Add broken link summary information to the response
- Ensure backward compatibility for existing URL checks without broken link data

**Add broken link helper methods:**
- Add `get_broken_links_summary(self) -> Dict[str, Any]` method to extract broken link statistics
- Add `has_broken_links(self) -> bool` method to check if broken links were found
- Add `get_broken_link_percentage(self) -> float` method to calculate percentage of broken links

**Update threat level calculation:**
- Modify `update_threat_level()` method to consider broken links in threat assessment
- Add logic to increase threat level if a high percentage of links are broken
- Consider broken links as a factor in overall safety score calculation

**Enhance indexes:**
- Add database index on broken_links_count for efficient querying
- Add composite index on (domain, broken_links_count) for domain-based broken link analysis

**Update validation methods:**
- Ensure broken link fields are properly validated
- Add constraints to ensure counts are non-negative
- Handle cases where broken link scanning was not performed

The changes should maintain database compatibility and provide efficient access to broken link information.

### src\services\url_analysis_service.py(MODIFY)

References: 

- src\models\analysis_results.py(MODIFY)
- src\models\subscription.py

Implement comprehensive broken link detection functionality in URLAnalysisService:

**Add broken link detection method:**
- Add `async def _scan_broken_links(self, url: str, scan_depth: int = 1, max_links: int = 100) -> Dict[str, Any]` method
- Implement link crawling logic that respects depth and link count limits
- Parse HTML content to extract all links (href, src attributes)
- Validate each link by making HTTP requests and checking response status
- Handle different types of links: internal, external, relative, absolute
- Track broken links with detailed error information (404, timeout, connection error, etc.)

**Add link crawling utilities:**
- Add `_extract_links_from_html(self, html_content: str, base_url: str) -> List[str]` method
- Add `_normalize_link(self, link: str, base_url: str) -> str` method for URL normalization
- Add `_is_valid_link(self, link: str) -> bool` method for basic link validation
- Add `_check_link_status(self, link: str) -> Dict[str, Any]` method for individual link validation

**Update _perform_comprehensive_analysis method:**
- Add condition to include broken link scanning when `ScanType.BROKEN_LINKS` is in scan_types
- Add task: `self._scan_broken_links(url, scan_depth, max_links)` to the analysis tasks
- Ensure broken link scanning respects subscription limits passed as parameters

**Add subscription limit integration:**
- Modify `analyze_url` method signature to accept `scan_depth: Optional[int] = None, max_links: Optional[int] = None`
- Pass these limits to the broken link scanning method
- Ensure limits are enforced during link crawling and validation

**Create ProviderScanResult for broken links:**
- Return broken link results in the same format as other scan types
- Include metadata with broken link count, total links checked, scan depth used
- Provide detailed broken link information in the raw_response field
- Set threat_detected based on whether broken links were found
- Calculate confidence_score based on the percentage of broken links

**Error handling and timeouts:**
- Implement proper timeout handling for link validation requests
- Add retry logic for transient network errors
- Handle various HTTP error codes and network exceptions
- Ensure the scan doesn't hang on slow or unresponsive links

**Performance optimizations:**
- Use asyncio.gather() for concurrent link validation
- Implement connection pooling for HTTP requests
- Add rate limiting to avoid overwhelming target servers
- Cache link validation results to avoid duplicate checks

The implementation should follow the existing patterns in the service and integrate seamlessly with the current analysis workflow.

### src\controllers\url_check_controller.py(MODIFY)

References: 

- src\models\subscription.py
- src\models\project.py

Update URLCheckController to handle broken link scans with subscription limit enforcement:

**Modify check_url method:**
- Add subscription limit validation for broken link scans
- Extract user's subscription plan and get scan depth and link limits
- Pass subscription limits to the URL analysis service
- Add validation to ensure requested scan parameters don't exceed plan limits

**Add subscription limit validation:**
- Add `_validate_broken_link_limits(self, user: User, scan_types: List[ScanType], requested_depth: Optional[int] = None, requested_links: Optional[int] = None) -> Tuple[int, int]` method
- Check if user's subscription plan allows broken link scanning
- Validate and clamp scan depth to plan limits using `plan.get_scan_depth_for_request()`
- Validate and clamp max links to plan limits using `plan.get_max_links_for_scan()`
- Raise HTTPException if broken link scanning is not allowed for the user's plan

**Update _perform_url_analysis method:**
- Modify method signature to accept scan depth and max links parameters
- Pass these parameters to the URL analysis service
- Ensure the parameters are properly validated before analysis

**Add broken link specific error handling:**
- Add specific error messages for broken link scan limit violations
- Provide clear feedback when users exceed their plan limits
- Include upgrade suggestions in error messages for users on lower plans

**Update bulk_check_urls method:**
- Apply the same subscription limit validation for bulk requests
- Ensure broken link scanning limits are enforced across all URLs in bulk requests
- Consider the cumulative impact of broken link scanning on plan limits

**Add logging for broken link scans:**
- Log broken link scan requests with depth and link count parameters
- Track subscription limit enforcement in logs
- Log broken link scan results and performance metrics

**Integration with project monitoring:**
- When broken link scans are triggered from project monitoring, respect the MonitoringConfig settings
- Use the project's configured scan_depth and max_links_per_scan values
- Ensure project-based scans also respect the user's subscription limits

The changes should maintain backward compatibility and follow the existing error handling and logging patterns in the controller.

### src\routes\url_check.py(MODIFY)

References: 

- src\models\url_check.py(MODIFY)
- src\models\analysis_results.py(MODIFY)

Update URL check routes to support broken link scanning parameters:

**Modify URLCheckRequest model:**
- Add `scan_depth: Optional[int] = Field(None, ge=1, le=10, description="Maximum depth for link crawling (broken link scans only)")` 
- Add `max_links: Optional[int] = Field(None, ge=1, le=1000, description="Maximum number of links to check (broken link scans only)")`
- Update the model docstring to document the new parameters

**Update BulkURLCheckRequest model:**
- Add the same scan_depth and max_links parameters
- Ensure bulk requests can also specify broken link scanning limits

**Modify check_url route:**
- Pass the scan_depth and max_links parameters from the request to the controller
- Update the route documentation to explain broken link scanning parameters
- Add examples showing how to use broken link scanning

**Update bulk_check_urls route:**
- Pass the broken link scanning parameters to the bulk check controller method
- Ensure the parameters are applied to all URLs in the bulk request

**Enhance route documentation:**
- Update docstrings to explain broken link scanning functionality
- Document subscription plan requirements for broken link scanning
- Provide examples of broken link scan requests
- Explain how scan depth and max links parameters work

**Add validation examples:**
- Include examples in the OpenAPI documentation showing valid broken link scan requests
- Document the relationship between subscription plans and scanning limits
- Provide error response examples for limit violations

The changes should maintain backward compatibility by making the new parameters optional with sensible defaults.
Enhance URLCheckResponse and related response models to include broken link results:

**Update URLCheckResponse model:**
- Add `broken_links_count: Optional[int] = Field(None, description="Number of broken links found")` 
- Add `total_links_checked: Optional[int] = Field(None, description="Total number of links checked")`
- Add `broken_links_details: Optional[List[Dict[str, Any]]] = Field(None, description="Detailed information about broken links")`
- Add `scan_depth_used: Optional[int] = Field(None, description="Actual scan depth used")`
- Add `max_links_used: Optional[int] = Field(None, description="Maximum links limit applied")`

**Create BrokenLinkDetail model:**
- Create new Pydantic model: `class BrokenLinkDetail(BaseModel):`
- Add fields: `url: str`, `status_code: Optional[int]`, `error_type: str`, `error_message: str`, `parent_url: str`, `link_type: str` (internal/external)
- Add `discovered_at_depth: int` to track at which crawl depth the link was found

**Update ScanResultResponse model:**
- Ensure it can properly represent broken link scan results
- Add support for broken link specific metadata
- Include broken link statistics in the scan result

**Create BrokenLinkSummary model:**
- Create summary model for broken link analysis: `class BrokenLinkSummary(BaseModel):`
- Include fields: `total_links: int`, `broken_links: int`, `broken_percentage: float`, `scan_depth: int`, `scan_duration: float`
- Add `broken_by_type: Dict[str, int]` to categorize broken links by error type
- Add `broken_by_depth: Dict[int, int]` to show broken links by crawl depth

**Update URLCheck.to_dict() method:**
- Modify the to_dict method in URLCheck model to include broken link information when available
- Extract broken link data from analysis_results JSON field
- Format broken link information for API responses

**Enhance analysis_results field:**
- Ensure the analysis_results JSON field can store comprehensive broken link data
- Include broken link details, statistics, and metadata
- Maintain backward compatibility with existing analysis result formats

**Update response documentation:**
- Add comprehensive documentation for all new broken link fields
- Provide examples of broken link scan responses
- Document the structure of broken link details and summaries

The changes should maintain backward compatibility and provide rich information about broken link scan results.

### src\models\analysis_results.py(MODIFY)

Add broken link detection support to the analysis results models:

**Enhance ProviderScanResult model:**
- Add `broken_links: Optional[List[Dict[str, Any]]] = Field(None, description="List of broken links found")`
- Add `total_links_checked: Optional[int] = Field(None, description="Total number of links validated")`
- Add `scan_depth_used: Optional[int] = Field(None, description="Actual crawl depth used")`

**Update ProviderMetadata model:**
- Add `broken_links_count: Optional[int] = None` for broken link statistics
- Add `total_links_checked: Optional[int] = None` for total link count
- Add `scan_depth: Optional[int] = None` for crawl depth information
- Add `max_links_limit: Optional[int] = None` for applied link limits
- Add `broken_link_types: Optional[Dict[str, int]] = None` for categorizing broken links by error type

**Create BrokenLinkInfo model:**
- Add new Pydantic model for individual broken link information:
```python
class BrokenLinkInfo(BaseModel):
    url: str
    status_code: Optional[int] = None
    error_type: str  # 404, timeout, connection_error, etc.
    error_message: str
    parent_url: str
    link_type: str  # internal, external, relative, absolute
    discovered_at_depth: int
    response_time: Optional[float] = None
```

**Update conversion utilities:**
- Modify `convert_legacy_analysis_results()` to handle broken link data
- Update `convert_analysis_results_to_dict_for_storage()` to include broken link information
- Ensure `create_scan_result_model()` can handle broken link scan results

**Add broken link specific helper methods:**
- Add `get_broken_links_summary()` method to AnalysisResults
- Add `get_broken_links_by_type()` method to categorize broken links
- Add `get_broken_links_by_depth()` method to analyze broken links by crawl depth
- Add `calculate_broken_link_percentage()` method for statistics

**Enhance backward compatibility:**
- Ensure existing analysis results without broken link data continue to work
- Provide default values for new broken link fields
- Handle cases where broken link scanning was not performed

The changes should integrate seamlessly with the existing analysis results structure and provide comprehensive broken link information.

### alembic\versions\006_add_broken_link_fields.py(NEW)

References: 

- alembic\versions\005_add_alert_instance_model.py
- alembic\versions\004_add_dashboard_project_models.py

Create a new Alembic migration to add broken link fields to the url_checks table:

**Migration Header:**
- Set revision ID as '006_add_broken_link_fields'
- Set down_revision to '005_add_alert_instance_model'
- Include proper docstring describing the broken link functionality additions

**Add Columns to url_checks table:**
- Add `broken_links_count` column: `sa.Column('broken_links_count', sa.Integer(), nullable=True, default=0)`
- Add `total_links_checked` column: `sa.Column('total_links_checked', sa.Integer(), nullable=True, default=0)`
- Add `scan_depth_used` column: `sa.Column('scan_depth_used', sa.Integer(), nullable=True)`
- Add `max_links_used` column: `sa.Column('max_links_used', sa.Integer(), nullable=True)`

**Add Database Indexes:**
- Create index on broken_links_count: `op.create_index('ix_url_checks_broken_links_count', 'url_checks', ['broken_links_count'])`
- Create composite index: `op.create_index('ix_url_checks_domain_broken_links', 'url_checks', ['domain', 'broken_links_count'])`
- Create index for efficient broken link queries: `op.create_index('ix_url_checks_total_links_checked', 'url_checks', ['total_links_checked'])`

**Update Existing Data:**
- Set default values for existing records: `op.execute("UPDATE url_checks SET broken_links_count = 0, total_links_checked = 0 WHERE broken_links_count IS NULL")`
- Ensure data consistency for existing URL checks

**Downgrade Function:**
- Implement complete rollback that drops all new columns and indexes
- Drop indexes in correct order: `op.drop_index('ix_url_checks_broken_links_count')`
- Drop columns: `op.drop_column('url_checks', 'broken_links_count')`
- Ensure clean rollback without data loss

**Migration Validation:**
- Include validation to ensure migration runs successfully
- Add comments explaining the purpose of each new field
- Follow the patterns established in existing migration files

The migration should be safe to run on existing databases and maintain data integrity.