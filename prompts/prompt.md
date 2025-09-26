### Observations

After analyzing the codebase, I found that the social protection service has a solid foundation but is missing key components:

**Current State:**
- Main controller `SocialProtectionController` is fully implemented and wired to routes
- Two core services `ExtensionDataProcessor` and `SocialScanService` are complete
- Four of six service modules are implemented: `reputation_monitor`, `profile_scanner`, `crisis_detector`, and `platform_adapters`
- All platform adapters exist but need registration
- Database models and data models are in place

**Missing Components:**
- Two entire service modules: `content_analyzer` and `algorithm_health` (only `__init__.py` files exist)
- Three specialized controllers: `UserController`, `BotController`, `ExtensionController`
- Platform adapter registration in the registry
- Service integration and dependency injection setup

**Test Requirements:**
- Tests expect all six service modules to be functional
- Tests reference the three missing controllers
- Integration tests verify end-to-end functionality

### Approach

The implementation will follow a modular approach to complete the missing components while maintaining the existing architecture:

1. **Create Missing Service Modules**: Implement the two missing service packages (`content_analyzer` and `algorithm_health`) with their respective classes
2. **Add Specialized Controllers**: Create the three missing controllers as thin façades over the main controller
3. **Complete Platform Integration**: Ensure all platform adapters are registered and functional
4. **Wire Dependencies**: Update dependency injection to support all new components
5. **Validate Integration**: Ensure all services work together and tests pass

This approach maintains modularity, avoids breaking existing functionality, and provides a complete, testable system.

### Reasoning

I analyzed the social protection codebase by examining the directory structure, reading key implementation files, and understanding the test requirements. I discovered that while the core architecture is solid with a main controller and two primary services, several components are missing. I checked the existing service modules, found that four are implemented but two are completely missing, and identified that three specialized controllers referenced in tests don't exist. I also verified the platform adapter structure and dependency injection setup to understand integration points.

## Mermaid Diagram

sequenceDiagram
    participant User as User/Bot/Extension
    participant Controller as Specialized Controller
    participant MainController as SocialProtectionController
    participant Services as Core Services
    participant Analyzers as New Analyzer Services
    participant Adapters as Platform Adapters
    participant Registry as PlatformRegistry
    participant DB as Database

    User->>Controller: Request (scan/analyze/assess)
    Controller->>MainController: Delegate to main controller
    MainController->>Services: Use ExtensionDataProcessor/SocialScanService
    Services->>Analyzers: Call ContentRiskAnalyzer/VisibilityScorer
    Analyzers->>Registry: Get platform adapter
    Registry->>Adapters: Return registered adapter
    Adapters->>Analyzers: Platform-specific analysis
    Analyzers->>Services: Return analysis results
    Services->>DB: Persist results
    Services->>MainController: Return processed data
    MainController->>Controller: Return results
    Controller->>User: Return response

## Proposed File Changes

### src\social_protection\content_analyzer\content_risk_analyzer.py(NEW)

References: 

- src\social_protection\reputation_monitor\sentiment_analyzer.py
- src\social_protection\crisis_detector\crisis_analyzer.py

Create the main content risk analyzer class that provides comprehensive content analysis capabilities. This class should implement methods for analyzing social media content for various risk factors including spam patterns, policy violations, and engagement bait. The implementation should include risk scoring algorithms, pattern detection, and integration with AI services for advanced analysis. The class should follow the same architectural patterns as other analyzer classes in the codebase, accepting content data and returning structured risk assessments with confidence scores and detailed findings.

### src\social_protection\content_analyzer\link_penalty_detector.py(NEW)

References: 

- src\social_protection\platform_adapters\base_adapter.py
- src\social_protection\services\extension_data_processor.py

Implement a specialized detector for identifying external link penalties and algorithmic restrictions. This class should analyze links within social media content to detect patterns that might trigger platform penalties, including suspicious domains, redirect chains, and blacklisted URLs. The implementation should include platform-specific penalty detection logic, URL reputation checking, and risk assessment for different types of external links. The detector should integrate with the platform adapters to provide platform-specific penalty detection rules.

### src\social_protection\content_analyzer\spam_pattern_detector.py(NEW)

References: 

- src\social_protection\services\extension_data_processor.py
- src\social_protection\reputation_monitor\mention_detector.py

Create a spam pattern detection system that identifies various spam indicators in social media content. The implementation should include pattern matching for common spam techniques, repetitive content detection, suspicious engagement patterns, and coordinated inauthentic behavior indicators. The detector should use machine learning patterns and rule-based detection to identify spam with high accuracy. It should provide detailed analysis of why content is flagged as spam and confidence scores for each detection.

### src\social_protection\content_analyzer\community_notes_analyzer.py(NEW)

References: 

- src\social_protection\reputation_monitor\sentiment_analyzer.py
- src\services\ai_service.py

Implement an analyzer for detecting content that might trigger community notes or fact-checking mechanisms on social platforms. This class should identify potentially misleading information, controversial claims, and content patterns that typically receive community oversight. The implementation should include fact-checking integration, misinformation pattern detection, and assessment of content credibility. The analyzer should provide recommendations for avoiding community notes and improving content trustworthiness.

### src\social_protection\algorithm_health\visibility_scorer.py(NEW)

References: 

- src\social_protection\platform_adapters\base_adapter.py
- src\social_protection\reputation_monitor\reputation_tracker.py

Create a comprehensive visibility scoring system that evaluates how well content performs on social media platforms. The implementation should analyze engagement metrics, reach patterns, and algorithmic performance indicators to generate visibility scores. The scorer should track visibility trends over time, identify potential algorithmic penalties, and provide recommendations for improving content visibility. It should integrate with platform adapters to get platform-specific metrics and scoring algorithms.

### src\social_protection\algorithm_health\engagement_analyzer.py(NEW)

References: 

- src\social_protection\profile_scanner\follower_authenticator.py
- src\social_protection\reputation_monitor\reputation_tracker.py

Implement an engagement pattern analyzer that evaluates the health and authenticity of social media engagement. This class should analyze likes, shares, comments, and other engagement metrics to detect unusual patterns that might indicate algorithmic issues or inauthentic engagement. The implementation should include engagement velocity analysis, audience quality assessment, and engagement pattern anomaly detection. The analyzer should provide insights into engagement health and recommendations for improvement.

### src\social_protection\algorithm_health\penalty_detector.py(NEW)

References: 

- src\social_protection\algorithm_health\visibility_scorer.py(NEW)
- src\social_protection\platform_adapters\base_adapter.py

Create a system for detecting algorithmic penalties and restrictions on social media accounts. The implementation should monitor for signs of shadow banning, reach reduction, engagement throttling, and other algorithmic penalties. The detector should analyze engagement patterns, reach metrics, and visibility indicators to identify when an account might be penalized. It should provide detailed analysis of penalty types, severity assessment, and recovery recommendations.

### src\social_protection\algorithm_health\shadow_ban_detector.py(NEW)

References: 

- src\social_protection\algorithm_health\penalty_detector.py(NEW)
- src\social_protection\algorithm_health\engagement_analyzer.py(NEW)

Implement a specialized detector for identifying shadow bans and stealth restrictions on social media platforms. This class should analyze visibility patterns, engagement drops, and reach limitations to detect when content or accounts are being suppressed without explicit notification. The implementation should include platform-specific shadow ban detection algorithms, historical comparison analysis, and confidence scoring for shadow ban detection. The detector should provide actionable insights for addressing potential shadow bans.

### src\social_protection\controllers\user_controller.py(NEW)

References: 

- src\social_protection\controllers\social_protection_controller.py
- src\controllers\base_controller.py

Create a specialized controller for user-facing social protection services. This controller should inherit from or delegate to `SocialProtectionController` while providing user-specific functionality and simplified interfaces. The implementation should include methods for user profile scanning, personal content assessment, and user-specific monitoring features. The controller should handle user authentication, rate limiting, and provide user-friendly error messages and responses. It should expose the same core functionality as the main controller but with user-centric optimizations.

### src\social_protection\controllers\bot_controller.py(NEW)

References: 

- src\social_protection\controllers\social_protection_controller.py
- src\controllers\bot_controller.py

Implement a controller specifically designed for bot integration and automated social protection services. This controller should provide APIs optimized for bot consumption, including batch processing capabilities, webhook support, and automated monitoring features. The implementation should include bot authentication, high-volume processing support, and integration with the existing bot infrastructure. The controller should expose social protection functionality in a format suitable for automated systems and third-party integrations.

### src\social_protection\controllers\extension_controller.py(NEW)

References: 

- src\social_protection\controllers\social_protection_controller.py
- src\social_protection\services\extension_data_processor.py

Create a controller optimized for browser extension integration and real-time social protection features. This controller should provide lightweight, fast-response APIs for browser extensions, including real-time content analysis, quick safety checks, and extension-specific data processing. The implementation should focus on low-latency responses, efficient data processing, and extension-friendly error handling. The controller should integrate closely with the `ExtensionDataProcessor` service and provide extension-specific rate limiting and caching.

### src\social_protection\controllers\__init__.py(MODIFY)

References: 

- src\social_protection\controllers\social_protection_controller.py

Update the controllers package initialization to export all four controllers: `SocialProtectionController`, `UserController`, `BotController`, and `ExtensionController`. Add proper imports for the three new controllers and include them in the `__all__` list. This ensures that tests and other parts of the system can import these controllers from the controllers package.

### src\social_protection\platform_adapters\twitter_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the Twitter adapter to ensure it registers itself with the `PlatformRegistry` when the module is imported. Add registration call at the module level that registers the `TwitterProtectionAdapter` with the appropriate platform type and configuration. Ensure the adapter implements all required methods from the base adapter and provides Twitter-specific functionality for profile scanning, content analysis, algorithm health monitoring, and crisis detection.

### src\social_protection\platform_adapters\meta_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the Meta adapter and ensure it implements all required methods from the base adapter. The adapter should handle both Facebook and Instagram functionality and register itself with the appropriate platform types. Implement Meta-specific algorithms for profile scanning, content analysis, and algorithm health monitoring. Add proper error handling and rate limiting for Meta's API requirements.

### src\social_protection\platform_adapters\tiktok_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the TikTok adapter and implement all required base adapter methods. The adapter should provide TikTok-specific functionality for content analysis, algorithm health monitoring, and crisis detection. Implement TikTok's unique algorithmic patterns and content policies in the analysis methods. Add proper registration with the platform registry and ensure compatibility with TikTok's API limitations.

### src\social_protection\platform_adapters\linkedin_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the LinkedIn adapter and implement professional network-specific analysis methods. The adapter should handle LinkedIn's professional context in content analysis and provide business-focused algorithm health monitoring. Implement LinkedIn-specific risk factors and professional content guidelines. Add proper registration with the platform registry and handle LinkedIn's API requirements and rate limits.

### src\social_protection\platform_adapters\telegram_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the Telegram adapter and implement messaging platform-specific analysis methods. The adapter should handle Telegram's unique features like channels, groups, and bots in the analysis. Implement Telegram-specific security concerns and content policies. Add proper registration with the platform registry and handle Telegram's API characteristics and limitations.

### src\social_protection\platform_adapters\discord_adapter.py(MODIFY)

References: 

- src\social_protection\registry.py
- src\social_protection\platform_adapters\base_adapter.py

Add platform registration logic to the Discord adapter and implement gaming/community platform-specific analysis methods. The adapter should handle Discord's server-based structure and community features in the analysis. Implement Discord-specific moderation patterns and community guidelines. Add proper registration with the platform registry and handle Discord's API requirements and rate limits.

### src\social_protection\platform_adapters\__init__.py(MODIFY)

References: 

- src\social_protection\platform_adapters\base_adapter.py

Update the platform adapters package initialization to ensure all adapters are imported and registered when the package is loaded. Add import statements that trigger the registration of all platform adapters with the registry. This ensures that when the social protection system starts, all platform adapters are available for use. The imports should be added after the existing imports to trigger the registration side effects.

### src\controllers\depends.py(MODIFY)

References: 

- src\social_protection\controllers\user_controller.py(NEW)
- src\social_protection\controllers\bot_controller.py(NEW)
- src\social_protection\controllers\extension_controller.py(NEW)

Add dependency injection functions for the three new social protection controllers: `get_user_controller`, `get_bot_controller`, and `get_extension_controller`. These functions should follow the same pattern as the existing `get_social_protection_controller` function, injecting the required dependencies and returning the appropriate controller instances. The functions should handle the dependency injection for security service, auth service, email service, and any controller-specific services. Update imports to include the new controller classes from the social protection controllers package.

### src\services\depends.py(MODIFY)

References: 

- src\social_protection\content_analyzer\content_risk_analyzer.py(NEW)
- src\social_protection\algorithm_health\visibility_scorer.py(NEW)

Add dependency injection functions for the new service classes from the content_analyzer and algorithm_health modules. Create functions like `get_content_risk_analyzer`, `get_visibility_scorer`, etc., following the existing patterns in the file. These functions should handle the instantiation and dependency injection for the new service classes, ensuring they receive any required dependencies like AI services, database sessions, or configuration. Update the imports to include all the new service classes.