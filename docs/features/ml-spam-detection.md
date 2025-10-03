# ML-Based Spam Detection

## Overview

The SpamPatternDetector now includes integrated ML model support for advanced spam classification. This enhancement provides more accurate spam detection by combining multiple analysis methods.

## Architecture

The spam detection system uses a multi-layered approach:

1. **ML Model Classification (Primary)**: Uses pre-trained transformer models (e.g., toxic-bert) for content analysis
2. **OpenAI GPT Analysis (Secondary)**: Leverages GPT models for contextual understanding when available
3. **Pattern-Based Detection (Fallback)**: Uses regex patterns and heuristics as a reliable fallback

## ML Model Integration

### Model Selection

The system uses the `unitary/toxic-bert` model by default, which provides:
- Toxicity detection
- Severe toxic content identification
- Obscene content detection
- Threat detection
- Insult detection
- Identity hate detection

### Classification Process

```python
# The ML model analyzes content and returns scores for multiple indicators
ml_result = await ai_service.detect_spam_patterns(content)

# Results include:
{
    "spam_score": 78,  # 0-100 score
    "is_spam": True,
    "detected_patterns": ["ml_toxic_content_75", "ml_obscene_content_65"],
    "confidence": 0.78,  # 0.0-1.0
    "ml_analysis": {
        "model": "toxic-bert",
        "indicators": {
            "toxic": 0.75,
            "severe_toxic": 0.30,
            "obscene": 0.65,
            "threat": 0.20,
            "insult": 0.45,
            "identity_hate": 0.15
        },
        "weighted_score": 0.52,
        "max_score": 0.75
    },
    "method": "ml_model"
}
```

### Scoring Algorithm

The ML spam score is calculated using weighted indicators:

```python
weights = {
    "toxic": 0.25,
    "severe_toxic": 0.30,
    "obscene": 0.15,
    "threat": 0.10,
    "insult": 0.10,
    "identity_hate": 0.10
}

weighted_score = sum(indicators[key] * weights[key] for key in indicators)
spam_score = int(weighted_score * 100)
```

Content is classified as spam if:
- Any single indicator exceeds 0.7
- Overall weighted score exceeds 0.6
- Three or more indicators are present

## Hybrid Analysis

When both ML and OpenAI are available, the system combines their results:

```python
# Weighted average: ML 60%, OpenAI 40%
combined_score = ml_score * 0.6 + openai_score * 0.4
```

This approach leverages the strengths of both methods:
- ML models provide fast, consistent classification
- OpenAI provides contextual understanding and nuanced analysis

## Confidence Scoring

Confidence is calculated based on:
- Maximum indicator score (primary factor)
- Weighted score distribution
- Number of detected patterns
- Agreement between analysis methods

High confidence (>0.7) results are returned immediately without additional analysis.

## Fallback Behavior

The system gracefully degrades when ML models are unavailable:

1. **ML Model Failure**: Falls back to OpenAI analysis
2. **OpenAI Failure**: Falls back to pattern-based detection
3. **All Methods Fail**: Returns safe default with error logging

## Performance Considerations

- **Content Truncation**: Content is truncated to 512 characters for ML model input
- **Caching**: Results are cached to avoid redundant analysis
- **Async Processing**: All analysis methods run asynchronously
- **Batch Processing**: Multiple pieces of content can be analyzed concurrently

## Configuration

ML model integration is configured in the AIService:

```python
model_configs = {
    "spam_detector": {
        "model_name": "unitary/toxic-bert",
        "task": "text-classification",
        "enabled": True
    }
}
```

To disable ML model integration:
```python
model_configs["spam_detector"]["enabled"] = False
```

## Testing

Comprehensive tests verify ML model integration:

- `test_ml_model_integration`: Basic ML model functionality
- `test_ml_model_high_confidence`: High confidence spam detection
- `test_ml_model_low_confidence`: Borderline content handling
- `test_ml_model_fallback_to_patterns`: Graceful degradation
- `test_ml_and_openai_combined`: Hybrid analysis

Run tests with:
```bash
pytest tests/test_spam_pattern_detector.py -v
```

## Usage Example

```python
from src.social_protection.content_analyzer.spam_pattern_detector import SpamPatternDetector
from src.services.ai_service import AIService

# Initialize services
ai_service = AIService()
await ai_service.initialize_models()

spam_detector = SpamPatternDetector(ai_service=ai_service)

# Analyze content
result = await spam_detector.detect_spam_patterns(
    content="Check out this amazing offer!",
    platform="twitter"
)

# Check results
if result.is_spam:
    print(f"Spam detected with {result.spam_score}% confidence")
    print(f"Detected patterns: {result.detected_patterns}")
    print(f"Recommendations: {result.recommendations}")
```

## Future Enhancements

Potential improvements for ML spam detection:

1. **Custom Model Training**: Train models on platform-specific spam data
2. **Multi-Language Support**: Add models for non-English content
3. **Real-Time Learning**: Update models based on user feedback
4. **Ensemble Methods**: Combine multiple ML models for better accuracy
5. **Explainable AI**: Provide detailed explanations for spam classifications

## References

- [Hugging Face Transformers](https://huggingface.co/docs/transformers)
- [Toxic-BERT Model](https://huggingface.co/unitary/toxic-bert)
- [Social Protection Design Document](../specs/social-protection-production-readiness/design.md)
