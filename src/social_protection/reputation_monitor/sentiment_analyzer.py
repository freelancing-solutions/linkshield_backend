
from src.services.depends import get_ai_service

class SentimentAnalyzer:

    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service or get_ai_service()


    def analyze_sentiment(self, content: str):
        """
            sentiment analisis for social media content
        """

