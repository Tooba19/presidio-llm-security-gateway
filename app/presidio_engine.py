from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from app.config import Config
from app.context_scoring import boost_scores_with_context
from app.custom_recognizers import KoreanPhoneRecognizer


class PresidioPIIEngine:
    def __init__(self, language: str = "en"):
        self.language = language

        self.analyzer = AnalyzerEngine()
        # Register custom recognizers (e.g., Korean phone numbers)
        self.analyzer.registry.add_recognizer(KoreanPhoneRecognizer())

        self.anonymizer = AnonymizerEngine()

    def analyze(self, text: str):
        results = self.analyzer.analyze(text=text, language=self.language)
        # Context-aware scoring (boost confidence using nearby keywords)
        results = boost_scores_with_context(text, results, window=Config.CONTEXT_WINDOW)
        return results

    def mask(self, text: str, analyzer_results):
        operators = {
            "DEFAULT": OperatorConfig("replace", {"new_value": Config.DEFAULT_MASK_TOKEN})
        }
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators
        )
        return anonymized.text