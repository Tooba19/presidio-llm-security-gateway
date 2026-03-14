from presidio_analyzer import Pattern, PatternRecognizer

class KoreanPhoneRecognizer(PatternRecognizer):
    """
    Detects Korean mobile numbers like 010-1234-5678.
    """
    def __init__(self):
        patterns = [
            Pattern(
                name="korean_mobile",
                regex=r"\b01[016789]-\d{3,4}-\d{4}\b",
                score=0.85
            )
        ]
        super().__init__(
            supported_entity="KR_PHONE_NUMBER",
            patterns=patterns
        )
