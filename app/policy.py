from app.config import Config

# Medium-sensitivity entities: mask if confidence is high enough
MASK_ONLY_TYPES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "KR_PHONE_NUMBER",
    "PERSON",
}

# High-sensitivity entities: block if confidence is high enough
BLOCK_TYPES = {
    "API_KEY",
    "PASSWORD",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
}


class PolicyEngine:
    def __init__(self, injection_block_threshold: float = Config.INJECTION_BLOCK_THRESHOLD):
        self.injection_block_threshold = injection_block_threshold

    def decide(
        self,
        injection_score: float,
        injection_matched: bool,
        pii_results,
        composite_name_phone: bool = False,
    ) -> str:
        """
        Decide final action for the input:
        - BLOCK for injection attempts or high-risk PII
        - MASK for medium-risk PII
        - ALLOW otherwise
        """

        # 1) Explicit injection pattern match has highest priority
        if injection_matched:
            return "BLOCK"

        # 2) Numeric injection score fallback
        if injection_score >= self.injection_block_threshold:
            return "BLOCK"

        # 3) Optional strict composite rule
        if Config.BLOCK_ON_COMPOSITE and composite_name_phone:
            return "BLOCK"

        # 4) No detected entities -> allow
        if not pii_results:
            return "ALLOW"

        # 5) Block high-risk entities with sufficient confidence
        for r in pii_results:
            if r.entity_type in BLOCK_TYPES and float(r.score) >= Config.PII_BLOCK_SCORE:
                return "BLOCK"

        # 6) Mask medium-risk entities with sufficient confidence
        for r in pii_results:
            if r.entity_type in MASK_ONLY_TYPES and float(r.score) >= Config.PII_MASK_SCORE:
                return "MASK"

        # 7) Ignore all other entity types (e.g., LOCATION, DATE_TIME)
        return "ALLOW"