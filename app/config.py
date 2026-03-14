import os

def _get_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return default if v is None else float(v)

def _get_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return default if v is None else int(v)

def _get_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _get_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return default if v is None else str(v)


class Config:
    """
    Central configuration for the LLM Security Gateway.
    All values can be overridden via environment variables.
    """

    # =========================
    # Injection Detection
    # =========================
    INJECTION_THRESHOLD = _get_float("INJECTION_THRESHOLD", 0.7)
    INJECTION_BLOCK_THRESHOLD = _get_float("INJECTION_BLOCK_THRESHOLD", 0.7)

    # =========================
    # Context-Aware Scoring
    # =========================
    CONTEXT_WINDOW = _get_int("CONTEXT_WINDOW", 25)

    # =========================
    # PII Confidence Calibration
    # =========================
    PII_MASK_SCORE = _get_float("PII_MASK_SCORE", 0.5)
    PII_BLOCK_SCORE = _get_float("PII_BLOCK_SCORE", 0.99)

    # =========================
    # Composite Entity Policy
    # =========================
    BLOCK_ON_COMPOSITE = _get_bool("BLOCK_ON_COMPOSITE", False)

    # =========================
    # Anonymization Settings
    # =========================
    DEFAULT_MASK_TOKEN = _get_str("DEFAULT_MASK_TOKEN", "<REDACTED>")

    # =========================
    # Performance Monitoring
    # =========================
    LATENCY_WARNING_MS = _get_float("LATENCY_WARNING_MS", 300.0)