# app/context_scoring.py

CONTEXT_KEYWORDS = {
    "code": 0.15,
    "verification": 0.20,
    "otp": 0.25,
    "passcode": 0.20,
    "pin": 0.20,
    "bank": 0.20,
    "account": 0.15,
    "id": 0.15,
}

def boost_scores_with_context(text: str, results, window: int = 25):
    """
    Post-process Presidio results: if sensitive context keywords appear near an entity,
    boost its confidence score. This is context-aware scoring.
    """
    lower = text.lower()

    for r in results:
        start = max(0, r.start - window)
        end = min(len(text), r.end + window)
        ctx = lower[start:end]

        boost = 0.0
        for kw, w in CONTEXT_KEYWORDS.items():
            if kw in ctx:
                boost += w

        r.score = min(1.0, float(r.score) + boost)

    return results