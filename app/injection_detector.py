from app.config import Config

DEFAULT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore instructions",
    "disregard previous instructions",
    "forget the above",
    "override previous instructions",
    "override previous rules",
    "override instructions",
    "reveal system prompt",
    "show system prompt",
    "print system prompt",
    "print system instructions",
    "reveal the system prompt",
    "show hidden system rules",
    "show hidden rules",
    "reveal hidden rules",
    "reveal system rules",
    "system rules",
    "hidden instructions",
    "hidden system rules",
    "bypass restrictions",
    "bypass safety",
    "bypass policy",
    "disregard safety policy",
    "disregard policy",
    "jailbreak",
    "do anything now",
    "dan",
    "developer message",
    "developer mode",
    "disable safety",
]

class InjectionDetector:
    def __init__(self, threshold: float = Config.INJECTION_THRESHOLD, patterns=None):
        self.threshold = threshold
        self.patterns = patterns if patterns is not None else DEFAULT_PATTERNS

        self.weights = {}
        for p in self.patterns:
            if "system prompt" in p or "developer message" in p or "hidden" in p:
                self.weights[p] = 0.6
            elif "bypass" in p or "jailbreak" in p or "dan" in p or "disable safety" in p:
                self.weights[p] = 0.5
            elif "override" in p or "disregard" in p:
                self.weights[p] = 0.5
            else:
                self.weights[p] = 0.4

    def analyze(self, text: str):
        t = text.lower()
        matched = [p for p in self.patterns if p in t]

        score = sum(self.weights[p] for p in matched)
        score = min(1.0, score)

        return {
            "score": score,
            "matched_patterns": matched,
            "is_malicious": score >= self.threshold or len(matched) > 0,
        }
