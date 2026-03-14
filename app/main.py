import time
from fastapi import FastAPI
from pydantic import BaseModel

from app.config import Config
from app.injection_detector import InjectionDetector
from app.presidio_engine import PresidioPIIEngine
from app.policy import PolicyEngine
from app.composite_detector import has_composite_name_phone

app = FastAPI(title="Presidio-Based LLM Security Mini-Gateway")

# Initialize components once (reuse across requests)
injection_detector = InjectionDetector(threshold=Config.INJECTION_THRESHOLD)
pii_engine = PresidioPIIEngine(language="en")
policy_engine = PolicyEngine(injection_block_threshold=Config.INJECTION_BLOCK_THRESHOLD)


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeResponse(BaseModel):
    action: str
    injection_score: float
    matched_patterns: list[str]
    pii_entities: list[dict]
    output: str
    latency_ms: float
    composite_name_phone: bool


def _serialize_pii(results):
    out = []
    for r in results:
        out.append(
            {
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": float(r.score),
            }
        )
    return out


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    start_time = time.perf_counter()

    text = req.text

    inj = injection_detector.analyze(text)
    pii_results = pii_engine.analyze(text)

    composite_name_phone = has_composite_name_phone(pii_results)
    injection_matched = len(inj.get("matched_patterns", [])) > 0

    action = policy_engine.decide(
        injection_score=inj["score"],
        injection_matched=injection_matched,
        pii_results=pii_results,
        composite_name_phone=composite_name_phone
    )

    latency_ms = (time.perf_counter() - start_time) * 1000

    if action == "BLOCK":
        return AnalyzeResponse(
            action="BLOCK",
            injection_score=inj["score"],
            matched_patterns=inj.get("matched_patterns", []),
            pii_entities=_serialize_pii(pii_results),
            output="Request blocked due to policy decision (prompt-injection and/or high-risk PII).",
            latency_ms=round(latency_ms, 2),
            composite_name_phone=composite_name_phone,
        )

    if action == "MASK":
        masked = pii_engine.mask(text, pii_results)
        return AnalyzeResponse(
            action="MASK",
            injection_score=inj["score"],
            matched_patterns=inj.get("matched_patterns", []),
            pii_entities=_serialize_pii(pii_results),
            output=masked,
            latency_ms=round(latency_ms, 2),
            composite_name_phone=composite_name_phone,
        )

    return AnalyzeResponse(
        action="ALLOW",
        injection_score=inj["score"],
        matched_patterns=inj.get("matched_patterns", []),
        pii_entities=_serialize_pii(pii_results),
        output=text,
        latency_ms=round(latency_ms, 2),
        composite_name_phone=composite_name_phone,
    )