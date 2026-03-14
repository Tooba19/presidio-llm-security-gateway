import json
import statistics
import time
from collections import defaultdict

from app.injection_detector import InjectionDetector
from app.presidio_engine import PresidioPIIEngine
from app.policy import PolicyEngine
from app.config import Config
from app.composite_detector import has_composite_name_phone


def load_dataset(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def run_gateway(text: str, injection_detector, pii_engine, policy_engine):
    start = time.perf_counter()

    inj = injection_detector.analyze(text)
    pii_results = pii_engine.analyze(text)
    composite_name_phone = has_composite_name_phone(pii_results)
    injection_matched = len(inj.get("matched_patterns", [])) > 0

    action = policy_engine.decide(
        injection_score=inj["score"],
        injection_matched=injection_matched,
        pii_results=pii_results,
        composite_name_phone=composite_name_phone,
    )

    latency_ms = (time.perf_counter() - start) * 1000

    return {
        "action": action,
        "injection_score": inj["score"],
        "matched_patterns": inj.get("matched_patterns", []),
        "num_pii": len(pii_results),
        "composite_name_phone": composite_name_phone,
        "latency_ms": latency_ms,
    }


def compute_macro_metrics(records):
    labels = ["ALLOW", "MASK", "BLOCK"]

    tp = {label: 0 for label in labels}
    fp = {label: 0 for label in labels}
    fn = {label: 0 for label in labels}

    for r in records:
        y_true = r["expected_action"]
        y_pred = r["predicted_action"]

        for label in labels:
            if y_true == label and y_pred == label:
                tp[label] += 1
            elif y_true != label and y_pred == label:
                fp[label] += 1
            elif y_true == label and y_pred != label:
                fn[label] += 1

    metrics = {}
    for label in labels:
        precision = tp[label] / (tp[label] + fp[label]) if (tp[label] + fp[label]) > 0 else 0.0
        recall = tp[label] / (tp[label] + fn[label]) if (tp[label] + fn[label]) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        metrics[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp[label],
            "fp": fp[label],
            "fn": fn[label],
        }

    return metrics


def print_confusion_matrix(records):
    labels = ["ALLOW", "MASK", "BLOCK"]
    matrix = {true_label: {pred_label: 0 for pred_label in labels} for true_label in labels}

    for r in records:
        matrix[r["expected_action"]][r["predicted_action"]] += 1

    print("\nCONFUSION MATRIX")
    print(f"{'Actual / Pred':<15} {'ALLOW':>8} {'MASK':>8} {'BLOCK':>8}")
    for true_label in labels:
        row = matrix[true_label]
        print(f"{true_label:<15} {row['ALLOW']:>8} {row['MASK']:>8} {row['BLOCK']:>8}")

    return matrix


def main():
    print("Loading dataset...")
    dataset = load_dataset("eval/prompts.jsonl")
    print(f"Loaded {len(dataset)} prompts")

    injection_detector = InjectionDetector(threshold=Config.INJECTION_THRESHOLD)
    pii_engine = PresidioPIIEngine(language="en")
    policy_engine = PolicyEngine(injection_block_threshold=Config.INJECTION_BLOCK_THRESHOLD)

    results = []
    by_category_latency = defaultdict(list)

    for item in dataset:
        out = run_gateway(
            item["text"],
            injection_detector=injection_detector,
            pii_engine=pii_engine,
            policy_engine=policy_engine,
        )

        record = {
            "text": item["text"],
            "category": item["category"],
            "expected_action": item["expected_action"],
            "predicted_action": out["action"],
            "correct": item["expected_action"] == out["action"],
            "latency_ms": out["latency_ms"],
            "injection_score": out["injection_score"],
            "matched_patterns": out["matched_patterns"],
            "num_pii": out["num_pii"],
            "composite_name_phone": out["composite_name_phone"],
        }
        results.append(record)
        by_category_latency[item["category"]].append(out["latency_ms"])

    total = len(results)
    correct = sum(r["correct"] for r in results)
    accuracy = correct / total if total > 0 else 0.0

    print(f"\nTOTAL SAMPLES: {total}")
    print(f"CORRECT: {correct}")
    print(f"ACCURACY: {accuracy:.4f}")

    metrics = compute_macro_metrics(results)

    print("\nPER-CLASS METRICS")
    for label, m in metrics.items():
        print(
            f"{label}: "
            f"precision={m['precision']:.4f}, "
            f"recall={m['recall']:.4f}, "
            f"f1={m['f1']:.4f}, "
            f"tp={m['tp']}, fp={m['fp']}, fn={m['fn']}"
        )

    print_confusion_matrix(results)

    print("\nLATENCY BY CATEGORY (ms)")
    for category, values in by_category_latency.items():
        avg = statistics.mean(values)
        std = statistics.pstdev(values) if len(values) > 1 else 0.0
        print(f"{category}: avg={avg:.2f}, std={std:.2f}, n={len(values)}")

    print("\nMISCLASSIFIED EXAMPLES")
    mistakes = [r for r in results if not r["correct"]]
    if not mistakes:
        print("None")
    else:
        for r in mistakes:
            print("-" * 80)
            print("Category:", r["category"])
            print("Expected:", r["expected_action"])
            print("Predicted:", r["predicted_action"])
            print("Injection score:", r["injection_score"])
            print("Matched patterns:", r["matched_patterns"])
            print("Composite:", r["composite_name_phone"])
            print("Text:", r["text"])


if __name__ == "__main__":
    main()
