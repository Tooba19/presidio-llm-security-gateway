# Presidio-Based LLM Security Mini-Gateway

A modular security gateway for Large Language Model (LLM) applications that detects prompt injection attempts and mitigates sensitive information leakage before requests reach the model.

## Overview

This project implements a lightweight preprocessing layer for LLM systems. It analyzes user input, detects adversarial prompt injection patterns, identifies personally identifiable information (PII) using Microsoft Presidio, and applies a policy decision to either:

- **ALLOW** the input
- **MASK** sensitive entities
- **BLOCK** malicious or high-risk input

The system is implemented with FastAPI and includes configurable thresholds, latency measurement, and an evaluation pipeline.

## System Architecture

The security gateway acts as a preprocessing layer between users and the LLM.

User Input  
→ Injection Detection  
→ Presidio PII Analyzer  
→ Policy Engine  
→ Output Decision (ALLOW / MASK / BLOCK)

<p align="center">
<img src="figures/arch.png" width="700">
</p>


## Features

- Rule-based prompt injection / jailbreak detection
- Microsoft Presidio-based PII detection and anonymization
- Custom Korean phone number recognizer
- Context-aware confidence boosting
- Composite entity detection (e.g., name + phone)
- Policy-driven enforcement (ALLOW / MASK / BLOCK)
- Configurable thresholds via `config.py`
- FastAPI REST API with Swagger UI
- Evaluation pipeline with accuracy, precision, recall, F1, confusion matrix, and latency reporting

## Project Structure

```text
app/
  main.py
  policy.py
  injection_detector.py
  presidio_engine.py
  context_scoring.py
  composite_detector.py
  custom_recognizers.py
  config.py

eval/
  prompts.jsonl
  run_eval.py

report/
  report.pdf

figures/
  arch.png
  ROC_Analysis_Final.pdf
  confusion_matrix_heatmap.pdf
  latency_distribution_plot.pdf
  precision_recall_curve.pdf

requirements.txt
README.md
```








