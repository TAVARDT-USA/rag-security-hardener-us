# RAG Security & Context Hardening Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/rag-security-hardener-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Retrieval-Augmented Generation (RAG) security evaluation and context hardening engine engineered by **TAVARDT**. Grounded in OWASP LLM01, OWASP LLM04, OWASP LLM07, and MITRE ATLAS standards, this toolkit audits multi-tenant vector boundaries, strips indirect injection markers, and exports production-ready middleware.

***

## Core Capabilities and Defensive Architecture

* **Deterministic Pipeline Auditing**: Validates context boundaries, metadata filters, and chunk quotas against formal security specifications.
* **Automated Middleware Generation**: Exports drop-in Python guardrail classes that sanitize retrieved text and enforce strict XML encapsulation tags.
* **Multi-Tenant Isolation Verification**: Confirms that vector database queries mandate cryptographic metadata filters to prevent cross-tenant information disclosure.

***

## Threat Vectors and Operational Impact

Deploying RAG workflows without structured context isolation allows adversarial data within retrieved documents to hijack model execution and leak confidential records. The toolkit evaluates five core security dimensions across the retrieval lifecycle:

* **Document Ingestion Origin Integrity**: Audits untrusted ingestion pipelines against steganographic prompt injections, unicode control sequences, and malicious document formats (Deduction: up to -25 points).
* **Vector Database Multi-Tenant Isolation**: Identifies shared vector collections lacking cryptographically verified namespace or RBAC metadata boundaries (Deduction: up to -30 points).
* **Context Boundary Encapsulation**: Blocks raw string concatenation of retrieved documents by requiring strict XML tags with explicit containment instructions (Deduction: up to -25 points).
* **Indirect Prompt Injection Filtering**: Deploys compiled heuristic regex filters to scrub adversarial instruction overrides embedded within retrieved chunks (Deduction: up to -20 points).
* **Grounded Output Validation Gates**: Enforces attribution verification and PII regex masking before model completions are returned to downstream clients (Deduction: up to -15 points).

Evaluated pipelines receive a cumulative score from 10 to 100 points. The system assigns clear status verdicts: **HARDENED** for scores 85 and above, **MODERATE** between 50 and 84, or **CRITICAL** below 50, triggering immediate pipeline rejection.

***

## CLI Installation and Execution

Evaluate pipeline security or export defensive middleware using lightweight standard Python commands:

```bash
# Clone the official repository
git clone https://github.com/TAVARDT-USA/rag-security-hardener-us.git

# Enter workspace directory
cd rag-security-hardener-us

# Evaluate RAG pipeline across all defensive layers
python rag_security_hardener.py -i 3 -v 3 -c 3 -f 3 -g 3

# Export hardened Python middleware guardrail
python rag_security_hardener.py -i 3 -v 3 -c 3 -f 3 -g 3 -e defensive_rag_middleware.py

# Output structured JSON audit report
python rag_security_hardener.py -i 3 -v 3 -c 3 -f 3 -g 3 -j
```

***

## Frequently Asked Technical Questions

### What threat vectors does the RAG security hardener evaluate across retrieval pipelines?

The toolkit audits pipelines against unverified document ingestion, cross-tenant vector leakage, prompt context boundary escapes, indirect injection payloads, and unvalidated model outputs. Evaluated pipelines receive a calibrated hardening score from 10 to 100 points, classifying architectures into HARDENED, MODERATE, or CRITICAL.

### How does XML context boundary encapsulation prevent indirect prompt injections?

Wrapping retrieved document chunks in strict XML containment tags isolates external knowledge from authoritative system instructions. This separation prevents malicious text inside third-party documents from being interpreted as executable system directives by the language model.

### Why is vector database tenant metadata filtering critical for multi-tenant applications?

Without strict namespace partitioning or cryptographic metadata filtering, semantic similarity searches can retrieve chunks belonging to different customer tenants. Enforcing tenant access control boundaries at query time eliminates lateral information leakage across organizational boundaries.

### What defensive capabilities does the exported middleware blueprint provide?

Generating a defensive middleware artifact with the -e parameter provides a drop-in Python guard class that scrubs injection patterns and normalizes delimiters prior to prompt assembly. This runtime sanitization layer catches adversarial instruction resets and credential extraction queries before they reach the model.

### Can the toolkit enforce security compliance within automated CI/CD pipelines?

The CLI tools accept pipeline parameter levels or configuration files, emitting machine-readable results with the -j flag. Automated testing jobs can programmatically inspect the resulting JSON scores to block deployments failing to meet minimum hardening thresholds.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
