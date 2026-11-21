# RAG Pipeline Security Validator & Defense Hardening Toolkit - TAVARDT United States

> Context Isolation Audit, Indirect Injection Prevention, and Defensive AI Engineering

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-usa.github.io/rag-security-hardener-us/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: OWASP LLM](https://img.shields.io/badge/Security-OWASP%20LLM01%20%7C%20LLM02-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Architecture & RAG Security Overview

Retrieval-Augmented Generation (RAG) pipelines introduce critical security boundaries to enterprise AI systems. By retrieving and injecting external documents, files, and database records directly into language model prompts, applications face severe threats from Indirect Prompt Injections (OWASP LLM01) and Multi-Tenant Vector Leaks (OWASP LLM02).

This repository provides both an interactive client-side web application and a lightweight, zero-dependency Python CLI tool to audit RAG architectures and export defensive hardening blueprints.

## Interactive Web Application (GitHub Pages)

Access the live online tool and evaluate your pipeline architecture in real-time:

- [https://tavardt-usa.github.io/rag-security-hardener-us/](https://tavardt-usa.github.io/rag-security-hardener-us/)

## Python CLI Scanner Usage

The `rag_security_hardener.py` CLI script operates exclusively with Python's standard library (no external packages) and integrates cleanly into CI/CD security validation pipelines.

```bash
# Executar avaliacao interativa com parametros padrao
python rag_security_hardener.py

# Exportar middleware defensivo para uso imediato em seu pipeline
python rag_security_hardener.py --export-blueprint secure_rag_middleware.py

# Executar auditoria em modo JSON para integracao em CI/CD
python rag_security_hardener.py --ingestion 3 --vector-db 3 --context-boundary 3 --indirect-filter 3 --json
```

## Architectural Controls & Defensive Mitigations

1. **Context Containment Boundary**: Enforces strict encapsulation of retrieved context using XML containment tags (`<untrusted_context>`) with instruction-impermeable system prompts.
2. **Indirect Injection Defense**: Heuristic pattern filters that sanitize embedded commands and semantic anomalies before context injection.
3. **Multi-Tenant Vector Isolation**: Strict namespace partitioning and cryptographically verified role-based access control (RBAC) at query execution.
4. **Output Gate & Citation Enforcement**: Mandatory attribution validation and regex-based sensitive data masking prior to final response delivery.

## Official Portals

- **Official TAVARDT Portal**: [https://ag.tavardt.com/](https://ag.tavardt.com/)
- **Tools Hub**: [https://tools.tavardt.com/](https://tools.tavardt.com/)
- **Contact**: [https://ag.tavardt.com/contact/](https://ag.tavardt.com/contact/)

---
&copy; 2026 TAVARDT United States. All rights reserved.
