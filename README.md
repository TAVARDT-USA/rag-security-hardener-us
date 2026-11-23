# RAG Security & Context Hardening Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/rag-security-hardener-us/)
[![Jurisdiction](https://img.shields.io/badge/Jurisdiction-USA-00C853.svg)](https://ag.tavardt.com/us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![OWASP LLM](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20Matrix-orange.svg)](https://atlas.mitre.org/)

**Corporate Defensive Architecture Hub and Hardening Blueprints for RAG (Retrieval-Augmented Generation) Pipelines**

Developed and maintained by the Artificial Intelligence Security Engineering Division of **[TAVARDT USA](https://ag.tavardt.com/us/)**.

***

## Official Portals

* **Institutional Portal**: [https://ag.tavardt.com/us/](https://ag.tavardt.com/us/)
* **Tools Center**: [https://tools.tavardt.com/us/](https://tools.tavardt.com/us/)
* **Contact and Technical Support**: [https://ag.tavardt.com/us/contact/](https://ag.tavardt.com/us/contact/)

***

## Online Demonstration & Defensive Architecture Hub

You can inspect the technical defensive specifications, architectural diagnostic tests, and mitigation blueprints directly in your browser:

* **[Official Web Application on GitHub Pages](https://tavardt-usa.github.io/rag-security-hardener-us/)**
* **[TAVARDT Tools Center](https://tools.tavardt.com/us/)**

> [!NOTE]
> **Technical Execution Scope:** This web hub provides defensive architecture specifications and hardening configuration blueprints. Active vector database audits and host pipeline scans require environment credentials and network connectivity via the provided deterministic Python CLI tool (`rag_security_auditor.py`). Web pages running in browser sandboxes cannot connect directly to private vector clusters.

***

## Hardening Blueprints Included

1. **rag-security-policy.yml:** Corporate security policies defining chunk limits, XML context isolation tags, and semantic validation rules.
2. **rag_chunk_sanitizer.py:** Sanitization pipeline stripping invisible Unicode characters, control codes, and prompt injection markers prior to embedding generation.
3. **vector_acl_filter.json:** Vector database query schema enforcing mandatory metadata access control (RBAC/ACL) per user and tenant to prevent cross-tenant exfiltration.
4. **rag_context_template.xml:** Context encapsulation template bounded by XML tags with strict non-execution directives for LLM engines.
5. **rag_security_auditor.py:** Deterministic local CLI utility running in the application environment to audit pipeline configurations and verify OWASP LLM compliance.

***

## Deterministic CLI Utility Usage

Run the deterministic audit script directly in the RAG application environment:

```bash
# 1. Download audit script from official repository
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/rag-security-hardener-us/main/rag_security_auditor.py

# 2. Inspect pipeline configuration and defensive blueprints
python3 rag_security_auditor.py

# 3. Output results in machine-readable JSON format
python3 rag_security_auditor.py -json
```

***

## Governance and Sovereignty

* **Organization:** TAVARDT-USA
* **Jurisdiction:** USA
* **Standards Compliance:** OWASP Top 10 for LLM Applications (LLM01, LLM07), MITRE ATLAS Framework, and Zero Trust Architecture.

Developed by the AI Security & Infrastructure Division of **[TAVARDT USA](https://ag.tavardt.com/us/)**. All rights reserved.
