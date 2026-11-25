# RAG Security & Context Hardening Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/rag-security-hardener-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Corporate Defensive Architecture Hub and Hardening Blueprints for RAG (Retrieval-Augmented Generation) Pipelines**

***

## Online Demonstration

You can inspect the technical defensive specifications, architectural diagnostic tests, and mitigation blueprints directly in your browser:

* **[Official Web Application on GitHub Pages](https://tavardt-usa.github.io/rag-security-hardener-us/)**

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

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License.

***

© 2026 TAVARDT. All rights reserved.
