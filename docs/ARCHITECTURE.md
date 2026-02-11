# Architecture

## Core
- `pyseckit/core/`: base scanner abstractions, finding model, config.
- `pyseckit/sast/`, `pyseckit/dast/`, `pyseckit/secret_scan/`, `pyseckit/cloud/`: scanner adapters.
- `pyseckit/reporting/`: report generation (JSON/HTML/CSV/XML).
- `pyseckit/cli.py`: command entrypoint for scan orchestration.

## Optional
- `pyseckit/web/`: Flask-based management endpoints and dashboard blueprint.
- `pyseckit/integrations/`: notification and Elasticsearch integration hooks.
- `pyseckit/plugins/`: extension mechanism for custom scanners.

## Data flow
```mermaid
flowchart LR
  A["Target Path"] --> B["Scanner Adapter"]
  B --> C["ScanResult"]
  C --> D["Severity + Policy Evaluation"]
  C --> E["Report Export"]
  C --> F["Notification / Storage Integrations"]
```
