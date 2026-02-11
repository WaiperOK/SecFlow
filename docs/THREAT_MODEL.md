# Threat Model

## Assets
- Security finding reports and CI gate decisions.
- Scanner execution context and configuration files.

## Threats
- Command injection through scanner command construction.
- False-negative masking via unsafe configuration overrides.
- Leakage of sensitive findings through uncontrolled report destinations.

## Mitigations
- Subprocess execution with explicit argument lists.
- Structured config validation via Pydantic models.
- Optional integration surfaces separated from core package import path.
