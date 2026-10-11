# MVP Scope

## Goal

Evaluate Terraform misconfiguration reports produced by Trivy.
Identify security regressions and make explainable CI decisions.

All examples use synthetic local configurations.
No cloud account or deployment is required.

## Processing steps

1. Load and validate a Trivy JSON report.
2. Normalize failed misconfiguration findings.
3. Compare current findings with a baseline.
4. Apply explicitly scoped, justified and time-limited exceptions.
5. Evaluate a configurable blocking policy.
6. Produce a report explaining the decision.

## Normalized finding

A finding will contain:

- Check identifier.
- Repository-relative target path.
- Resource identifier when available.
- Severity.
- Title and description.
- Source line range when available.

Unsupported or missing critical fields must produce an explicit error.
Optional fields must not be invented.

## Comparison

Finding identity will use the check identifier, target path and resource
identifier. Source line numbers are evidence, not stable identity.

Ambiguous identities must be detected rather than silently merged.
Severity changes must be reported separately from newly introduced findings.

A baseline represents previous findings, not proof that they are acceptable.

## Exceptions

Each exception must specify its scope, justification and expiration date.
Expired exceptions must not suppress findings.

## CI outcome

Distinguish:

- Policy passed.
- Policy blocked.
- Analysis failed.

An analysis failure must never be presented as a passed security assessment.

## Validation

Use synthetic safe and unsafe Terraform examples, captured scanner reports,
unit tests and integration tests.

Record the scanner version and scan settings used for comparisons.
Evaluate false positives and comparison limitations explicitly.

## Out of scope

- Cloud deployment.
- Automatic infrastructure changes.
- Vulnerability exploitation.
- Machine learning.
- A complete cloud security assessment.
