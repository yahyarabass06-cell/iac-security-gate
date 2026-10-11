# Evaluation

## Scope

Evaluation covers the Python application's report validation, comparison,
exception handling, policy decisions and output behavior.

The latest observed local suite passed 196 tests.
This is regression-test evidence, not a measurement of real-world security
coverage or Trivy detection accuracy.

## Captured Scanner Evidence

Two synthetic Terraform configurations were scanned with Trivy 0.75.0.

| Configuration | Observed AWS-0107 findings | Severity |
| --- | --- | --- |
| Unrestricted SSH ingress, 0.0.0.0/0 | 1 | HIGH |
| Restricted SSH ingress, 10.10.10.0/24 | 0 | Not applicable |

The restricted example's absence of this finding does not establish overall
security. These two examples are insufficient to estimate precision, recall
or false-positive rates.

Fixture metadata records input and report SHA-256 fingerprints.
The scanner version is recorded; downloaded rule bundles are not pinned.

## Tested Decision Scenarios

| Scenario | Expected behavior |
| --- | --- |
| Restricted baseline to unrestricted current scan | Added finding; blocked |
| Unrestricted baseline to restricted current scan | Removed finding; passed |
| Identical unrestricted reports | Unchanged finding; still blocked |
| Active exact exception | Finding retained as excepted; policy passed |
| Exception on its expiration date | Exception expired; finding blocked |
| HIGH exception with CRITICAL current finding | Exception unmatched; blocked |
| Duplicate finding identity | Analysis rejected |
| Inconsistent failure count | Report rejected |
| Different scanner versions | Comparison rejected |
| Different roots without explicit allowance | Comparison rejected |
| Existing export destination | Preserved; output error |
| Filesystem publication failure | Temporary file cleaned up |

Unit tests cover individual rules. Integration tests connect the reader,
comparison, policy, exceptions, report builder and CLI.

## Reproducibility

A clean local Git clone was installed non-editably in a fresh Python 3.14
environment using requirements-dev.lock.

Dependency checks, Ruff, all 196 tests, the installed CLI and an exported
blocking assessment succeeded.

GitHub Actions is configured for Python 3.12 and 3.14.
Remote outcomes must be verified after publication.

## Future Measurements

For broader decision evaluation, define expected outcomes independently
before running the application, then report incorrect passes, incorrect
blocks and explicit analysis errors separately.

For performance, measure representative report sizes and finding densities.
Record hardware, Python version, input size, peak memory and repeated timings.
Separate parsing, comparison, serialization and complete CLI execution.

No application throughput, memory ceiling or production-scale performance
claim is made from the current test-suite duration.
