# Security Considerations

## Intended Use

This is an educational defensive tool for authorized Terraform scan reports.
Bundled examples are synthetic and must not be deployed.

The application evaluates supplied reports. It does not inspect live cloud
resources or establish that the reports are authentic or complete.

## Protect Inputs and Outputs

Reports can disclose resource names, file paths and configuration details.

- Keep real reports and Terraform state files outside public repositories.
- Share synthetic reproductions when reporting issues.
- Run the application without administrator privileges.
- Use input and output directories you control.
- Review generated assessments before sharing them.

Git ignore rules do not remove files already tracked by Git and do not
provide access control.

## Protect Gate Configuration

Policy, exception and baseline changes affect security decisions.
Review changes to these files and to the workflow that invokes the gate.

Exceptions are technical inputs, not proof of organizational approval.
Expired exceptions remain visible but cannot suppress findings.
An exception matches one identity and one exact severity.

Historical replay can override the evaluation date. Operational CI must use
the current date, not a historical override.

## Understand Scan Coverage

Matching scanner versions do not guarantee identical rules or scan settings.
Root-change allowance does not prove equivalent scan scope.

Filters, ignored findings, incomplete coverage or modified input reports can
change results. A passing assessment is not a complete security certification.

SHA-256 identifies analyzed report bytes; it does not establish authenticity.

## Resource and Filesystem Boundaries

Reports are loaded into memory. Input size and nesting limits are not currently
enforced; evaluate resource usage before operational integration.

File export requires an existing user-controlled directory and a filesystem
supporting hard links. A completed temporary file is published exclusively.
Existing destination paths, including symlinks, are refused.

New files use owner-only permissions on POSIX systems.
Power-loss durability of the directory entry is not guaranteed.

## Dependencies and CI

The Python application has no third-party runtime dependencies.
The development snapshot pins versions without artifact hashes.

CI actions are pinned to commits. Review dependency and action updates before
accepting them and rerun quality checks.

Captured-report tests validate the Python application. They do not validate
the current state or security of the Trivy distribution or downloaded rules.

## Reporting a Vulnerability

Do not publish credentials, real infrastructure reports or sensitive details.

Use GitHub private vulnerability reporting if enabled. Otherwise, request
a private reporting channel without disclosing the vulnerability publicly.

Provide the affected commit, a minimal synthetic reproduction, expected
behavior and observed behavior.
