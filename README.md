# Plugin releases

Each case pins a ClawHub plugin version. The install workflow uses OpenClaw
2026.11.7 and Node 24.22.3 and runs the standard
`openclaw plugins install 'clawhub:<package>@<version>'` followed by
`openclaw plugins list`. A separate step allows only the selected plugin,
enables it, starts a loopback-only Gateway without credentials, and stops it
after startup and a short observation window. Neither listing nor startup
asserts that the plugin's feature works. The job records an ordinary install
result, including a refusal or failure; it never acknowledges a safety warning
for the operator.

The recording action runs on the ephemeral runner. Plugin commands run in a
fresh unprivileged container without host mounts or the runner environment.
The bridge blocks direct access to the runner and common private/metadata
ranges; it is not a public egress allowlist. Third-party pull requests do not
run these jobs. Static-only releases are never part of the install matrix.

Under `clawscan/<case>/<version>/scan.json`, the scan summaries retain
the input SHA-256, tool version, measured wall time, status, and verdict.
They omit model-generated findings, logs, paths, and environment values. The
archives are fetched from the registry and not committed. The stock profile
ran locally through the Gateway with overlapping wall-clock timings; these
are not production registry audit records. The install workflow resolves
the same pinned version separately; it does not consume the local scan bytes.

No runtime result is asserted until the workflow runs and the receipt is
checked against the corresponding commit and job.

## Compare observations with existing evidence

After a receipt is finalized, run `node scripts/correlate.mjs <inputs.json>`.
The input is an array of objects with a `release` label and:

- `sources`: relative JSON files for `clawscan` (the private stock run
  artifact with scanner findings), `manifest`, `package`, and `audit`.
  Supply npm advisory JSON only if `npm audit --json` ran against a lock
  verified to describe the actual installed tree. If the install didn't
  produce that lock or there was no usable advisory output, pass `null`.
  Docs or inspected source may be supplied as additional JSON sources.
- `runtime`: `profileFile`, independently verified `expected` run identity
  (repository, run_id, profile_id, job, head_sha, commit_sha, job_index for
  matrix receipts), `capture` (complete or best-effort), observed
  `actionTypes`, and exact `windows` entries with `step` and `phase`
  (install or first-load); set `covered: true` only for verified windows.
  Include a channel only if the recorder actually
  reported it. Do not infer writes or child starts from a network receipt.
- `rules`: reviewed entries with `id`, `kind`, `phase`, `target`,
  `chainSuffix`, and `evidence` containing `source` and a JSON
  `pointer`. A static rule references a specific finding, not the verdict.
  For example, explain registry traffic only from an installer step and
  reviewed execution chain, not from the hostname alone. A dependency or an
  advisory alone does not show what code ran. Set `reviewedRules` only after
  checking the evidence and chain against the receipt.
- `applicabilityByFinding`: reviewed finding pointers with expected
  `phase` and `kind` for the reverse comparison.

Matching requires the same action, target, phase, and exact chain suffix.
A hostname-only match is weak and never removes a row from the new-only
card. Rows without a verified workload step and lineage are excluded, not
declared new. Missing inputs make the card unavailable, not empty. Counts
cover only comparable releases and are scoped to the evidence supplied;
“not observed” is not “did not happen,” and “new” is not “malicious.”
