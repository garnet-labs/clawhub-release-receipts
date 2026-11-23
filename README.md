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

The recording action runs on the ephemeral runner. Plugin commands run in
the job step as a separate, unprivileged Linux user with a fresh home and
without inheriting the runner environment. The Gateway binds only to
loopback; this workflow does not restrict outgoing traffic. Third-party
pull requests do not run these jobs. JEP Guard and Louter are static-only:
the workflow checks their tracked scan summaries without installing them.

Under `clawscan/<case>/<version>/scan.json`, the scan summaries retain
the input SHA-256, tool version, measured wall time, status, and verdict.
They omit model-generated findings, logs, paths, and environment values. The
archives are fetched from the registry and not committed. The stock profile
ran locally through the Gateway with overlapping wall-clock timings; these
are not production registry audit records. After the standard install,
the workflow downloads the same pinned release artifact separately and
requires its SHA-256 to match the tracked scan summary.

No runtime result is asserted until the workflow runs and the receipt is
checked against the corresponding commit and job.

## Compare observations with existing evidence

After a receipt is finalized, run `node scripts/correlate.mjs <inputs.json>`.
The input is an array of objects with a `release` label and:

- `sources`: relative JSON files for `clawscan` (the private stock run
  artifact with scanner findings), `manifest`, `package`, and `audit`.
  Supply npm advisory JSON for a resolved lock. State whether the lock
  describes the recorded install or a separate local resolution from the
  same archive; a local resolution does not prove the CI transitive tree.
  If there was no usable advisory output, pass `null`.
  Docs or inspected source may be supplied as additional JSON sources.
- `runtime`: `profileFile`, independently verified `expected` run identity
  (repository, run_id, profile_id, job, head_sha, commit_sha, job_index for
  matrix receipts), `capture` (complete or best-effort), observed
  `actionTypes`, and exact GitHub job step `windows` entries with `phase`
  (install or first-load), `started_at`, and `completed_at`; set
  `covered: true` only for verified windows. A row without its own
  timestamp is scoped to the whole `job`, not inferred from the profile
  timestamp or the recorded step label.
  Include a channel only if the recorder actually
  reported it. Do not infer writes or child starts from a network receipt.
- `rules`: reviewed entries with `id`, `kind`, `phase`, `target`,
  `chainSuffix`, optional `protocol` and `port`, and `evidence` containing `source` and a JSON
  `pointer`. A static rule references a specific finding, not the verdict.
  For example, explain registry traffic only from an installer step and
  reviewed execution chain, not from the hostname alone. A dependency or an
  advisory alone does not show what code ran. Set `reviewedRules` only after
  checking the evidence and chain against the receipt.
- `applicabilityByFinding`: reviewed finding pointers with expected
  `phase` and `kind` for the reverse comparison.

Matching requires the same action, target, phase, and exact chain suffix.
A hostname-only match is weak and never removes a row from the new-only
card. Only recorded lineages that pass through `Runner.Worker` are in
scope. This is narrower than the App's workload predicate. Missing inputs
make the card unavailable, not empty. Counts
cover only comparable releases and are scoped to the evidence supplied;
“not observed” is not “did not happen,” and “new” is not “malicious.”
