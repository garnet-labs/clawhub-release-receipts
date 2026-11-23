import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

function chainMatches(chain, suffix) {
  return Array.isArray(suffix) && suffix.length > 0 && suffix.length <= chain.length
    && suffix.every((segment, index) => chain[chain.length - suffix.length + index] === segment);
}

function strings(value) {
  return Array.isArray(value) ? value.filter(item => typeof item === 'string' && item.length > 0) : [];
}

function findings(artifact) {
  if (artifact?.schemaVersion !== 'clawscan-run-v1' || artifact.complete !== true) return null;
  const scanner = artifact.scanners?.['aig-mcp'];
  if (scanner?.status !== 'completed') return null;
  const runs = scanner.raw?.runs;
  if (!Array.isArray(runs)) return null;
  return runs.flatMap((run, i) => (run.results ?? []).map((finding, j) => ({
    id: `/scanners/aig-mcp/raw/runs/${i}/results/${j}`,
    ruleId: finding.ruleId ?? null,
  })));
}

function profileBinding(profile, expected) {
  if (!profile || !expected) return false;
  const run = profile.run;
  const fields = ['repository', 'run_id', 'profile_id', 'job', 'head_sha', 'commit_sha'];
  return fields.every(key => typeof expected[key] === 'string' && expected[key].length > 0
    && String(run?.[key]) === expected[key])
    && (expected.job_index === undefined || Number.isInteger(expected.job_index) && run.job_index === expected.job_index);
}

function time(value) {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(value)
    ? Date.parse(value) : NaN;
}

function phaseFor(record, windows) {
  if (record.timestamp == null) return 'job';
  const observed = time(record.timestamp);
  const matches = windows.filter(window => observed >= time(window.started_at)
    && observed < time(window.completed_at));
  return matches.length === 1 ? matches[0].phase : null;
}

function profileActions(profile, types, windows) {
  const records = [
    ['connection', 'associations', row => strings(row.remote_names).length > 0
      ? strings(row.remote_names) : strings([row.remote_address])],
    ['file-write', 'file_writes', row => strings([row.path])],
    ['child-process', 'child_processes', row => strings([row.process])],
  ];
  const rows = [];
  let excluded = 0;
  let substrate = 0;
  let untimestamped = 0;
  for (const [kind, key, targetsFor] of records) {
    if (!types.includes(kind) || !Array.isArray(profile[key])) continue;
    profile[key].forEach((record, index) => {
      if (record.timestamp == null) untimestamped += 1;
      const chain = strings(record.ancestry);
      const targets = targetsFor(record);
      if (record.lineage_recorded === true && chain.length > 0 && !chain.includes('Runner.Worker')) {
        substrate += 1;
      }
      const phase = phaseFor(record, windows);
      if (phase === null || record.lineage_recorded !== true || !chain.includes('Runner.Worker')
        || targets.length === 0) {
        excluded += 1;
        return;
      }
      const network = kind === 'connection' ? { protocol: record.protocol, ports: strings(record.remote_ports) } : {};
      rows.push({ kind, targets, chain, phase, ...network, pointer: `/profile/${key}/${index}` });
    });
  }
  return { rows, excluded, substrate, untimestamped };
}

function valueAt(source, pointer) {
  if (pointer === '') return source;
  if (!pointer.startsWith('/')) return undefined;
  return pointer.slice(1).split('/').reduce((value, segment) => {
    const key = segment.replaceAll('~1', '/').replaceAll('~0', '~');
    return value !== null && typeof value === 'object' && Object.hasOwn(value, key) ? value[key] : undefined;
  }, source);
}

function applicability(rule, sources, staticIds) {
  const { source, pointer } = rule.evidence ?? {};
  if (typeof pointer !== 'string' || !Object.hasOwn(sources, source)) throw Error('Invalid evidence reference');
  if (valueAt(sources[source], pointer) === undefined || sources[source] === null) throw Error('Evidence pointer not found');
  if (source === 'clawscan' && !staticIds.has(pointer)) throw Error('Reference is not a ClawScan finding');
  return source === 'clawscan' ? 'confirmed' : 'explained';
}

function matchRule(row, rule) {
  if (row.kind !== rule.kind || row.phase !== rule.phase || !row.targets.includes(rule.target)) return null;
  if (rule.protocol !== undefined && row.protocol !== rule.protocol) return null;
  if (rule.port !== undefined && !row.ports?.some(port => port.split(' ')[0] === rule.port)) return null;
  if (rule.kind === 'connection' && !rule.chainSuffix?.length) return 'weak';
  return chainMatches(row.chain, rule.chainSuffix) ? 'strong' : null;
}

export function correlateRelease(input) {
  const { release, runtime = {}, sources = {}, rules = [], applicabilityByFinding = {} } = input;
  const profile = runtime.payload?.profile;
  const staticFindings = findings(sources.clawscan);
  const staticIds = new Set((staticFindings ?? []).map(finding => finding.id));
  const windows = (runtime.windows ?? []).filter(window => window.covered === true);
  const bound = profileBinding(profile, runtime.expected);
  const observedTypes = bound ? (runtime.actionTypes ?? []).filter(kind => {
    const field = { connection: 'associations', 'file-write': 'file_writes', 'child-process': 'child_processes' }[kind];
    return typeof field === 'string' && Array.isArray(profile[field]);
  }) : [];
  const hasRuntime = observedTypes.length > 0 && ['best-effort', 'complete'].includes(runtime.capture);
  const applicable = rules.map(rule => ({
    ...rule,
    label: applicability(rule, sources, staticIds),
  }));
  const { rows, excluded, substrate, untimestamped } = observedTypes.length > 0
    ? profileActions(profile, observedTypes, windows)
    : { rows: [], excluded: 0, substrate: 0, untimestamped: 0 };
  const hasJobRows = rows.some(row => row.phase === 'job');
  const classified = (hasRuntime ? rows : []).map(row => {
    const matches = applicable.flatMap(rule => {
      const strength = matchRule(row, rule);
      return strength === null ? [] : [{ rule: rule.id, evidence: rule.evidence, strength, label: rule.label }];
    });
    const label = matches.some(match => match.strength === 'strong' && match.label === 'confirmed')
      ? 'confirmed'
      : matches.some(match => match.strength === 'strong' && match.label === 'explained') ? 'explained' : 'new';
    return { ...row, label, matches, ...(label === 'new' ? { rule: 'no-strong-match-in-supplied-evidence' } : {}) };
  });
  const reverse = (staticFindings ?? []).map(finding => {
    const matches = classified.filter(row => row.matches.some(match => match.strength === 'strong'
      && match.evidence.source === 'clawscan' && match.evidence.pointer === finding.id));
    const scope = applicabilityByFinding[finding.id];
    const observedWindow = scope && (scope.phase === 'job' || windows.some(window => window.phase === scope.phase));
    const state = matches.length > 0 ? 'observed'
      : !hasRuntime || !scope || scope.phase !== 'job' && hasJobRows ? 'undeterminable'
        : !observedWindow ? 'out of window'
          : observedTypes.includes(scope.kind) ? 'not observed' : 'undeterminable';
    return { ...finding, state, runtime: matches.map(row => row.pointer) };
  });
  const audit = sources.audit;
  const auditAvailable = audit !== null && typeof audit === 'object' && typeof audit.vulnerabilities === 'object'
    && audit.vulnerabilities !== null && !audit.error;
  const statuses = {
    runtime: hasRuntime ? runtime.capture : 'undeterminable',
    static: staticFindings === null ? 'undeterminable' : 'complete',
    advisory: auditAvailable ? 'available' : 'undeterminable',
    manifest: sources.manifest && sources.package ? 'available' : 'undeterminable',
  };
  const eligible = hasRuntime && rows.length > 0 && staticFindings !== null && statuses.manifest === 'available'
    && auditAvailable && input.reviewedRules === true;
  return {
    release, statuses, eligible, observedTypes, excluded, substrate, untimestamped, workload: rows.length,
    // Unavailable evidence is never rendered as an empty, successful card.
    card: eligible ? classified.filter(row => row.label === 'new') : null,
    rows: classified, reverse,
    caveat: 'New means no strong match in the supplied evidence. Not observed is scoped to capture and is not evidence of absence.',
  };
}

export function correlateCohort(inputs) {
  const releases = inputs.map(correlateRelease);
  const eligible = releases.filter(release => release.eligible);
  const sum = (records, count) => records.reduce((total, record) => total + count(record), 0);
  const countComparable = count => eligible.length === 0 ? null : sum(eligible, count);
  return {
    releases,
    summary: {
      cohortReleases: releases.length,
      comparableReleases: eligible.length,
      agreement: countComparable(release => release.reverse.filter(finding => finding.state === 'observed').length),
      newRows: countComparable(release => release.card.length),
      releasesWithNewRows: countComparable(release => Number(release.card.length > 0)),
      staticOnly: countComparable(release => release.reverse.filter(finding => ['not observed', 'out of window'].includes(finding.state)).length),
      staticOnlyNotObserved: countComparable(release => release.reverse.filter(finding => finding.state === 'not observed').length),
      staticUndeterminable: sum(releases, release => release.reverse.filter(finding => finding.state === 'undeterminable').length),
    },
  };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function loadInputs(path) {
  const base = dirname(resolve(path));
  return readJson(path).map(input => ({
    ...input,
    sources: Object.fromEntries(Object.entries(input.sources ?? {}).map(([name, file]) =>
      [name, file === null ? null : readJson(resolve(base, file))])),
    runtime: {
      ...input.runtime,
      payload: input.runtime?.profileFile ? readJson(resolve(base, input.runtime.profileFile)) : null,
    },
  }));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length !== 3) throw Error('Usage: node scripts/correlate.mjs <inputs.json>');
  console.log(JSON.stringify(correlateCohort(loadInputs(process.argv[2])), null, 2));
}
