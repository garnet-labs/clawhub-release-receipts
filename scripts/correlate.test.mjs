import assert from 'node:assert/strict';
import test from 'node:test';
import { correlateCohort, correlateRelease } from './correlate.mjs';

const finding = index => `/scanners/aig-mcp/raw/runs/0/results/${index}`;
const expected = {
  repository: 'example/releases', run_id: '42', profile_id: 'profile', job: 'install',
  head_sha: 'head', commit_sha: 'commit', job_index: 1,
};
const step = '03. Install and list plugins';
const phase = 'install';
const connection = (host, process = 'node', github_step = step) => ({
  remote_names: [host], ancestry: ['runner', 'Runner.Worker', process], lineage_recorded: true, github_step,
  timestamp: '2026-11-23T21:26:01Z',
});
const rule = (id, target, source, pointer, chainSuffix = ['node']) => ({
  id, kind: 'connection', phase, target, chainSuffix, evidence: { source, pointer },
});

function input() {
  return {
    release: 'package@1.0.0', reviewedRules: true,
    sources: {
      clawscan: {
        schemaVersion: 'clawscan-run-v1', complete: true,
        scanners: { 'aig-mcp': { status: 'completed', raw: { runs: [{ results: [{ ruleId: 'A' }, { ruleId: 'B' }, { ruleId: 'C' }] }] } } },
      },
      manifest: { network: 'registry.example' }, package: {}, audit: { vulnerabilities: {} },
    },
    runtime: {
      expected, capture: 'best-effort', actionTypes: ['connection', 'file-write'],
      windows: [{ step, phase, covered: true, started_at: '2026-11-23T21:26:00Z', completed_at: '2026-11-23T21:26:02Z' }],
      payload: { profile: { run: expected, associations: [
        connection('matched.example'), connection('registry.example'), connection('unexpected.example', 'child'),
        { ...connection('background.example', 'runner', '99. Runner Processes'), ancestry: ['systemd', 'runner'] },
      ] } },
    },
    rules: [
      rule('finding-a', 'matched.example', 'clawscan', finding(0)),
      rule('registry', 'registry.example', 'manifest', '/network'),
      rule('destination-only', 'unexpected.example', 'clawscan', finding(1), []),
    ],
    applicabilityByFinding: {
      [finding(1)]: { phase, kind: 'connection' },
      [finding(2)]: { phase: 'credentialed-use', kind: 'connection' },
    },
  };
}

test('labels strong matches and keeps weak matches in the new-only card', () => {
  const result = correlateRelease(input());
  assert.deepEqual(result.rows.map(row => row.label), ['confirmed', 'explained', 'new']);
  assert.deepEqual(result.card.map(row => row.targets[0]), ['unexpected.example']);
  assert.equal(result.card[0].matches[0].strength, 'weak');
  assert.deepEqual(result.reverse.map(finding => finding.state), ['observed', 'not observed', 'out of window']);
  assert.deepEqual(result.observedTypes, ['connection']);
  assert.equal(result.excluded, 1);
});

test('same destination alone cannot override a different chain or phase', () => {
  const value = input();
  value.runtime.payload.profile.associations[0].ancestry = ['runner', 'Runner.Worker', 'different'];
  assert.equal(correlateRelease(value).rows[0].label, 'new');
  value.runtime.payload.profile.associations[0].ancestry = ['runner', 'Runner.Worker', 'node'];
  value.runtime.windows[0].phase = 'first-load';
  assert.equal(correlateRelease(value).rows[0].label, 'new');
});

test('missing advisory and mismatched receipt do not get counted as clean releases', () => {
  const stale = input();
  stale.runtime.expected = { ...expected, head_sha: 'stale' };
  const noAudit = input();
  noAudit.sources.audit = null;
  const result = correlateCohort([input(), stale, noAudit]);
  assert.equal(result.releases[1].card, null);
  assert.equal(result.releases[2].card, null);
  assert.deepEqual(result.summary, {
    cohortReleases: 3, comparableReleases: 1, agreement: 1, newRows: 1,
    releasesWithNewRows: 1, staticOnly: 2, staticOnlyNotObserved: 1, staticUndeterminable: 3,
  });
  assert.equal(correlateCohort([stale]).summary.newRows, null);
});

test('cannot cite a verdict or a nonexistent JSON pointer as matching evidence', () => {
  const value = input();
  value.rules[0].evidence.pointer = '/complete';
  assert.throws(() => correlateRelease(value), /not a ClawScan finding/);
  value.rules[0].evidence.pointer = '/missing';
  assert.throws(() => correlateRelease(value), /not found/);
});

test('scope follows the timestamp and worker chain, not the recorded step label', () => {
  const value = input();
  const [row, noTime, noWindow, substrate] = value.runtime.payload.profile.associations;
  row.github_step = '99. Runner Processes';
  delete noTime.timestamp;
  noWindow.timestamp = '2026-11-23T21:26:02Z';
  substrate.github_step = step;
  value.runtime.payload.profile.timestamp = '2026-11-23T21:26:01Z';
  const result = correlateRelease(value);
  assert.deepEqual(result.rows.map(row => row.phase), ['install', 'job']);
  assert.equal(result.rows[0].label, 'confirmed');
  assert.equal(result.substrate, 1);
  assert.equal(result.excluded, 2);
  assert.equal(result.untimestamped, 1);
  assert.equal(result.reverse[1].state, 'undeterminable');
});

test('reports the workload split without implying complete comparison coverage', () => {
  const value = input();
  delete value.runtime.capture;
  const ungraded = correlateRelease(value);
  assert.equal(ungraded.workload, 3);
  assert.deepEqual(ungraded.rows, []);
  assert.equal(ungraded.card, null);
  value.runtime.capture = 'best-effort';
  value.runtime.payload.profile.associations.splice(0, 3);
  const substrateOnly = correlateRelease(value);
  assert.equal(substrateOnly.workload, 0);
  assert.equal(substrateOnly.substrate, 1);
  assert.equal(substrateOnly.card, null);
});

test('network rules can require a protocol and port as well as a chain', () => {
  const value = input();
  Object.assign(value.rules[1], { protocol: 'UDP', port: '53' });
  const row = value.runtime.payload.profile.associations[1];
  Object.assign(row, { protocol: 'TCP', remote_ports: ['53 (dns)'] });
  assert.equal(correlateRelease(value).rows[1].label, 'new');
  row.protocol = 'UDP';
  assert.equal(correlateRelease(value).rows[1].label, 'explained');
});
