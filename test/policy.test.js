import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compilePolicy, evaluate, validatePolicy } from '../src/policy.js';

const policy = compilePolicy({
  rules: [
    { name: 'blocked', email: '^shared\\.', deny: true, message: 'Shared accounts cannot use WiFi.' },
    { name: 'staff', orgUnit: '/Staff/', vlanId: 20 },
    { name: 'students', orgUnit: '/Students', vlanId: 30 },
  ],
  default: null,
});

test('first matching rule wins', () => {
  assert.equal(evaluate(policy, { email: 'shared.lab@x.org', orgUnitPath: '/Staff' }).allow, false);
  assert.equal(evaluate(policy, { email: 'a@x.org', orgUnitPath: '/Staff' }).rule.vlanId, 20);
});

test('org units match their children but not look-alike siblings', () => {
  assert.equal(evaluate(policy, { email: 'a@x.org', orgUnitPath: '/students/Grade 10' }).rule.name, 'students');
  assert.equal(evaluate(policy, { email: 'a@x.org', orgUnitPath: '/StudentsArchive' }).allow, false);
});

test('default: null denies anyone unmatched', () => {
  const d = evaluate(policy, { email: 'a@x.org', orgUnitPath: '/Visitors' });
  assert.equal(d.allow, false);
  assert.equal(d.rule, null);
});

test('no default configured lets everyone from an allowed domain on, on the WLAN VLAN', () => {
  const d = evaluate(compilePolicy({}), { email: 'a@x.org' });
  assert.equal(d.allow, true);
  assert.equal(d.rule.vlanId, undefined);
});

test('org-unit rules never match when the directory lookup is off', () => {
  const p = compilePolicy({ rules: [{ name: 'all', orgUnit: '/' }], default: null });
  assert.equal(evaluate(p, { email: 'a@x.org', orgUnitPath: undefined }).allow, false);
});

test('validation keeps the VLAN, drops unknown fields and refuses bad values', () => {
  const ok = validatePolicy({ rules: [{ name: 'Staff', orgUnit: '/Staff', vlanId: 20, extra: 'dropped' }] }, { directoryEnabled: true });
  assert.deepEqual(ok.policy.rules[0], { name: 'Staff', orgUnit: '/Staff', vlanId: 20 });
  const bad = validatePolicy({ rules: [{ name: 'X', vlanId: 0 }, { name: 'Y', orgUnit: 'Staff' }] }, { directoryEnabled: true });
  assert.equal(bad.problems.length, 2);
});
