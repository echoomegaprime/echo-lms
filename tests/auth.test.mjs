import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.ts';

function makeD1() {
  const stmt = {
    bind() { return stmt; },
    async run() { return { success: true }; },
    async all() { return { results: [] }; },
    async first() { return null; },
    async batch() { return []; },
  };
  return { prepare() { return stmt; }, batch: async () => [] };
}

function makeEnv(overrides = {}) {
  return {
    DB: makeD1(),
    CACHE: { get: async () => null, put: async () => {} },
    ENGINE_RUNTIME: { fetch: async () => new Response(JSON.stringify({ response: 'ok' })) },
    SHARED_BRAIN: { fetch: async () => new Response('ok') },
    EMAIL_SENDER: { fetch: async () => new Response('ok') },
    ECHO_API_KEY: 'test-echo-lms-key-9e3d',
    ...overrides,
  };
}

const ctx = { waitUntil() {}, passThroughOnException() {} };

test('GET /health and /status need no auth (unchanged public contract)', async () => {
  const env = makeEnv();
  for (const p of ['/', '/health', '/status']) {
    const res = await worker.fetch(new Request('https://x' + p), env, ctx);
    assert.notEqual(res.status, 401);
  }
});

test('GET /certificates/verify/:num needs no auth (unchanged public contract)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/certificates/verify/CERT-ABC-1234'), env, ctx);
  assert.notEqual(res.status, 401);
});

test('POST /webhooks/stripe needs no X-Echo-API-Key (has its own signature check)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/webhooks/stripe', { method: 'POST', body: '{}' }), env, ctx);
  assert.notEqual(res.status, 401);
});

test('a GET to a management endpoint with NO key is now rejected -- this repo previously exempted every GET from auth entirely', async () => {
  const env = makeEnv();
  const cases = [
    '/tenants/some-id',
    '/students',
    '/students/some-id/enrollments',
    '/analytics/overview',
    '/analytics/popular-courses',
    '/analytics/student-activity',
    '/courses',
    '/courses/some-id',
    '/courses/slug/some-slug',
    '/instructors',
    '/quizzes/some-id/attempts',
  ];
  for (const path of cases) {
    const res = await worker.fetch(new Request('https://x' + path), env, ctx);
    assert.equal(res.status, 401, `${path} should require auth now (was previously exempt as a GET)`);
  }
});

test('a GET to a management endpoint WITH the correct key is accepted', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/students', {
    headers: { 'X-Echo-API-Key': 'test-echo-lms-key-9e3d', 'X-Tenant-ID': 't1' },
  }), env, ctx);
  assert.notEqual(res.status, 401);
});

test('a GET to a management endpoint with the WRONG key is rejected', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/students', {
    headers: { 'X-Echo-API-Key': 'wrong-key', 'X-Tenant-ID': 't1' },
  }), env, ctx);
  assert.equal(res.status, 401);
});

test('a POST management endpoint still requires auth (unchanged)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/tenants', {
    method: 'POST',
    body: JSON.stringify({ name: 'x' }),
    headers: { 'Content-Type': 'application/json' },
  }), env, ctx);
  assert.equal(res.status, 401);
});

test('GET /public/course/:id still needs no auth (unchanged storefront contract)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x/public/course/some-id'), env, ctx);
  assert.notEqual(res.status, 401);
});

test('key-length side-channel: a same-length wrong key and a different-length wrong key both fail identically', async () => {
  const env = makeEnv();
  for (const key of ['test-echo-lms-key-XXXX', 'x']) {
    const res = await worker.fetch(new Request('https://x/students', { headers: { 'X-Echo-API-Key': key } }), env, ctx);
    assert.equal(res.status, 401);
  }
});
