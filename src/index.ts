import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  ECHO_API_KEY: string;
};

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});
app.use('*', cors());

// --- Helpers ---
function uid(): string { return crypto.randomUUID(); }
function sanitize(s: unknown, max = 2000): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max);
}
function sanitizeBody(b: Record<string, unknown>): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) o[k] = typeof v === 'string' ? sanitize(v) : v;
  return o;
}
function tid(c: any): string { return sanitize(c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || ''); }
function json(c: any, d: unknown, s = 200) { return c.json(d, s); }

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-lms', version: '1.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}


interface RLState { c: number; t: number }
async function rateLimit(env: Env, key: string, max: number, windowSec = 60): Promise<boolean> {
  const k = `rl:${key}`;
  const now = Date.now();
  const raw = await env.CACHE.get(k);
  let st: RLState = raw ? JSON.parse(raw) : { c: 0, t: now };
  const elapsed = (now - st.t) / 1000;
  const decay = Math.floor(elapsed * (max / windowSec));
  st.c = Math.max(0, st.c - decay);
  st.t = now;
  if (st.c >= max) return false;
  st.c++;
  await env.CACHE.put(k, JSON.stringify(st), { expirationTtl: windowSec * 2 });
  return true;
}

// Auth middleware
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status' || c.req.method === 'GET') return next();
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== c.env.ECHO_API_KEY) return json(c, { error: 'Unauthorized' }, 401);
  return next();
});

// Rate limiting
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status') return next();
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const max = c.req.method === 'GET' ? 200 : 60;
  if (!await rateLimit(c.env, `${ip}:${c.req.method}`, max)) return json(c, { error: 'Rate limited' }, 429);
  return next();
});

// Health
app.get('/', (c) => c.redirect('/health'));
app.get('/health', (c) => json(c, { status: 'ok', service: 'echo-lms', version: '1.0.0', timestamp: new Date().toISOString() }));
app.get('/status', (c) => json(c, { status: 'operational', service: 'echo-lms', version: '1.0.0' }));

// === TENANTS ===
app.post('/tenants', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO tenants (id,name,email,plan,max_courses,max_students) VALUES (?,?,?,?,?,?)').bind(id, b.name, b.email || null, b.plan || 'free', b.max_courses || 5, b.max_students || 50).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create tenant', { error: e.message });
    return json(c, { error: 'Failed to create tenant', detail: e.message }, 500);
  }
});
app.get('/tenants/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
  } catch (e: any) {
    slog('error', 'Failed to get tenant', { error: e.message });
    return json(c, { error: 'Failed to get tenant', detail: e.message }, 500);
  }
});

// === INSTRUCTORS ===
app.get('/instructors', async (c) => {
  try {
    const t = tid(c);
    if (!t) return json(c, { error: 'tenant required' }, 400);
    const r = await c.env.DB.prepare('SELECT * FROM instructors WHERE tenant_id=? ORDER BY name').bind(t).all();
    return json(c, { instructors: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list instructors', { error: e.message });
    return json(c, { error: 'Failed to list instructors', detail: e.message }, 500);
  }
});
app.post('/instructors', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO instructors (id,tenant_id,name,email,bio,avatar_url,expertise) VALUES (?,?,?,?,?,?,?)').bind(id, t, b.name, b.email || null, b.bio || null, b.avatar_url || null, b.expertise || null).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create instructor', { error: e.message });
    return json(c, { error: 'Failed to create instructor', detail: e.message }, 500);
  }
});

// === COURSES ===
app.get('/courses', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const cat = c.req.query('category');
    const status = c.req.query('status');
    let q = 'SELECT * FROM courses WHERE tenant_id=?';
    const params: string[] = [t];
    if (cat) { q += ' AND category=?'; params.push(cat); }
    if (status) { q += ' AND status=?'; params.push(status); }
    q += ' ORDER BY created_at DESC';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(c, { courses: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list courses', { error: e.message });
    return json(c, { error: 'Failed to list courses', detail: e.message }, 500);
  }
});
app.get('/courses/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM courses WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
  } catch (e: any) {
    slog('error', 'Failed to get course', { error: e.message });
    return json(c, { error: 'Failed to get course', detail: e.message }, 500);
  }
});
app.get('/courses/slug/:slug', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM courses WHERE slug=?').bind(c.req.param('slug')).first();
    return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
  } catch (e: any) {
    slog('error', 'Failed to get course by slug', { error: e.message });
    return json(c, { error: 'Failed to get course by slug', detail: e.message }, 500);
  }
});
app.post('/courses', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const tenant = await c.env.DB.prepare('SELECT max_courses FROM tenants WHERE id=?').bind(t).first<any>();
    if (tenant) {
      const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM courses WHERE tenant_id=?').bind(t).first<any>();
      if (cnt && cnt.c >= tenant.max_courses) return json(c, { error: 'Course limit reached' }, 403);
    }
    const id = uid();
    const slug = b.slug || b.title?.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || id;
    await c.env.DB.prepare('INSERT INTO courses (id,tenant_id,instructor_id,title,description,category,level,status,thumbnail_url,duration_hours,price,is_free,certificate_enabled,prerequisites_json,tags,slug) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, t, b.instructor_id || null, b.title, b.description || null, b.category || null, b.level || 'beginner', 'draft', b.thumbnail_url || null, b.duration_hours || 0, b.price || 0, b.is_free !== undefined ? (b.is_free ? 1 : 0) : 1, b.certificate_enabled ? 1 : 0, JSON.stringify(b.prerequisites || []), b.tags || null, slug).run();
    return json(c, { id, slug }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create course', { error: e.message });
    return json(c, { error: 'Failed to create course', detail: e.message }, 500);
  }
});
app.put('/courses/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = c.req.param('id');
    await c.env.DB.prepare('UPDATE courses SET title=COALESCE(?,title),description=COALESCE(?,description),category=COALESCE(?,category),level=COALESCE(?,level),thumbnail_url=COALESCE(?,thumbnail_url),duration_hours=COALESCE(?,duration_hours),price=COALESCE(?,price),tags=COALESCE(?,tags),updated_at=datetime(\'now\') WHERE id=?').bind(b.title || null, b.description || null, b.category || null, b.level || null, b.thumbnail_url || null, b.duration_hours ?? null, b.price ?? null, b.tags || null, id).run();
    return json(c, { updated: true });
  } catch (e: any) {
    slog('error', 'Failed to update course', { error: e.message });
    return json(c, { error: 'Failed to update course', detail: e.message }, 500);
  }
});
app.post('/courses/:id/publish', async (c) => {
  try {
    await c.env.DB.prepare("UPDATE courses SET status='published',updated_at=datetime('now') WHERE id=?").bind(c.req.param('id')).run();
    return json(c, { published: true });
  } catch (e: any) {
    slog('error', 'Failed to publish course', { error: e.message });
    return json(c, { error: 'Failed to publish course', detail: e.message }, 500);
  }
});
app.delete('/courses/:id', async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM courses WHERE id=?').bind(c.req.param('id')).run();
    return json(c, { deleted: true });
  } catch (e: any) {
    slog('error', 'Failed to delete course', { error: e.message });
    return json(c, { error: 'Failed to delete course', detail: e.message }, 500);
  }
});

// === MODULES ===
app.get('/courses/:cid/modules', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM modules WHERE course_id=? ORDER BY order_num').bind(c.req.param('cid')).all();
    return json(c, { modules: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list modules', { error: e.message });
    return json(c, { error: 'Failed to list modules', detail: e.message }, 500);
  }
});
app.post('/courses/:cid/modules', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO modules (id,course_id,tenant_id,title,description,order_num) VALUES (?,?,?,?,?,?)').bind(id, c.req.param('cid'), t, b.title, b.description || null, b.order_num || 0).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create module', { error: e.message });
    return json(c, { error: 'Failed to create module', detail: e.message }, 500);
  }
});

// === LESSONS ===
app.get('/modules/:mid/lessons', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM lessons WHERE module_id=? ORDER BY order_num').bind(c.req.param('mid')).all();
    return json(c, { lessons: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list lessons by module', { error: e.message });
    return json(c, { error: 'Failed to list lessons', detail: e.message }, 500);
  }
});
app.get('/courses/:cid/lessons', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM lessons WHERE course_id=? ORDER BY order_num').bind(c.req.param('cid')).all();
    return json(c, { lessons: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list lessons by course', { error: e.message });
    return json(c, { error: 'Failed to list lessons', detail: e.message }, 500);
  }
});
app.post('/modules/:mid/lessons', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO lessons (id,module_id,course_id,tenant_id,title,type,content_json,video_url,duration_min,order_num,is_free_preview) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(id, c.req.param('mid'), b.course_id, t, b.title, b.type || 'text', JSON.stringify(b.content || {}), b.video_url || null, b.duration_min || 0, b.order_num || 0, b.is_free_preview ? 1 : 0).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create lesson', { error: e.message });
    return json(c, { error: 'Failed to create lesson', detail: e.message }, 500);
  }
});
app.put('/lessons/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    await c.env.DB.prepare('UPDATE lessons SET title=COALESCE(?,title),content_json=COALESCE(?,content_json),video_url=COALESCE(?,video_url),duration_min=COALESCE(?,duration_min),type=COALESCE(?,type) WHERE id=?').bind(b.title || null, b.content ? JSON.stringify(b.content) : null, b.video_url || null, b.duration_min ?? null, b.type || null, c.req.param('id')).run();
    return json(c, { updated: true });
  } catch (e: any) {
    slog('error', 'Failed to update lesson', { error: e.message });
    return json(c, { error: 'Failed to update lesson', detail: e.message }, 500);
  }
});

// === QUIZZES ===
app.get('/courses/:cid/quizzes', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM quizzes WHERE course_id=? ORDER BY order_num').bind(c.req.param('cid')).all();
    return json(c, { quizzes: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list quizzes', { error: e.message });
    return json(c, { error: 'Failed to list quizzes', detail: e.message }, 500);
  }
});
app.post('/courses/:cid/quizzes', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO quizzes (id,lesson_id,course_id,tenant_id,title,description,questions_json,passing_score,time_limit_min,max_attempts,shuffle_questions,show_answers,order_num) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, b.lesson_id || null, c.req.param('cid'), t, b.title, b.description || null, JSON.stringify(b.questions || []), b.passing_score || 70, b.time_limit_min || 0, b.max_attempts || 3, b.shuffle_questions ? 1 : 0, b.show_answers !== false ? 1 : 0, b.order_num || 0).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create quiz', { error: e.message });
    return json(c, { error: 'Failed to create quiz', detail: e.message }, 500);
  }
});

// === STUDENTS ===
app.get('/students', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const search = c.req.query('search');
    let q = 'SELECT * FROM students WHERE tenant_id=?';
    const params: string[] = [t];
    if (search) { q += ' AND (name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    q += ' ORDER BY name';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(c, { students: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list students', { error: e.message });
    return json(c, { error: 'Failed to list students', detail: e.message }, 500);
  }
});
app.post('/students', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const tenant = await c.env.DB.prepare('SELECT max_students FROM tenants WHERE id=?').bind(t).first<any>();
    if (tenant) {
      const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM students WHERE tenant_id=?').bind(t).first<any>();
      if (cnt && cnt.c >= tenant.max_students) return json(c, { error: 'Student limit reached' }, 403);
    }
    const id = uid();
    await c.env.DB.prepare('INSERT INTO students (id,tenant_id,name,email,avatar_url) VALUES (?,?,?,?,?)').bind(id, t, b.name, b.email, b.avatar_url || null).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create student', { error: e.message });
    return json(c, { error: 'Failed to create student', detail: e.message }, 500);
  }
});

// === ENROLLMENTS ===
app.get('/courses/:cid/enrollments', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT e.*,s.name as student_name,s.email as student_email FROM enrollments e JOIN students s ON e.student_id=s.id WHERE e.course_id=? ORDER BY e.started_at DESC').bind(c.req.param('cid')).all();
    return json(c, { enrollments: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list course enrollments', { error: e.message });
    return json(c, { error: 'Failed to list enrollments', detail: e.message }, 500);
  }
});
app.get('/students/:sid/enrollments', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT e.*,co.title as course_title FROM enrollments e JOIN courses co ON e.course_id=co.id WHERE e.student_id=? ORDER BY e.started_at DESC').bind(c.req.param('sid')).all();
    return json(c, { enrollments: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list student enrollments', { error: e.message });
    return json(c, { error: 'Failed to list enrollments', detail: e.message }, 500);
  }
});
app.post('/enroll', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const existing = await c.env.DB.prepare('SELECT id FROM enrollments WHERE course_id=? AND student_id=?').bind(b.course_id, b.student_id).first();
    if (existing) return json(c, { error: 'Already enrolled' }, 409);
    const lessonCount = await c.env.DB.prepare('SELECT COUNT(*) as c FROM lessons WHERE course_id=?').bind(b.course_id).first<any>();
    const id = uid();
    await c.env.DB.prepare('INSERT INTO enrollments (id,course_id,student_id,tenant_id,total_lessons) VALUES (?,?,?,?,?)').bind(id, b.course_id, b.student_id, t, lessonCount?.c || 0).run();
    await c.env.DB.prepare('UPDATE courses SET enrollment_count=enrollment_count+1 WHERE id=?').bind(b.course_id).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to enroll student', { error: e.message });
    return json(c, { error: 'Failed to enroll student', detail: e.message }, 500);
  }
});

// === LESSON PROGRESS ===
app.post('/progress', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const existing = await c.env.DB.prepare('SELECT id,status FROM lesson_progress WHERE enrollment_id=? AND lesson_id=?').bind(b.enrollment_id, b.lesson_id).first<any>();
    if (existing) {
      await c.env.DB.prepare('UPDATE lesson_progress SET status=?,time_spent_sec=time_spent_sec+?,completed_at=CASE WHEN ?=\'completed\' THEN datetime(\'now\') ELSE completed_at END WHERE id=?').bind(b.status || existing.status, b.time_spent_sec || 0, b.status || '', existing.id).run();
      if (b.status === 'completed' && existing.status !== 'completed') {
        await c.env.DB.prepare('UPDATE enrollments SET completed_lessons=completed_lessons+1,progress=CAST(completed_lessons+1 AS REAL)/CAST(CASE WHEN total_lessons>0 THEN total_lessons ELSE 1 END AS REAL)*100,last_activity_at=datetime(\'now\') WHERE id=?').bind(b.enrollment_id).run();
      }
      return json(c, { updated: true });
    }
    const id = uid();
    await c.env.DB.prepare('INSERT INTO lesson_progress (id,enrollment_id,lesson_id,student_id,tenant_id,status,time_spent_sec,completed_at) VALUES (?,?,?,?,?,?,?,?)').bind(id, b.enrollment_id, b.lesson_id, b.student_id, t, b.status || 'in_progress', b.time_spent_sec || 0, b.status === 'completed' ? new Date().toISOString() : null).run();
    if (b.status === 'completed') {
      await c.env.DB.prepare('UPDATE enrollments SET completed_lessons=completed_lessons+1,progress=CAST(completed_lessons+1 AS REAL)/CAST(CASE WHEN total_lessons>0 THEN total_lessons ELSE 1 END AS REAL)*100,last_activity_at=datetime(\'now\') WHERE id=?').bind(b.enrollment_id).run();
    }
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to update lesson progress', { error: e.message });
    return json(c, { error: 'Failed to update lesson progress', detail: e.message }, 500);
  }
});
app.get('/enrollments/:eid/progress', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT lp.*,l.title as lesson_title FROM lesson_progress lp JOIN lessons l ON lp.lesson_id=l.id WHERE lp.enrollment_id=? ORDER BY l.order_num').bind(c.req.param('eid')).all();
    return json(c, { progress: r.results });
  } catch (e: any) {
    slog('error', 'Failed to get enrollment progress', { error: e.message });
    return json(c, { error: 'Failed to get enrollment progress', detail: e.message }, 500);
  }
});

// === QUIZ ATTEMPTS ===
app.post('/quizzes/:qid/attempt', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const quiz = await c.env.DB.prepare('SELECT * FROM quizzes WHERE id=?').bind(c.req.param('qid')).first<any>();
    if (!quiz) return json(c, { error: 'Quiz not found' }, 404);
    const prevAttempts = await c.env.DB.prepare('SELECT COUNT(*) as c FROM quiz_attempts WHERE quiz_id=? AND student_id=?').bind(quiz.id, b.student_id).first<any>();
    if (prevAttempts && prevAttempts.c >= quiz.max_attempts) return json(c, { error: 'Max attempts reached' }, 403);
    const questions = JSON.parse(quiz.questions_json || '[]');
    const answers = b.answers || {};
    let correct = 0;
    for (const q of questions) {
      if (answers[q.id] !== undefined && String(answers[q.id]) === String(q.correct_answer)) correct++;
    }
    const score = questions.length > 0 ? (correct / questions.length) * 100 : 0;
    const passed = score >= (quiz.passing_score || 70);
    const id = uid();
    await c.env.DB.prepare('INSERT INTO quiz_attempts (id,quiz_id,student_id,enrollment_id,tenant_id,score,passed,answers_json,time_taken_sec,attempt_number) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id, quiz.id, b.student_id, b.enrollment_id, t, score, passed ? 1 : 0, JSON.stringify(answers), b.time_taken_sec || 0, (prevAttempts?.c || 0) + 1).run();
    return json(c, { id, score: Math.round(score * 100) / 100, passed, correct, total: questions.length }, 201);
  } catch (e: any) {
    slog('error', 'Failed to submit quiz attempt', { error: e.message });
    return json(c, { error: 'Failed to submit quiz attempt', detail: e.message }, 500);
  }
});
app.get('/quizzes/:qid/attempts', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM quiz_attempts WHERE quiz_id=? ORDER BY created_at DESC').bind(c.req.param('qid')).all();
    return json(c, { attempts: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list quiz attempts', { error: e.message });
    return json(c, { error: 'Failed to list quiz attempts', detail: e.message }, 500);
  }
});

// === CERTIFICATES ===
app.post('/certificates', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const enrollment = await c.env.DB.prepare('SELECT * FROM enrollments WHERE id=?').bind(b.enrollment_id).first<any>();
    if (!enrollment) return json(c, { error: 'Enrollment not found' }, 404);
    if (enrollment.progress < 100) return json(c, { error: 'Course not completed' }, 400);
    const id = uid();
    const certNum = `CERT-${Date.now().toString(36).toUpperCase()}-${id.slice(0, 4).toUpperCase()}`;
    await c.env.DB.prepare('INSERT INTO certificates (id,enrollment_id,course_id,student_id,tenant_id,certificate_number) VALUES (?,?,?,?,?,?)').bind(id, enrollment.id, enrollment.course_id, enrollment.student_id, t, certNum).run();
    await c.env.DB.prepare('UPDATE enrollments SET certificate_id=?,completed_at=datetime(\'now\') WHERE id=?').bind(id, enrollment.id).run();
    await c.env.DB.prepare('UPDATE courses SET completion_count=completion_count+1 WHERE id=?').bind(enrollment.course_id).run();
    return json(c, { id, certificate_number: certNum }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create certificate', { error: e.message });
    return json(c, { error: 'Failed to create certificate', detail: e.message }, 500);
  }
});
app.get('/certificates/verify/:num', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT c.*,co.title as course_title,s.name as student_name FROM certificates c JOIN courses co ON c.course_id=co.id JOIN students s ON c.student_id=s.id WHERE c.certificate_number=?').bind(c.req.param('num')).first();
    return r ? json(c, { valid: true, certificate: r }) : json(c, { valid: false }, 404);
  } catch (e: any) {
    slog('error', 'Failed to verify certificate', { error: e.message });
    return json(c, { error: 'Failed to verify certificate', detail: e.message }, 500);
  }
});

// === REVIEWS ===
app.get('/courses/:cid/reviews', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT r.*,s.name as student_name FROM reviews r JOIN students s ON r.student_id=s.id WHERE r.course_id=? ORDER BY r.created_at DESC').bind(c.req.param('cid')).all();
    return json(c, { reviews: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list reviews', { error: e.message });
    return json(c, { error: 'Failed to list reviews', detail: e.message }, 500);
  }
});
app.post('/courses/:cid/reviews', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const rating = Math.min(5, Math.max(1, parseInt(b.rating) || 5));
    const id = uid();
    await c.env.DB.prepare('INSERT INTO reviews (id,course_id,student_id,tenant_id,rating,comment) VALUES (?,?,?,?,?,?)').bind(id, c.req.param('cid'), b.student_id, t, rating, b.comment || null).run();
    const avg = await c.env.DB.prepare('SELECT AVG(rating) as a FROM reviews WHERE course_id=?').bind(c.req.param('cid')).first<any>();
    await c.env.DB.prepare('UPDATE courses SET avg_rating=? WHERE id=?').bind(avg?.a || 0, c.req.param('cid')).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create review', { error: e.message });
    return json(c, { error: 'Failed to create review', detail: e.message }, 500);
  }
});

// === DISCUSSIONS ===
app.get('/courses/:cid/discussions', async (c) => {
  try {
    const lessonId = c.req.query('lesson_id');
    let q = 'SELECT * FROM discussions WHERE course_id=?';
    const params: string[] = [c.req.param('cid')];
    if (lessonId) { q += ' AND lesson_id=?'; params.push(lessonId); }
    q += ' ORDER BY is_pinned DESC, created_at DESC';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(c, { discussions: r.results });
  } catch (e: any) {
    slog('error', 'Failed to list discussions', { error: e.message });
    return json(c, { error: 'Failed to list discussions', detail: e.message }, 500);
  }
});
app.post('/courses/:cid/discussions', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO discussions (id,course_id,lesson_id,tenant_id,author_id,author_name,content,parent_id,is_pinned) VALUES (?,?,?,?,?,?,?,?,?)').bind(id, c.req.param('cid'), b.lesson_id || null, t, b.author_id, b.author_name, b.content, b.parent_id || null, 0).run();
    return json(c, { id }, 201);
  } catch (e: any) {
    slog('error', 'Failed to create discussion', { error: e.message });
    return json(c, { error: 'Failed to create discussion', detail: e.message }, 500);
  }
});

// === ANALYTICS ===
app.get('/analytics/overview', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const [courses, students, enrollments, completions, revenue] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as c FROM courses WHERE tenant_id=?').bind(t).first<any>(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM students WHERE tenant_id=?').bind(t).first<any>(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM enrollments WHERE tenant_id=?').bind(t).first<any>(),
      c.env.DB.prepare("SELECT COUNT(*) as c FROM enrollments WHERE tenant_id=? AND completed_at IS NOT NULL").bind(t).first<any>(),
      c.env.DB.prepare('SELECT SUM(co.price) as total FROM enrollments e JOIN courses co ON e.course_id=co.id WHERE e.tenant_id=? AND co.is_free=0').bind(t).first<any>(),
    ]);
    return json(c, {
      total_courses: courses?.c || 0,
      total_students: students?.c || 0,
      total_enrollments: enrollments?.c || 0,
      total_completions: completions?.c || 0,
      completion_rate: enrollments?.c ? Math.round(((completions?.c || 0) / enrollments.c) * 100) : 0,
      estimated_revenue: revenue?.total || 0,
    });
  } catch (e: any) {
    slog('error', 'Failed to get analytics overview', { error: e.message });
    return json(c, { error: 'Failed to get analytics overview', detail: e.message }, 500);
  }
});
app.get('/analytics/popular-courses', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const r = await c.env.DB.prepare('SELECT id,title,enrollment_count,avg_rating,completion_count FROM courses WHERE tenant_id=? ORDER BY enrollment_count DESC LIMIT 10').bind(t).all();
    return json(c, { courses: r.results });
  } catch (e: any) {
    slog('error', 'Failed to get popular courses', { error: e.message });
    return json(c, { error: 'Failed to get popular courses', detail: e.message }, 500);
  }
});
app.get('/analytics/student-activity', async (c) => {
  try {
    const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
    const r = await c.env.DB.prepare("SELECT DATE(last_activity_at) as day, COUNT(*) as active_students FROM enrollments WHERE tenant_id=? AND last_activity_at > datetime('now','-30 days') GROUP BY day ORDER BY day").bind(t).all();
    return json(c, { activity: r.results });
  } catch (e: any) {
    slog('error', 'Failed to get student activity', { error: e.message });
    return json(c, { error: 'Failed to get student activity', detail: e.message }, 500);
  }
});

// === AI ENDPOINTS ===
app.post('/ai/generate-outline', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'EDU-01', query: `Generate a detailed course outline for: "${b.topic}". Level: ${b.level || 'beginner'}. Target audience: ${b.audience || 'general'}. Include 5-8 modules with 3-5 lessons each. Return as JSON with modules array containing title, description, and lessons array.` }),
    });
    const data = await resp.json() as any;
    return json(c, { outline: data.response || data });
  } catch (e: any) {
    slog('error', 'AI generate-outline failed', { error: e.message });
    return json(c, { error: 'AI service unavailable', detail: e.message }, 503);
  }
});
app.post('/ai/generate-quiz', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'EDU-01', query: `Generate ${b.count || 5} multiple-choice quiz questions about: "${b.topic}". Difficulty: ${b.difficulty || 'medium'}. Return as JSON array with id, question, options (array of 4), correct_answer (the correct option text), explanation.` }),
    });
    const data = await resp.json() as any;
    return json(c, { questions: data.response || data });
  } catch (e: any) {
    slog('error', 'AI generate-quiz failed', { error: e.message });
    return json(c, { error: 'AI service unavailable', detail: e.message }, 503);
  }
});
app.post('/ai/summarize-progress', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const enrollment = await c.env.DB.prepare('SELECT e.*,co.title FROM enrollments e JOIN courses co ON e.course_id=co.id WHERE e.id=?').bind(b.enrollment_id).first<any>();
    if (!enrollment) return json(c, { error: 'Enrollment not found' }, 404);
    const quizResults = await c.env.DB.prepare('SELECT q.title,qa.score,qa.passed FROM quiz_attempts qa JOIN quizzes q ON qa.quiz_id=q.id WHERE qa.enrollment_id=? ORDER BY qa.created_at DESC LIMIT 10').bind(b.enrollment_id).all();
    return json(c, {
      summary: {
        course: enrollment.title,
        progress_pct: Math.round(enrollment.progress || 0),
        lessons_completed: enrollment.completed_lessons,
        lessons_total: enrollment.total_lessons,
        quiz_results: quizResults.results,
        status: enrollment.progress >= 100 ? 'completed' : enrollment.progress > 50 ? 'on_track' : 'needs_attention',
      },
    });
  } catch (e: any) {
    slog('error', 'Failed to summarize progress', { error: e.message });
    return json(c, { error: 'Failed to summarize progress', detail: e.message }, 500);
  }
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  slog('error', 'Unhandled request error', { error: err.message, stack: err.stack });
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// Scheduled: cleanup old data
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    try {
      await env.DB.prepare("DELETE FROM activity_log WHERE created_at < datetime('now','-90 days')").run();
      await env.DB.prepare("DELETE FROM lesson_progress WHERE status='not_started' AND enrollment_id IN (SELECT id FROM enrollments WHERE last_activity_at < datetime('now','-180 days'))").run();
    } catch (e: any) {
      console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-lms', msg: 'Scheduled cleanup failed', error: e.message }));
    }
  },
};
