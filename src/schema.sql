-- Echo LMS v1.0.0 Schema
-- AI-powered learning management system

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  plan TEXT DEFAULT 'free',
  max_courses INTEGER DEFAULT 5,
  max_students INTEGER DEFAULT 50,
  branding_json TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS instructors (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  bio TEXT,
  avatar_url TEXT,
  expertise TEXT,
  course_count INTEGER DEFAULT 0,
  rating REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_inst_tenant ON instructors(tenant_id);

CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  instructor_id TEXT,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  level TEXT DEFAULT 'beginner',
  status TEXT DEFAULT 'draft',
  thumbnail_url TEXT,
  duration_hours REAL DEFAULT 0,
  price REAL DEFAULT 0,
  is_free INTEGER DEFAULT 1,
  enrollment_count INTEGER DEFAULT 0,
  completion_count INTEGER DEFAULT 0,
  avg_rating REAL DEFAULT 0,
  certificate_enabled INTEGER DEFAULT 0,
  certificate_template TEXT,
  prerequisites_json TEXT DEFAULT '[]',
  tags TEXT,
  slug TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (instructor_id) REFERENCES instructors(id)
);
CREATE INDEX IF NOT EXISTS idx_course_tenant ON courses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_course_status ON courses(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_course_slug ON courses(slug);
CREATE INDEX IF NOT EXISTS idx_course_cat ON courses(tenant_id, category);

CREATE TABLE IF NOT EXISTS modules (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  order_num INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);
CREATE INDEX IF NOT EXISTS idx_mod_course ON modules(course_id);

CREATE TABLE IF NOT EXISTS lessons (
  id TEXT PRIMARY KEY,
  module_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  type TEXT DEFAULT 'text',
  content_json TEXT DEFAULT '{}',
  video_url TEXT,
  duration_min INTEGER DEFAULT 0,
  order_num INTEGER DEFAULT 0,
  is_free_preview INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (module_id) REFERENCES modules(id),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);
CREATE INDEX IF NOT EXISTS idx_lesson_mod ON lessons(module_id);
CREATE INDEX IF NOT EXISTS idx_lesson_course ON lessons(course_id);

CREATE TABLE IF NOT EXISTS quizzes (
  id TEXT PRIMARY KEY,
  lesson_id TEXT,
  course_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  questions_json TEXT NOT NULL DEFAULT '[]',
  passing_score REAL DEFAULT 70,
  time_limit_min INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  shuffle_questions INTEGER DEFAULT 0,
  show_answers INTEGER DEFAULT 1,
  order_num INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);
CREATE INDEX IF NOT EXISTS idx_quiz_course ON quizzes(course_id);

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  avatar_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_student_tenant ON students(tenant_id);
CREATE INDEX IF NOT EXISTS idx_student_email ON students(tenant_id, email);

CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  progress REAL DEFAULT 0,
  completed_lessons INTEGER DEFAULT 0,
  total_lessons INTEGER DEFAULT 0,
  started_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT,
  certificate_id TEXT,
  last_activity_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (student_id) REFERENCES students(id)
);
CREATE INDEX IF NOT EXISTS idx_enroll_course ON enrollments(course_id);
CREATE INDEX IF NOT EXISTS idx_enroll_student ON enrollments(student_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_unique ON enrollments(course_id, student_id);

CREATE TABLE IF NOT EXISTS lesson_progress (
  id TEXT PRIMARY KEY,
  enrollment_id TEXT NOT NULL,
  lesson_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  status TEXT DEFAULT 'not_started',
  time_spent_sec INTEGER DEFAULT 0,
  completed_at TEXT,
  FOREIGN KEY (enrollment_id) REFERENCES enrollments(id),
  FOREIGN KEY (lesson_id) REFERENCES lessons(id)
);
CREATE INDEX IF NOT EXISTS idx_lprog_enroll ON lesson_progress(enrollment_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_lprog_unique ON lesson_progress(enrollment_id, lesson_id);

CREATE TABLE IF NOT EXISTS quiz_attempts (
  id TEXT PRIMARY KEY,
  quiz_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  score REAL DEFAULT 0,
  passed INTEGER DEFAULT 0,
  answers_json TEXT DEFAULT '{}',
  time_taken_sec INTEGER DEFAULT 0,
  attempt_number INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (quiz_id) REFERENCES quizzes(id),
  FOREIGN KEY (student_id) REFERENCES students(id)
);
CREATE INDEX IF NOT EXISTS idx_qatt_quiz ON quiz_attempts(quiz_id);
CREATE INDEX IF NOT EXISTS idx_qatt_student ON quiz_attempts(student_id);

CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,
  enrollment_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  certificate_number TEXT NOT NULL,
  issued_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (enrollment_id) REFERENCES enrollments(id)
);
CREATE INDEX IF NOT EXISTS idx_cert_student ON certificates(student_id);
CREATE INDEX IF NOT EXISTS idx_cert_number ON certificates(certificate_number);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  rating INTEGER NOT NULL,
  comment TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);
CREATE INDEX IF NOT EXISTS idx_review_course ON reviews(course_id);

CREATE TABLE IF NOT EXISTS discussions (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  lesson_id TEXT,
  tenant_id TEXT NOT NULL,
  author_id TEXT NOT NULL,
  author_name TEXT NOT NULL,
  content TEXT NOT NULL,
  parent_id TEXT,
  is_pinned INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);
CREATE INDEX IF NOT EXISTS idx_disc_course ON discussions(course_id);
CREATE INDEX IF NOT EXISTS idx_disc_lesson ON discussions(lesson_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_id TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
