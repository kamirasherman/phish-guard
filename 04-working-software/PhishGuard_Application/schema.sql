CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('administrator', 'campaign_manager', 'analyst', 'viewer')),
    account_group TEXT NOT NULL DEFAULT 'application_staff' CHECK (account_group IN ('application_staff', 'phishguard_test_users')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    failure_message TEXT,
    media_filename TEXT,
    media_original_name TEXT,
    media_mime TEXT,
    live_sender_email TEXT,
    simulation_alias TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL,
    dispatched_at TEXT
);

CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    first_name TEXT,
    token_digest TEXT UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
    UNIQUE (campaign_id, email)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('delivered', 'clicked', 'completed')),
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE CASCADE,
    UNIQUE (recipient_id, event_type)
);

CREATE TABLE IF NOT EXISTS quizzes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL UNIQUE,
    title TEXT NOT NULL,
    passing_score INTEGER NOT NULL CHECK (passing_score BETWEEN 50 AND 100),
    questions_json TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    score_percent INTEGER NOT NULL CHECK (score_percent BETWEEN 0 AND 100),
    correct_answers INTEGER NOT NULL CHECK (correct_answers BETWEEN 0 AND 5),
    total_questions INTEGER NOT NULL CHECK (total_questions = 5),
    passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
    answers_json TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dispatch_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    requested_by_user_id INTEGER,
    mode TEXT NOT NULL CHECK (mode IN ('preview', 'smtp')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed')),
    smtp_fingerprint TEXT NOT NULL DEFAULT '',
    total_recipients INTEGER NOT NULL DEFAULT 0,
    processed_recipients INTEGER NOT NULL DEFAULT 0,
    sent_recipients INTEGER NOT NULL DEFAULT 0,
    failed_recipients INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS dispatch_job_recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'processing', 'sent', 'failed')),
    error_type TEXT NOT NULL DEFAULT '',
    attempted_at TEXT,
    FOREIGN KEY (job_id) REFERENCES dispatch_jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE CASCADE,
    UNIQUE (job_id, recipient_id)
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role, active);
CREATE INDEX IF NOT EXISTS idx_users_group ON users(account_group, active);
CREATE INDEX IF NOT EXISTS idx_recipients_campaign ON recipients(campaign_id);
CREATE INDEX IF NOT EXISTS idx_recipients_token ON recipients(token_digest);
CREATE INDEX IF NOT EXISTS idx_events_recipient ON events(recipient_id);
CREATE INDEX IF NOT EXISTS idx_quizzes_campaign ON quizzes(campaign_id);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_recipient ON quiz_attempts(recipient_id, quiz_id, id);
CREATE INDEX IF NOT EXISTS idx_dispatch_jobs_status ON dispatch_jobs(status, id);
CREATE INDEX IF NOT EXISTS idx_dispatch_jobs_campaign ON dispatch_jobs(campaign_id, id);
CREATE INDEX IF NOT EXISTS idx_dispatch_job_recipients_job ON dispatch_job_recipients(job_id, status, id);
