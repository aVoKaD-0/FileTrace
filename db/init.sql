CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

Create Table IF NOT EXISTS Users(
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash VARCHAR(64) UNIQUE NOT NULL,
    email_encrypted TEXT NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    confirmed BOOLEAN DEFAULT FALSE,
    confirmation_code VARCHAR(255),
    refresh_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    login_attempts INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_email_hash ON Users (email_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_token ON Users (refresh_token);

Create Table IF NOT EXISTS Analysis(
    id SERIAL PRIMARY KEY,
    user_id uuid,
    filename TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT,
    analysis_id uuid UNIQUE,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

Create Table IF NOT EXISTS Results(
    analysis_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_activity TEXT,
    docker_output TEXT,
    results TEXT,
    FOREIGN KEY (analysis_id) REFERENCES Analysis(analysis_id) ON DELETE CASCADE
);

-- Audit events table for security and user actions logging
Create Table IF NOT EXISTS AuditEvents(
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id uuid NULL,
    event_type VARCHAR(64) NOT NULL,
    source_ip TEXT,
    user_agent TEXT,
    request_id VARCHAR(64),
    metadatas JSONB,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_user_time ON AuditEvents (user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_time ON AuditEvents (event_type, occurred_at DESC);
