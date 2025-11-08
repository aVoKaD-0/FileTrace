CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

Create Table IF NOT EXISTS Users(
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    confirmed BOOLEAN DEFAULT FALSE,
    confirmation_code VARCHAR(255),
    refresh_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    login_attempts INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_email ON Users (email);
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
