CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL, 
    password TEXT NOT NULL, 
    role TEXT CHECK(role IN ('ANALYST', 'MANAGER')) DEFAULT 'ANALYST',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked BOOLEAN DEFAULT 0
);

CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK(severity IN ('LOW', 'MED', 'HIGH')) DEFAULT 'LOW',
    status TEXT CHECK(status IN ('OPEN', 'IN PROGRESS', 'RESOLVED')) DEFAULT 'OPEN',
    owner_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT, -- ticket, auth, audit
    resource_id TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

INSERT INTO users(email, password, role) VALUES ('admin@test.com', 'admin123', 'MANAGER');
INSERT INTO users(email, password, role) VALUES ('cosmin@test.com', 'test123', 'ANALYST');