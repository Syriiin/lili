CREATE TABLE users (
	id SERIAL PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	password_salted_hash TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
    last_login TIMESTAMP NOT NULL
);

CREATE TABLE lilipads (
	id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
	name TEXT NOT NULL,
	text TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
