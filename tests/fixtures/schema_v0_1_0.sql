CREATE TABLE categories (
	id VARCHAR(64) NOT NULL, 
	name VARCHAR(64) NOT NULL, 
	position INTEGER, 
	collapsed_default BOOLEAN, 
	created_at FLOAT, 
	PRIMARY KEY (id)
);
CREATE TABLE identities (
	hash VARCHAR(64) NOT NULL, 
	display_name VARCHAR(64), 
	public_key BLOB, 
	avatar BLOB, 
	status_text VARCHAR(256), 
	bio VARCHAR(1024), 
	first_seen FLOAT, 
	last_seen FLOAT, 
	blocked BOOLEAN, 
	blocked_at FLOAT, 
	blocked_by VARCHAR(64), 
	announce_data BLOB, 
	PRIMARY KEY (hash)
);
CREATE TABLE roles (
	id VARCHAR(64) NOT NULL, 
	name VARCHAR(64) NOT NULL, 
	permissions INTEGER, 
	position INTEGER, 
	colour VARCHAR(7), 
	mentionable BOOLEAN, 
	is_builtin BOOLEAN, 
	created_at FLOAT, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
CREATE TABLE peers (
	identity_hash VARCHAR(64) NOT NULL, 
	node_name VARCHAR(128), 
	last_announce FLOAT, 
	last_seen FLOAT, 
	channels_mirrored JSON, 
	sync_cursor JSON, 
	federation_trusted BOOLEAN, 
	last_handshake FLOAT, 
	public_key BLOB, 
	PRIMARY KEY (identity_hash)
);
CREATE TABLE audit_log (
	id INTEGER NOT NULL, 
	actor VARCHAR(64) NOT NULL, 
	action_type VARCHAR(64) NOT NULL, 
	target VARCHAR(64), 
	channel_id VARCHAR(64), 
	timestamp FLOAT, 
	details JSON, 
	PRIMARY KEY (id)
);
CREATE INDEX ix_audit_log_timestamp ON audit_log (timestamp);
CREATE TABLE sessions (
	session_id VARCHAR(64) NOT NULL, 
	identity_hash VARCHAR(64), 
	sync_profile INTEGER, 
	cdsp_version INTEGER, 
	state VARCHAR(32), 
	resume_token BLOB, 
	deferred_count INTEGER, 
	created_at FLOAT, 
	last_activity FLOAT, 
	expires_at FLOAT, 
	PRIMARY KEY (session_id)
);
CREATE INDEX ix_sessions_identity_hash ON sessions (identity_hash);
CREATE TABLE federation_epoch_state (
	peer_identity_hash VARCHAR(64) NOT NULL, 
	current_epoch_id INTEGER, 
	epoch_duration INTEGER, 
	is_initiator BOOLEAN, 
	epoch_start_time FLOAT, 
	current_key_send BLOB, 
	current_key_recv BLOB, 
	nonce_prefix BLOB, 
	message_counter INTEGER, 
	last_chain_hash BLOB, 
	updated_at FLOAT, 
	PRIMARY KEY (peer_identity_hash)
);
CREATE TABLE channels (
	id VARCHAR(64) NOT NULL, 
	name VARCHAR(64) NOT NULL, 
	description VARCHAR(512), 
	category_id VARCHAR(64), 
	position INTEGER, 
	access_mode VARCHAR(20), 
	slowmode INTEGER, 
	max_retention INTEGER, 
	latest_seq INTEGER, 
	identity_hash VARCHAR(64), 
	destination_hash VARCHAR(32), 
	created_at FLOAT, 
	sealed BOOLEAN, 
	rotation_old_hash VARCHAR(64), 
	rotation_grace_end FLOAT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(category_id) REFERENCES categories (id)
);
CREATE INDEX ix_channels_category_id ON channels (category_id);
CREATE TABLE deferred_sync_items (
	id INTEGER NOT NULL, 
	session_id VARCHAR(64), 
	channel_id VARCHAR(64), 
	sync_action INTEGER, 
	payload JSON, 
	priority INTEGER, 
	created_at FLOAT, 
	expires_at FLOAT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(session_id) REFERENCES sessions (session_id) ON DELETE CASCADE
);
CREATE INDEX ix_deferred_sync_items_session_id ON deferred_sync_items (session_id);
CREATE TABLE messages (
	msg_hash VARCHAR(64) NOT NULL, 
	channel_id VARCHAR(64) NOT NULL, 
	sender_hash VARCHAR(64), 
	seq INTEGER, 
	timestamp FLOAT NOT NULL, 
	type INTEGER NOT NULL, 
	body TEXT, 
	media_path VARCHAR(512), 
	media_meta JSON, 
	reply_to VARCHAR(64), 
	thread_seq INTEGER, 
	ttl INTEGER, 
	received_at FLOAT, 
	deleted BOOLEAN, 
	deleted_by VARCHAR(64), 
	pinned BOOLEAN, 
	pinned_at FLOAT, 
	edit_chain JSON, 
	reactions JSON, 
	lxmf_signature BLOB, 
	lxmf_signed_part BLOB, 
	display_name VARCHAR(64), 
	mentions JSON, 
	origin_node VARCHAR(64), 
	encrypted_body BLOB, 
	encryption_nonce BLOB, 
	encryption_epoch INTEGER, 
	PRIMARY KEY (msg_hash), 
	FOREIGN KEY(channel_id) REFERENCES channels (id)
);
CREATE INDEX ix_messages_timestamp ON messages (timestamp);
CREATE INDEX ix_channel_seq ON messages (channel_id, seq);
CREATE INDEX ix_messages_reply_to ON messages (reply_to);
CREATE INDEX ix_messages_channel_id ON messages (channel_id);
CREATE INDEX ix_messages_sender_hash ON messages (sender_hash);
CREATE TABLE role_assignments (
	id INTEGER NOT NULL, 
	role_id VARCHAR(64) NOT NULL, 
	identity_hash VARCHAR(64) NOT NULL, 
	channel_id VARCHAR(64), 
	assigned_at FLOAT, 
	assigned_by VARCHAR(64), 
	PRIMARY KEY (id), 
	CONSTRAINT uq_role_identity_channel UNIQUE (role_id, identity_hash, channel_id), 
	FOREIGN KEY(role_id) REFERENCES roles (id), 
	FOREIGN KEY(identity_hash) REFERENCES identities (hash), 
	FOREIGN KEY(channel_id) REFERENCES channels (id)
);
CREATE INDEX ix_role_identity_channel ON role_assignments (identity_hash, channel_id);
CREATE INDEX ix_role_assignments_role_id ON role_assignments (role_id);
CREATE TABLE channel_overrides (
	id INTEGER NOT NULL, 
	channel_id VARCHAR(64) NOT NULL, 
	role_id VARCHAR(64) NOT NULL, 
	allow INTEGER, 
	deny INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(channel_id) REFERENCES channels (id), 
	FOREIGN KEY(role_id) REFERENCES roles (id)
);
CREATE UNIQUE INDEX ix_override_channel_role ON channel_overrides (channel_id, role_id);
CREATE TABLE invites (
	token_hash VARCHAR(64) NOT NULL, 
	channel_id VARCHAR(64), 
	created_by VARCHAR(64) NOT NULL, 
	max_uses INTEGER, 
	uses INTEGER, 
	used_by JSON, 
	used_at JSON, 
	expires_at FLOAT, 
	created_at FLOAT, 
	revoked BOOLEAN, 
	PRIMARY KEY (token_hash), 
	FOREIGN KEY(channel_id) REFERENCES channels (id)
);
CREATE TABLE sealed_keys (
	id INTEGER NOT NULL, 
	channel_id VARCHAR(64) NOT NULL, 
	epoch INTEGER NOT NULL, 
	encrypted_key_blob BLOB NOT NULL, 
	identity_hash VARCHAR(64) NOT NULL, 
	created_at FLOAT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(channel_id) REFERENCES channels (id)
);
CREATE INDEX ix_sealed_channel_epoch ON sealed_keys (channel_id, epoch);
CREATE TABLE pending_sealed_distributions (
	id INTEGER NOT NULL, 
	channel_id VARCHAR(64) NOT NULL, 
	identity_hash VARCHAR(64) NOT NULL, 
	role_id VARCHAR(64) NOT NULL, 
	queued_at FLOAT NOT NULL, 
	last_attempt_at FLOAT, 
	retry_count INTEGER NOT NULL, 
	last_error VARCHAR, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_pending_sealed_distributions_triple UNIQUE (channel_id, identity_hash, role_id), 
	FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE, 
	FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE
);
CREATE INDEX ix_pending_sealed_distributions_identity_hash ON pending_sealed_distributions (identity_hash);
CREATE TABLE threads (
	root_msg_hash VARCHAR(64) NOT NULL, 
	channel_id VARCHAR(64) NOT NULL, 
	reply_count INTEGER, 
	latest_thread_seq INTEGER, 
	last_activity FLOAT, 
	participant_hashes JSON, 
	PRIMARY KEY (root_msg_hash), 
	FOREIGN KEY(root_msg_hash) REFERENCES messages (msg_hash), 
	FOREIGN KEY(channel_id) REFERENCES channels (id)
);
