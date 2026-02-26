-- ===============================
-- ENABLE EXTENSIONS
-- ===============================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ===============================
-- USERS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('USER', 'ISSUER', 'VERIFIER', 'AUDITOR')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_wallet ON users(wallet_address);

-- ===============================
-- DOCUMENTS TABLE (IPFS Storage)
-- ===============================
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ipfs_cid TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);

-- ===============================
-- DOCUMENT KEYS TABLE (Supports Multi-Recipient)
-- ===============================
CREATE TABLE IF NOT EXISTS document_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_user_id UUID REFERENCES users(id),
    encrypted_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_doc_keys_doc ON document_keys(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_keys_user ON document_keys(recipient_user_id);

-- ===============================
-- CREDENTIALS TABLE (Verifiable Credentials)
-- ===============================
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    issuer_id UUID REFERENCES users(id),
    credential_id VARCHAR(150) UNIQUE NOT NULL,
    vc_ipfs_cid TEXT NOT NULL,
    vc_hash VARCHAR(256) NOT NULL,
    blockchain_tx_hash VARCHAR(256),
    revoked BOOLEAN DEFAULT FALSE,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_credentials_doc ON credentials(document_id);
CREATE INDEX IF NOT EXISTS idx_credentials_hash ON credentials(vc_hash);
CREATE INDEX IF NOT EXISTS idx_credentials_revoked ON credentials(revoked);
CREATE INDEX IF NOT EXISTS idx_credentials_issuer ON credentials(issuer_id);

-- ===============================
-- REVOCATION HISTORY TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS revocation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id VARCHAR(150) NOT NULL REFERENCES credentials(credential_id) ON DELETE CASCADE,
    revoked_by UUID REFERENCES users(id),
    reason TEXT,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_revocation_credential ON revocation_history(credential_id);

-- ===============================
-- PROOF VERIFICATION LOGS
-- ===============================
CREATE TABLE IF NOT EXISTS proof_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id VARCHAR(150) NOT NULL REFERENCES credentials(credential_id) ON DELETE CASCADE,
    verifier_id UUID REFERENCES users(id),
    verification_status BOOLEAN,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proof_logs_credential ON proof_logs(credential_id);

-- ===============================
-- AUDIT LOG TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action_type VARCHAR(50),
    entity_type VARCHAR(50),
    entity_id VARCHAR(150),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
