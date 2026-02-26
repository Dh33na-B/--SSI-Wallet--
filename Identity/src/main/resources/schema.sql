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
    encryption_public_key TEXT,
    role VARCHAR(20) NOT NULL CHECK (role IN ('USER', 'ISSUER', 'VERIFIER', 'AUDITOR')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_wallet ON users(wallet_address);
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS encryption_public_key TEXT;

-- ===============================
-- DOCUMENT TYPES TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS document_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_document_types_name ON document_types(name);

INSERT INTO document_types (name)
VALUES ('Passport')
ON CONFLICT (name) DO NOTHING;

INSERT INTO document_types (name)
VALUES ('Degree Certificate')
ON CONFLICT (name) DO NOTHING;

INSERT INTO document_types (name)
VALUES ('Address Proof')
ON CONFLICT (name) DO NOTHING;

-- ===============================
-- DOCUMENTS TABLE (IPFS Storage)
-- ===============================
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_type_id UUID REFERENCES document_types(id),
    file_name VARCHAR(255),
    ipfs_cid TEXT NOT NULL,
    encryption_iv TEXT,
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);

-- Keep existing databases in sync when table already exists
ALTER TABLE IF EXISTS documents ADD COLUMN IF NOT EXISTS document_type_id UUID;
ALTER TABLE IF EXISTS documents ADD COLUMN IF NOT EXISTS file_name VARCHAR(255);
ALTER TABLE IF EXISTS documents ADD COLUMN IF NOT EXISTS encryption_iv TEXT;
CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type_id);

-- ===============================
-- DOCUMENT REVIEW REQUESTS (Issuer <-> Holder Notifications)
-- ===============================
CREATE TABLE IF NOT EXISTS document_review_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    holder_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'REQUESTED'
        CHECK (status IN (
            'REQUESTED',
            'HOLDER_APPROVED',
            'HOLDER_REJECTED',
            'ISSUER_ACCEPTED',
            'ISSUER_REJECTED_REUPLOAD_REQUIRED'
        )),
    issuer_encryption_public_key TEXT,
    issuer_note TEXT,
    holder_note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_doc_review_document ON document_review_requests(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_review_holder ON document_review_requests(holder_id);
CREATE INDEX IF NOT EXISTS idx_doc_review_issuer ON document_review_requests(issuer_id);
CREATE INDEX IF NOT EXISTS idx_doc_review_status ON document_review_requests(status);
ALTER TABLE IF EXISTS document_review_requests
    ADD COLUMN IF NOT EXISTS issuer_encryption_public_key TEXT;

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
    holder_id UUID REFERENCES users(id),
    credential_id VARCHAR(150) UNIQUE NOT NULL,
    vc_ipfs_cid TEXT NOT NULL,
    vc_hash VARCHAR(256) NOT NULL,
    signature_suite VARCHAR(100),
    blockchain_tx_hash VARCHAR(256),
    revoked BOOLEAN DEFAULT FALSE,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_credentials_doc ON credentials(document_id);
CREATE INDEX IF NOT EXISTS idx_credentials_hash ON credentials(vc_hash);
CREATE INDEX IF NOT EXISTS idx_credentials_revoked ON credentials(revoked);
CREATE INDEX IF NOT EXISTS idx_credentials_issuer ON credentials(issuer_id);
ALTER TABLE IF EXISTS credentials ADD COLUMN IF NOT EXISTS holder_id UUID REFERENCES users(id);
ALTER TABLE IF EXISTS credentials ADD COLUMN IF NOT EXISTS signature_suite VARCHAR(100);
CREATE INDEX IF NOT EXISTS idx_credentials_holder ON credentials(holder_id);

-- ===============================
-- CREDENTIAL KEYS TABLE (Encrypted K_vc per recipient)
-- ===============================
CREATE TABLE IF NOT EXISTS credential_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    recipient_user_id UUID REFERENCES users(id),
    encrypted_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_credential_keys_credential ON credential_keys(credential_id);
CREATE INDEX IF NOT EXISTS idx_credential_keys_recipient ON credential_keys(recipient_user_id);

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
    verification_request_id UUID,
    verification_status BOOLEAN,
    signature_valid BOOLEAN,
    blockchain_anchored BOOLEAN,
    blockchain_revoked BOOLEAN,
    vc_hash_matches BOOLEAN,
    revealed_fields TEXT,
    notes TEXT,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proof_logs_credential ON proof_logs(credential_id);

ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS verification_request_id UUID;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS signature_valid BOOLEAN;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS blockchain_anchored BOOLEAN;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS blockchain_revoked BOOLEAN;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS vc_hash_matches BOOLEAN;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS revealed_fields TEXT;
ALTER TABLE IF EXISTS proof_logs ADD COLUMN IF NOT EXISTS notes TEXT;

CREATE INDEX IF NOT EXISTS idx_proof_logs_request ON proof_logs(verification_request_id);

-- ===============================
-- VERIFICATION REQUESTS (Verifier <-> Holder selective disclosure flow)
-- ===============================
CREATE TABLE IF NOT EXISTS verification_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_ref_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    holder_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verifier_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_fields TEXT NOT NULL,
    disclosed_fields TEXT,
    purpose TEXT,
    proof_value TEXT,
    proof_nonce TEXT,
    revealed_messages TEXT,
    status VARCHAR(40) NOT NULL DEFAULT 'REQUESTED'
        CHECK (status IN ('REQUESTED', 'VERIFIED_VALID', 'VERIFIED_INVALID', 'HOLDER_DECLINED')),
    verification_status BOOLEAN,
    signature_valid BOOLEAN,
    blockchain_anchored BOOLEAN,
    blockchain_revoked BOOLEAN,
    vc_hash_matches BOOLEAN,
    verification_message TEXT,
    expires_at TIMESTAMP,
    responded_at TIMESTAMP,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verif_req_verifier ON verification_requests(verifier_id);
CREATE INDEX IF NOT EXISTS idx_verif_req_holder ON verification_requests(holder_id);
CREATE INDEX IF NOT EXISTS idx_verif_req_credential ON verification_requests(credential_ref_id);
CREATE INDEX IF NOT EXISTS idx_verif_req_status ON verification_requests(status);

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
