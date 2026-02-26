package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"golang.org/x/crypto/nacl/box"
)

const (
	defaultBindAddress = ":8085"
	defaultKeyFile     = "./data/issuer-bbs-key.json"
	keyWrapVersion     = "x25519-xsalsa20-poly1305"
	bbsSignatureLen    = 112
)

type config struct {
	BindAddress        string
	KeyFilePath        string
	AuthToken          string
	DefaultIssuer      string
	DefaultProofMethod string
	AllowedOrigins     []string
}

type keyStore struct {
	KID              string `json:"kid"`
	PrivateKeyBase64 string `json:"privateKeyBase64"`
	PublicKeyBase64  string `json:"publicKeyBase64"`
	CreatedAt        string `json:"createdAt"`
}

type signerService struct {
	cfg         config
	bbs         *bbs12381g2pub.BBSG2Pub
	privateKey  []byte
	publicKey   []byte
	publicKeyB6 string
}

type signCredentialRequest struct {
	Credential         map[string]any `json:"credential"`
	VerificationMethod string         `json:"verificationMethod,omitempty"`
	ProofPurpose       string         `json:"proofPurpose,omitempty"`
	Created            string         `json:"created,omitempty"`
}

type signCredentialResponse struct {
	SignedCredential map[string]any `json:"signedCredential"`
	SignatureSuite   string         `json:"signatureSuite"`
	ProofValue       string         `json:"proofValue"`
	PublicKeyBase64  string         `json:"publicKeyBase64"`
	KID              string         `json:"kid"`
	MessageCount     int            `json:"messageCount"`
}

type deriveProofRequest struct {
	SignedCredential map[string]any `json:"signedCredential"`
	RevealFields     []string       `json:"revealFields"`
	Nonce            string         `json:"nonce,omitempty"`
}

type deriveProofResponse struct {
	ProofValue       string         `json:"proofValue"`
	Nonce            string         `json:"nonce"`
	SignatureSuite   string         `json:"signatureSuite"`
	RevealedIndexes  []int          `json:"revealedIndexes"`
	RevealedClaims   map[string]any `json:"revealedClaims"`
	RevealedMessages []string       `json:"revealedMessages"`
}

type verifyProofRequest struct {
	SignedCredential map[string]any `json:"signedCredential,omitempty"`
	RevealFields     []string       `json:"revealFields,omitempty"`
	RevealedMessages []string       `json:"revealedMessages,omitempty"`
	ProofValue       string         `json:"proofValue"`
	Nonce            string         `json:"nonce"`
}

type verifyProofResponse struct {
	Valid          bool   `json:"valid"`
	SignatureSuite string `json:"signatureSuite"`
	Message        string `json:"message,omitempty"`
}

type wrapKeyRequest struct {
	RecipientPublicKeyBase64 string `json:"recipientPublicKeyBase64"`
	PayloadBase64            string `json:"payloadBase64"`
}

type wrapKeyResponse struct {
	EnvelopeJSON string `json:"envelopeJson"`
	EnvelopeHex  string `json:"envelopeHex"`
	Version      string `json:"version"`
}

type errorResponse struct {
	Message string `json:"message"`
}

type canonicalEntry struct {
	Path  string
	Value any
}

var fieldPathPattern = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)
var hexOnlyPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func main() {
	cfg := loadConfig()

	service, err := newSignerService(cfg)
	if err != nil {
		log.Fatalf("failed to initialize signer service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", service.handleHealth)
	mux.HandleFunc("GET /v1/keys/public", service.handlePublicKey)
	mux.HandleFunc("POST /v1/credentials/sign", service.withAuth(service.handleSignCredential))
	mux.HandleFunc("POST /v1/credentials/proof", service.withAuth(service.handleDeriveProof))
	mux.HandleFunc("POST /v1/credentials/proof/verify", service.withAuth(service.handleVerifyProof))
	mux.HandleFunc("POST /v1/keys/wrap", service.withAuth(service.handleWrapKey))

	server := &http.Server{
		Addr:              cfg.BindAddress,
		Handler:           service.withLogging(service.withCORS(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("bbs signer listening on %s", cfg.BindAddress)
	log.Printf("signer public key (base64): %s", service.publicKeyB6)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server terminated: %v", err)
	}
}

func loadConfig() config {
	allowedOrigins := []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	rawOrigins := strings.TrimSpace(os.Getenv("BBS_SIGNER_ALLOWED_ORIGINS"))
	if rawOrigins != "" {
		parts := strings.Split(rawOrigins, ",")
		allowedOrigins = make([]string, 0, len(parts))
		for _, part := range parts {
			clean := strings.TrimSpace(part)
			if clean != "" {
				allowedOrigins = append(allowedOrigins, clean)
			}
		}
		if len(allowedOrigins) == 0 {
			allowedOrigins = []string{"http://localhost:5173"}
		}
	}

	return config{
		BindAddress:        firstNonBlank(os.Getenv("BBS_SIGNER_BIND_ADDRESS"), defaultBindAddress),
		KeyFilePath:        firstNonBlank(os.Getenv("BBS_SIGNER_KEY_FILE"), defaultKeyFile),
		AuthToken:          strings.TrimSpace(os.Getenv("BBS_SIGNER_AUTH_TOKEN")),
		DefaultIssuer:      strings.TrimSpace(os.Getenv("BBS_SIGNER_DEFAULT_ISSUER")),
		DefaultProofMethod: strings.TrimSpace(os.Getenv("BBS_SIGNER_DEFAULT_VERIFICATION_METHOD")),
		AllowedOrigins:     allowedOrigins,
	}
}

func newSignerService(cfg config) (*signerService, error) {
	bbs := bbs12381g2pub.New()
	privateKey, publicKey, publicKeyB64, err := loadOrCreateIssuerKeyPair(cfg.KeyFilePath)
	if err != nil {
		return nil, err
	}

	return &signerService{
		cfg:         cfg,
		bbs:         bbs,
		privateKey:  privateKey,
		publicKey:   publicKey,
		publicKeyB6: publicKeyB64,
	}, nil
}

func loadOrCreateIssuerKeyPair(path string) ([]byte, []byte, string, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		store := &keyStore{}
		if err = json.Unmarshal(existing, store); err != nil {
			return nil, nil, "", fmt.Errorf("invalid key file format: %w", err)
		}
		privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(store.PrivateKeyBase64))
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid private key encoding: %w", err)
		}
		publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(store.PublicKeyBase64))
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid public key encoding: %w", err)
		}
		return privateKey, publicKey, store.PublicKeyBase64, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, "", fmt.Errorf("could not read key file: %w", err)
	}

	seed := make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		return nil, nil, "", fmt.Errorf("could not generate key seed: %w", err)
	}

	publicKey, privateKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not generate bbs key pair: %w", err)
	}

	publicKeyBytes, err := publicKey.Marshal()
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not marshal public key: %w", err)
	}
	privateKeyBytes, err := privateKey.Marshal()
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not marshal private key: %w", err)
	}

	store := &keyStore{
		KID:              "issuer-bbs-key-1",
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(publicKeyBytes),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	keyJSON, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not marshal key file: %w", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, "", fmt.Errorf("could not create key dir: %w", err)
	}
	if err = os.WriteFile(path, keyJSON, 0o600); err != nil {
		return nil, nil, "", fmt.Errorf("could not persist key file: %w", err)
	}

	return privateKeyBytes, publicKeyBytes, store.PublicKeyBase64, nil
}

func (s *signerService) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *signerService) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKeyBase64": s.publicKeyB6,
		"signatureSuite":  "BbsBlsSignature2020",
	})
}

func (s *signerService) handleSignCredential(w http.ResponseWriter, r *http.Request) {
	request := &signCredentialRequest{}
	if err := decodeJSON(r, request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}
	if len(request.Credential) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "credential payload is required"})
		return
	}

	credentialToSign, err := deepCopyMap(request.Credential)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "credential payload must be JSON object"})
		return
	}
	delete(credentialToSign, "proof")

	entries := flattenCredential(credentialToSign)
	messages := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		messages = append(messages, []byte(canonicalMessage(entry)))
	}

	signature, err := s.bbs.Sign(messages, s.privateKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "bbs sign failed: " + err.Error()})
		return
	}

	proofValue := base64.StdEncoding.EncodeToString(signature)
	created := strings.TrimSpace(request.Created)
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	proofPurpose := firstNonBlank(strings.TrimSpace(request.ProofPurpose), "assertionMethod")
	verificationMethod := strings.TrimSpace(request.VerificationMethod)
	if verificationMethod == "" {
		verificationMethod = firstNonBlank(
			s.cfg.DefaultProofMethod,
			firstNonBlank(s.cfg.DefaultIssuer, "did:example:issuer")+"#bbs-key-1",
		)
	}

	signedCredential, err := deepCopyMap(credentialToSign)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "could not copy credential"})
		return
	}
	signedCredential["proof"] = map[string]any{
		"type":               "BbsBlsSignature2020",
		"created":            created,
		"proofPurpose":       proofPurpose,
		"verificationMethod": verificationMethod,
		"proofValue":         proofValue,
	}

	response := signCredentialResponse{
		SignedCredential: signedCredential,
		SignatureSuite:   "BbsBlsSignature2020",
		ProofValue:       proofValue,
		PublicKeyBase64:  s.publicKeyB6,
		KID:              "issuer-bbs-key-1",
		MessageCount:     len(messages),
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *signerService) handleDeriveProof(w http.ResponseWriter, r *http.Request) {
	request := &deriveProofRequest{}
	if err := decodeJSON(r, request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}
	if len(request.SignedCredential) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential is required"})
		return
	}

	proofRaw, ok := request.SignedCredential["proof"]
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential.proof is required"})
		return
	}
	proofMap, ok := proofRaw.(map[string]any)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential.proof must be an object"})
		return
	}

	proofType := strings.TrimSpace(asString(proofMap["type"]))
	if proofType == "BbsBlsSignatureProof2020" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential contains a derived proof, not an issuer signature"})
		return
	}

	proofValue, ok := proofMap["proofValue"].(string)
	if !ok || strings.TrimSpace(proofValue) == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential.proof.proofValue is required"})
		return
	}
	signature, err := decodeIssuerSignature(proofValue)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}

	credential, err := deepCopyMap(request.SignedCredential)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential must be a JSON object"})
		return
	}
	delete(credential, "proof")

	entries := flattenCredential(credential)
	fieldIndex := make(map[string]int, len(entries))
	messages := make([][]byte, 0, len(entries))
	for idx, entry := range entries {
		fieldIndex[entry.Path] = idx
		messages = append(messages, []byte(canonicalMessage(entry)))
	}

	if len(request.RevealFields) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "revealFields must contain at least one field path"})
		return
	}

	type revealedItem struct {
		Index   int
		Path    string
		Value   any
		Message string
	}
	revealedItems := make([]revealedItem, 0, len(request.RevealFields))
	seen := make(map[int]struct{})
	for _, field := range request.RevealFields {
		path := strings.TrimSpace(field)
		if path == "" || !fieldPathPattern.MatchString(path) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "invalid reveal field path: " + field})
			return
		}
		idx, found := fieldIndex[path]
		if !found {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "reveal field not found in credential: " + path})
			return
		}
		if _, exists := seen[idx]; exists {
			continue
		}
		seen[idx] = struct{}{}
		revealedItems = append(revealedItems, revealedItem{
			Index:   idx,
			Path:    path,
			Value:   entries[idx].Value,
			Message: canonicalMessage(entries[idx]),
		})
	}
	sort.Slice(revealedItems, func(i, j int) bool {
		return revealedItems[i].Index < revealedItems[j].Index
	})

	revealedIndexes := make([]int, 0, len(revealedItems))
	revealedMessages := make([]string, 0, len(revealedItems))
	revealedClaims := make(map[string]any, len(revealedItems))
	for _, item := range revealedItems {
		revealedIndexes = append(revealedIndexes, item.Index)
		revealedMessages = append(revealedMessages, item.Message)
		revealedClaims[item.Path] = item.Value
	}
	sort.Ints(revealedIndexes)

	nonce, nonceB64, err := resolveNonce(request.Nonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}

	proofBytes, err := s.bbs.DeriveProof(messages, signature, nonce, s.publicKey, revealedIndexes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "bbs derive proof failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, deriveProofResponse{
		ProofValue:       base64.StdEncoding.EncodeToString(proofBytes),
		Nonce:            nonceB64,
		SignatureSuite:   "BbsBlsSignatureProof2020",
		RevealedIndexes:  revealedIndexes,
		RevealedClaims:   revealedClaims,
		RevealedMessages: revealedMessages,
	})
}

func (s *signerService) handleVerifyProof(w http.ResponseWriter, r *http.Request) {
	request := &verifyProofRequest{}
	if err := decodeJSON(r, request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}

	proofValue := strings.TrimSpace(request.ProofValue)
	if proofValue == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "proofValue is required"})
		return
	}
	proofBytes, err := base64.StdEncoding.DecodeString(proofValue)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "proofValue must be valid base64"})
		return
	}

	nonceInput := strings.TrimSpace(request.Nonce)
	if nonceInput == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "nonce is required"})
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceInput)
	if err != nil || len(nonce) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "nonce must be valid base64"})
		return
	}

	var revealedMessages [][]byte
	if len(request.SignedCredential) > 0 {
		if len(request.RevealFields) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "revealFields are required when signedCredential is provided"})
			return
		}

		credential, errCopy := deepCopyMap(request.SignedCredential)
		if errCopy != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "signedCredential must be a JSON object"})
			return
		}
		delete(credential, "proof")

		entries := flattenCredential(credential)
		fieldIndex := make(map[string]int, len(entries))
		for idx, entry := range entries {
			fieldIndex[entry.Path] = idx
		}

		type msgItem struct {
			index   int
			message string
		}
		items := make([]msgItem, 0, len(request.RevealFields))
		seen := make(map[int]struct{})
		for _, field := range request.RevealFields {
			path := strings.TrimSpace(field)
			if path == "" || !fieldPathPattern.MatchString(path) {
				writeJSON(w, http.StatusBadRequest, errorResponse{Message: "invalid reveal field path: " + field})
				return
			}
			idx, found := fieldIndex[path]
			if !found {
				writeJSON(w, http.StatusBadRequest, errorResponse{Message: "reveal field not found in credential: " + path})
				return
			}
			if _, exists := seen[idx]; exists {
				continue
			}
			seen[idx] = struct{}{}
			items = append(items, msgItem{
				index:   idx,
				message: canonicalMessage(entries[idx]),
			})
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].index < items[j].index
		})

		revealedMessages = make([][]byte, 0, len(items))
		for _, item := range items {
			revealedMessages = append(revealedMessages, []byte(item.message))
		}
	} else {
		if len(request.RevealedMessages) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "revealedMessages is required when signedCredential is not provided"})
			return
		}

		revealedMessages = make([][]byte, 0, len(request.RevealedMessages))
		for _, message := range request.RevealedMessages {
			value := strings.TrimSpace(message)
			if value == "" {
				continue
			}
			revealedMessages = append(revealedMessages, []byte(value))
		}
	}

	if len(revealedMessages) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "at least one revealed message is required"})
		return
	}

	err = s.bbs.VerifyProof(revealedMessages, proofBytes, nonce, s.publicKey)
	if err != nil {
		writeJSON(w, http.StatusOK, verifyProofResponse{
			Valid:          false,
			SignatureSuite: "BbsBlsSignatureProof2020",
			Message:        "bbs verify proof failed: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, verifyProofResponse{
		Valid:          true,
		SignatureSuite: "BbsBlsSignatureProof2020",
	})
}

func (s *signerService) handleWrapKey(w http.ResponseWriter, r *http.Request) {
	request := &wrapKeyRequest{}
	if err := decodeJSON(r, request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: err.Error()})
		return
	}
	recipientPublicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.RecipientPublicKeyBase64))
	if err != nil || len(recipientPublicKey) != 32 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "recipientPublicKeyBase64 must be base64 of 32-byte X25519 key"})
		return
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.PayloadBase64))
	if err != nil || len(payloadBytes) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "payloadBase64 must be valid non-empty base64"})
		return
	}

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], recipientPublicKey)

	ephemeralPubKey, ephemeralPrivKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Message: "failed to generate ephemeral key"})
		return
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Message: "failed to generate nonce"})
		return
	}

	ciphertext := box.Seal(nil, payloadBytes, &nonce, &recipientPubKey, ephemeralPrivKey)
	envelope := map[string]any{
		"version":        keyWrapVersion,
		"nonce":          base64.StdEncoding.EncodeToString(nonce[:]),
		"ephemPublicKey": base64.StdEncoding.EncodeToString(ephemeralPubKey[:]),
		"ciphertext":     base64.StdEncoding.EncodeToString(ciphertext),
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Message: "failed to marshal wrapped payload"})
		return
	}

	writeJSON(w, http.StatusOK, wrapKeyResponse{
		EnvelopeJSON: string(envelopeJSON),
		EnvelopeHex:  "0x" + hex.EncodeToString(envelopeJSON),
		Version:      keyWrapVersion,
	})
}

func resolveNonce(input string) ([]byte, string, error) {
	if strings.TrimSpace(input) != "" {
		nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
		if err != nil || len(nonce) == 0 {
			return nil, "", errors.New("nonce must be valid base64")
		}
		return nonce, base64.StdEncoding.EncodeToString(nonce), nil
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", errors.New("could not generate nonce")
	}
	return nonce, base64.StdEncoding.EncodeToString(nonce), nil
}

func flattenCredential(value map[string]any) []canonicalEntry {
	out := make([]canonicalEntry, 0, 64)
	flattenNode("", value, &out)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

func flattenNode(path string, value any, out *[]canonicalEntry) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			flattenNode(nextPath, typed[key], out)
		}
	case []any:
		for idx, elem := range typed {
			nextPath := fmt.Sprintf("%s[%d]", path, idx)
			if path == "" {
				nextPath = fmt.Sprintf("[%d]", idx)
			}
			flattenNode(nextPath, elem, out)
		}
	default:
		*out = append(*out, canonicalEntry{
			Path:  path,
			Value: typed,
		})
	}
}

func canonicalMessage(entry canonicalEntry) string {
	rawValue, err := json.Marshal(entry.Value)
	if err != nil {
		rawValue = []byte(`""`)
	}
	return entry.Path + "=" + string(rawValue)
}

func deepCopyMap(value map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	copied := make(map[string]any)
	if err = json.Unmarshal(raw, &copied); err != nil {
		return nil, err
	}
	return copied, nil
}

func decodeIssuerSignature(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, errors.New("signedCredential.proof.proofValue is required")
	}

	var decoded []byte
	var err error

	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		decoded, err = hex.DecodeString(value[2:])
		if err != nil {
			return nil, errors.New("proof.proofValue hex is invalid")
		}
	} else {
		decoded, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(value)
		}
		if err != nil {
			if len(value)%2 == 0 && hexOnlyPattern.MatchString(value) {
				decoded, err = hex.DecodeString(value)
			}
		}
		if err != nil {
			return nil, errors.New("proof.proofValue must be base64 or hex")
		}
	}

	if len(decoded) != bbsSignatureLen {
		return nil, fmt.Errorf("proof.proofValue is %d bytes, expected %d-byte BBS signature", len(decoded), bbsSignatureLen)
	}
	return decoded, nil
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func (s *signerService) withAuth(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken != "" {
			token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if token != s.cfg.AuthToken {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Message: "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (s *signerService) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *signerService) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowOrigin := ""
		if origin != "" && originAllowed(origin, s.cfg.AllowedOrigins) {
			allowOrigin = origin
		}
		if allowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func originAllowed(origin string, allowed []string) bool {
	if origin == "" || len(allowed) == 0 {
		return false
	}
	for _, candidate := range allowed {
		clean := strings.TrimSpace(candidate)
		if clean == "*" || strings.EqualFold(clean, origin) {
			return true
		}
	}
	return false
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	reader := io.LimitReader(r.Body, 2<<20)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid JSON payload: " + err.Error())
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func firstNonBlank(first string, fallback string) string {
	if strings.TrimSpace(first) != "" {
		return strings.TrimSpace(first)
	}
	return fallback
}
