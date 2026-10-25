package connect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"toktrail-collector/internal/local/statedir"
)

// computeReceiptFingerprint calculates a deterministic SHA-256 fingerprint
// over the ticket and canonical connect endpoint URL. The ticket is never
// saved in plaintext.
func computeReceiptFingerprint(ticket, strippedURL string) string {
	h := sha256.New()
	h.Write([]byte(ticket))
	h.Write([]byte("\x00"))
	h.Write([]byte(strings.ToLower(strings.TrimRight(strippedURL, "/"))))
	return hex.EncodeToString(h.Sum(nil))
}

// shouldSkipBind returns true only if the device state was already successfully
// bound for this exact ticket/url receipt fingerprint or bind fingerprint and the identity exactly matches.
// Crucially, pending fingerprints are NOT sufficient proof of binding, preventing false skips
// on rerun after a failed bind on previously bound devices.
func shouldSkipBind(st statedir.DeviceState, receiptFingerprint string, bindFingerprint string, cfg Config) bool {
	if st.DeviceID == "" {
		return false
	}
	hasAtomicProof := (st.ConnectReceiptHash != "" && st.ConnectReceiptHash == receiptFingerprint) ||
		(st.LastBindFingerprint != "" && st.LastBindFingerprint == bindFingerprint)
	if !hasAtomicProof {
		return false
	}
	if strings.TrimRight(st.ServerURL, "/") != strings.TrimRight(cfg.ServerURL, "/") {
		return false
	}
	if st.ApplicationID != cfg.ApplicationID {
		return false
	}
	if st.ExternalSubjectID != cfg.SubjectID {
		return false
	}
	return true
}
