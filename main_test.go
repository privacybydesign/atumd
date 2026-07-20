package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/bwesterb/go-pow"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"
)

// TestSignSmoke exercises the timestamping endpoint (POST /) end-to-end with
// Ed25519: boots minimal global state, posts an atum.Request, and verifies the
// returned signature against the in-test public key.
func TestSignSmoke(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	conf = Conf{
		CanonicalUrl:       "http://test",
		MaxNonceSize:       128,
		AcceptableLag:      60,
		DefaultSigAlg:      atum.Ed25519,
		DisableOtherSigAlg: true,
	}
	ed25519Sk = sk
	ed25519Pk = pk
	serverInfo = atum.ServerInfo{
		MaxNonceSize:        conf.MaxNonceSize,
		AcceptableLag:       conf.AcceptableLag,
		DefaultSigAlg:       conf.DefaultSigAlg,
		RequiredProofOfWork: map[atum.SignatureAlgorithm]pow.Request{},
	}

	nonce := []byte("smoke-test-nonce")
	body, err := json.Marshal(atum.Request{Nonce: nonce})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rootHandler(rr, req)

	if rr.Code != http.StatusOK {
		out, _ := io.ReadAll(rr.Result().Body)
		t.Fatalf("status %d, body %q", rr.Code, out)
	}

	var resp atum.Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("server returned error: %s", *resp.Error)
	}
	if resp.Stamp == nil {
		t.Fatal("response has no stamp")
	}
	if resp.Stamp.ServerUrl != conf.CanonicalUrl {
		t.Errorf("ServerUrl = %q, want %q", resp.Stamp.ServerUrl, conf.CanonicalUrl)
	}
	if resp.Stamp.Sig.Alg != atum.Ed25519 {
		t.Errorf("Sig.Alg = %q, want %q", resp.Stamp.Sig.Alg, atum.Ed25519)
	}

	ok, verr := resp.Stamp.Sig.DangerousVerifySignatureButNotPublicKey(
		resp.Stamp.Time, nonce)
	if verr != nil {
		t.Fatalf("verify: %v", verr)
	}
	if !ok {
		t.Fatal("signature did not verify")
	}
}

// TestRequestBodyLimit verifies the 4 KiB MaxBytesReader cap rejects oversize
// POST bodies with 413 instead of silently allocating arbitrarily large buffers.
func TestRequestBodyLimit(t *testing.T) {
	rr := httptest.NewRecorder()
	body := bytes.Repeat([]byte("A"), 8*1024)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	requestHandler(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: status %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestHealthCheckContentType is a regression test for the WriteHeader/Header
// ordering bug: setting headers after WriteHeader silently drops them.
func TestHealthCheckContentType(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	healthCheckHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/plain")
	}
}

// TestKeyFilePermsInsecure guards the private-key file permission check that
// both loadXMSSMTKey and loadEd25519Key rely on: a signing key that is group-
// or world-accessible must be treated as insecure and refused, while a 0600
// key is accepted.
func TestKeyFilePermsInsecure(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want bool
	}{
		{0600, false},
		{0400, false},
		{0640, true},
		{0604, true},
		{0644, true},
		{0666, true},
		{0700, false}, // owner-only, group/world bits clear
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte("key"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		fileInfo, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if got := keyFilePermsInsecure(fileInfo); got != c.want {
			t.Errorf("keyFilePermsInsecure(%#o) = %v, want %v",
				c.mode, got, c.want)
		}
	}
}

// TestXMSSMTBorrowedSeqNosYAMLTag is a regression test for the `taml` →
// `yaml` struct-tag typo: the xmssmtBorrowedSeqNos config key was silently
// ignored before the fix.
func TestXMSSMTBorrowedSeqNosYAMLTag(t *testing.T) {
	var c Conf
	if err := yaml.Unmarshal([]byte("xmssmtBorrowedSeqNos: 42\n"), &c); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if c.XMSSMTBorrowedSeqNos == nil {
		t.Fatal("XMSSMTBorrowedSeqNos is nil — yaml tag not honored")
	}
	if *c.XMSSMTBorrowedSeqNos != 42 {
		t.Fatalf("XMSSMTBorrowedSeqNos = %d, want 42", *c.XMSSMTBorrowedSeqNos)
	}
}

// TestServerInfoConcurrentAccess guards against the data race between
// powNonceRevolver (which calls computePowNonces) and the request/serverInfo
// handlers (which read serverInfo.RequiredProofOfWork via getServerInfo).
// Run with -race: before the fix, the in-place map mutation in
// computePowNonces races with the map reads here.
func TestServerInfoConcurrentAccess(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	conf = Conf{PowWindow: time.Hour, PowKey: make([]byte, 32)}
	diff := uint32(16)
	conf.Ed25519PowDifficulty = &diff
	conf.XMSSMTPowDifficulty = &diff
	serverInfo = atum.ServerInfo{
		RequiredProofOfWork: make(map[atum.SignatureAlgorithm]pow.Request),
	}

	const iters = 200
	var wg sync.WaitGroup

	// Writers: mimic the nonce revolver.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				computePowNonces()
			}
		}()
	}

	// Readers: mimic serverInfoHandler / processAtumRequest reading the map.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				info := getServerInfo()
				_, _ = json.Marshal(info)
				_ = info.RequiredProofOfWork[atum.XMSSMT]
			}
		}()
	}

	wg.Wait()
}
