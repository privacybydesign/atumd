package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/bwesterb/go-pow"
	"golang.org/x/crypto/ed25519"
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
