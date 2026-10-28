package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestManualEnableRequiresExplicitLocalConfirmation(t *testing.T) {
	dir := t.TempDir()
	for _, flags := range [][]string{{"--token-stdin"}, {"--confirm-local"}, {"PRIVATE-POSITIONAL-SENTINEL"}} {
		args := append([]string{"--state-dir", dir}, flags...)
		_, _, _, err := parseCursorEnableArgs(args)
		if err == nil {
			t.Fatal("manual enable accepted an incomplete consent or credential argument")
		}
		if strings.Contains(err.Error(), "PRIVATE-POSITIONAL-SENTINEL") {
			t.Fatal("error echoed positional credential")
		}
	}
	gotDir, _, manual, err := parseCursorEnableArgs([]string{"--state-dir", dir, "--token-stdin", "--confirm-local"})
	if err != nil || !manual || gotDir != dir {
		t.Fatalf("explicit manual enable rejected: %v", err)
	}
	_, _, manual, err = parseCursorEnableArgs([]string{"--state-dir", dir})
	if err != nil || manual {
		t.Fatal("normal enable no longer uses desktop login")
	}
}

func TestManualProviderReadsCredentialOnlyOnceAndRedactsIt(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	const token = "SYNTHETIC-MANUAL-CREDENTIAL-SENTINEL"
	if _, err = writer.WriteString(token + "\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	provider, err := protectedManualProvider(input)
	if err != nil {
		t.Fatal(err)
	}
	// The enable flow verifies and then runs sync, which fetches again.
	for i := 0; i < 2; i++ {
		cred, err := provider.Fetch(context.Background())
		if err != nil || cred.AccessToken != token {
			t.Fatalf("manual credential unavailable on call %d: %v", i, err)
		}
	}
	rendered := fmt.Sprintf("%v %+v %#v", provider, provider, provider)
	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered+string(encoded), token) {
		t.Fatal("manual credential escaped through formatting or JSON")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = provider.Fetch(ctx); err != context.Canceled {
		t.Fatal("cached credential ignored cancellation")
	}
}

func TestManualConfirmationPrintsNoticeWithoutReadingStdin(t *testing.T) {
	var out bytes.Buffer
	yes, err := manualEnableConfirmation("Account collection permission notice", &out)
	if err != nil || !yes || !strings.Contains(out.String(), "permission notice") {
		t.Fatal("explicit manual confirmation did not display its notice")
	}
}

func TestProtectedManualProviderRefusesMissingInput(t *testing.T) {
	if _, err := protectedManualProvider(nil); err == nil {
		t.Fatal("missing protected input accepted")
	}
}
