package netif

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTxQueueCount(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tx-0", "tx-1", "tx-2", "rx-0", "rx-1"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := txQueueCount(dir); err != nil || n != 3 {
		t.Fatalf("txQueueCount = %d, %v; want 3", n, err)
	}

	empty := t.TempDir()
	if _, err := txQueueCount(empty); err == nil {
		t.Fatal("expected an error with no TX queues")
	}
}
