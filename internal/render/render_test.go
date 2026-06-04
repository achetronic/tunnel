package render

import (
	"flag"
	"os"
	"testing"
)

// update regenerates the golden files when passed as -update to go test.
var update = flag.Bool("update", false, "regenerate golden files in testdata/")

// goldenRead reads a golden file, or calls t.Fatal if the file is missing
// and -update was not requested.
func goldenRead(t *testing.T, name string, got []byte) []byte {
	t.Helper()
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("failed to write golden file %s: %v", path, err)
		}
		return got
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file %s missing; run with -update to create it: %v", path, err)
	}
	return want
}
