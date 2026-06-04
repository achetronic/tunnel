package sshexec

import "context"

// FakeExecutor is an in-memory Executor used in tests. It records every command
// run and every file written, and lets tests override behaviour through RunFunc
// and PutFunc. It honours context cancellation so tests can exercise the same
// cancellation paths as the real executor.
type FakeExecutor struct {
	// RunFunc, when set, provides the response for Run. It receives the same
	// context passed by the caller.
	RunFunc func(ctx context.Context, cmd string) (string, error)
	// PutFunc, when set, provides the response for Put.
	PutFunc func(ctx context.Context, path string, content []byte) error

	// Files holds the content written through Put, keyed by path.
	Files map[string][]byte
	// Runs records, in order, every command passed to Run.
	Runs []string
}

// NewFakeExecutor returns a ready FakeExecutor with an initialised file map.
func NewFakeExecutor() *FakeExecutor {
	return &FakeExecutor{
		Files: make(map[string][]byte),
	}
}

// Run records cmd, honours context cancellation, and delegates to RunFunc when
// set; otherwise it returns an empty successful result.
func (f *FakeExecutor) Run(ctx context.Context, cmd string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.Runs = append(f.Runs, cmd)
	if f.RunFunc != nil {
		return f.RunFunc(ctx, cmd)
	}
	return "", nil
}

// Put records the written content, honours context cancellation, and delegates
// to PutFunc when set; otherwise it returns success.
func (f *FakeExecutor) Put(ctx context.Context, path string, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.Files[path] = append([]byte(nil), content...)
	if f.PutFunc != nil {
		return f.PutFunc(ctx, path, content)
	}
	return nil
}
