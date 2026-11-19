package system

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes a command without a shell. Implementations must not interpolate
// arguments into a shell string.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Local runs commands on the host (or in this container's mount and network namespace).
type Local struct{}

func (Local) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(out)
		}
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("%s: %s", name, msg)
	}
	return out, nil
}
