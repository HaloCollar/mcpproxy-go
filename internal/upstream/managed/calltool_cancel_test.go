package managed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/upstream/types"
)

// fakeToolCaller injects a canned tools/call outcome in place of the concrete
// core client, so the managed-side error classification (GH #965) can be
// exercised without a live upstream.
type fakeToolCaller struct {
	mu     sync.Mutex
	calls  int
	err    error
	result *mcp.CallToolResult
	// waitCtx makes CallTool block until the caller's context is done and
	// return the transport-shaped error, like a slow upstream call does.
	waitCtx bool
}

func (f *fakeToolCaller) CallTool(ctx context.Context, _ string, _ map[string]interface{}) (*mcp.CallToolResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.waitCtx {
		<-ctx.Done()
		return nil, fmt.Errorf("CallTool failed for 'slow': transport error: %w", ctx.Err())
	}
	return f.result, f.err
}

func (f *fakeToolCaller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newTestClientForCallTool builds a Ready managed client with a fake tool
// invoker wired in (mirrors newTestClientForHealth in health_flap_test.go).
func newTestClientForCallTool(t *testing.T, callErr error) (*Client, *fakeToolCaller) {
	t.Helper()
	mc := newTestClientForHealth(t)
	fake := &fakeToolCaller{err: callErr}
	mc.toolInvoker = fake
	return mc, fake
}

// TestCallTool_CallerCanceledContextDoesNotEvictServer: an HTTP client that
// hangs up cancels the request context, the upstream call returns "context
// canceled", and the whole server used to be evicted for every other client.
// A caller-scoped cancellation must never touch server state (GH #965).
func TestCallTool_CallerCanceledContextDoesNotEvictServer(t *testing.T) {
	mc, fake := newTestClientForCallTool(t,
		fmt.Errorf("CallTool failed for 'search': transport error: %w", context.Canceled))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller went away before the call returned

	_, err := mc.CallTool(ctx, "search", nil)

	require.Error(t, err)
	assert.Equal(t, 1, fake.callCount())
	assert.Equal(t, types.StateReady, mc.StateManager.GetState(),
		"a caller-canceled tool call must not evict the upstream")
	assert.Equal(t, 0, mc.StateManager.GetConnectionInfo().RetryCount,
		"a caller-canceled tool call must not burn the reconnect budget")
}

// TestCallTool_CallerDeadlineDoesNotEvictServer is the slow-tool shape: a
// legitimately long tool call outlives the caller's per-request deadline. The
// upstream is still healthy, so it must stay Ready.
func TestCallTool_CallerDeadlineDoesNotEvictServer(t *testing.T) {
	mc, fake := newTestClientForCallTool(t, nil)
	fake.waitCtx = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := mc.CallTool(ctx, "slow", nil)

	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
	assert.Equal(t, types.StateReady, mc.StateManager.GetState(),
		"a tool call that outlives the caller's deadline must not evict the upstream")
	assert.Equal(t, 0, mc.StateManager.GetConnectionInfo().RetryCount)
}

// TestCallTool_TransportErrorWithLiveContextStillEvicts is the control: hard
// transport evidence with the caller still waiting keeps marking the server
// failed, exactly as before.
func TestCallTool_TransportErrorWithLiveContextStillEvicts(t *testing.T) {
	mc, _ := newTestClientForCallTool(t,
		errors.New("CallTool failed for 'search': transport error: write: broken pipe"))

	_, err := mc.CallTool(context.Background(), "search", nil)

	require.Error(t, err)
	assert.Equal(t, types.StateError, mc.StateManager.GetState(),
		"a real transport failure must still mark the upstream failed")
}
