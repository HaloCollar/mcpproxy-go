package managed

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	uptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/config"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/secret"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/upstream/types"
)

// stdioCrashHelperEnv switches the test binary into a tiny stdio MCP server
// (TestStdioCrashHelperProcess) so the crash tests below launch, kill and
// relaunch a real child process without any node/python dependency.
const stdioCrashHelperEnv = "MCPPROXY_TEST_STDIO_CRASH_HELPER"

// TestStdioCrashHelperProcess is not a test: when stdioCrashHelperEnv is set it
// serves MCP over stdio with one tool, "pid", that returns the helper's own
// process id, and exits when stdin closes.
func TestStdioCrashHelperProcess(t *testing.T) {
	if os.Getenv(stdioCrashHelperEnv) != "1" {
		t.Skip("helper process for the stdio crash tests")
	}
	s := server.NewMCPServer("stdio-crash-helper", "1.0.0", server.WithToolCapabilities(false))
	s.AddTool(mcp.NewTool("pid", mcp.WithDescription("returns the helper process id")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(strconv.Itoa(os.Getpid())), nil
		})
	_ = server.ServeStdio(s)
	os.Exit(0)
}

// newStdioCrashClient builds a managed client whose upstream is the helper
// above, connects it and returns it Ready.
func newStdioCrashClient(t *testing.T) *Client {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stdio crash tests launch the test binary through a POSIX shell")
	}
	exe, err := os.Executable()
	require.NoError(t, err)

	serverConfig := &config.ServerConfig{
		Name:     "stdio-crash-helper",
		Command:  exe,
		Args:     []string{"-test.run=^TestStdioCrashHelperProcess$"},
		Env:      map[string]string{stdioCrashHelperEnv: "1"},
		Protocol: "stdio",
		Enabled:  true,
	}
	mc, err := NewClient("stdio-crash-helper", serverConfig, zap.NewNop(), nil, config.DefaultConfig(), nil, secret.NewResolver())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, mc.Connect(ctx))
	require.Equal(t, types.StateReady, mc.StateManager.GetState())
	t.Cleanup(func() { _ = mc.Disconnect() })
	return mc
}

// helperPID calls the helper's "pid" tool through the managed client.
func helperPID(t *testing.T, mc *Client) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := mc.CallTool(ctx, "pid", nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Content)
	text, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok, "pid tool must return text content")
	pid, err := strconv.Atoi(text.Text)
	require.NoError(t, err)
	return pid
}

// killHelper kills the helper child the way an upstream crash would.
func killHelper(t *testing.T, pid int) {
	t.Helper()
	proc, err := os.FindProcess(pid)
	require.NoError(t, err)
	require.NoError(t, proc.Kill())
}

// relaunchViaHealthLoop drives the health loop (the background relaunch path,
// gated by the StateManager backoff) until the server is Ready again.
func relaunchViaHealthLoop(t *testing.T, mc *Client) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		mc.performHealthCheck()
		if mc.StateManager.GetState() == types.StateReady {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server was not relaunched; state %s, last error %v",
		mc.StateManager.GetState(), mc.StateManager.GetConnectionInfo().LastError)
}

func assertProcessExitState(t *testing.T, mc *Client) {
	t.Helper()
	info := mc.StateManager.GetConnectionInfo()
	assert.Equal(t, types.StateError, info.State, "a dead stdio child must take the server out of Ready")
	require.Error(t, info.LastError)
	assert.Contains(t, info.LastError.Error(), "transport closed")
	assert.Contains(t, info.LastError.Error(), "stdio server process exited",
		"the server status must say the process exited")
	assert.False(t, mc.IsConnected())
}

// TestStdioCrash_HealthCheckDetectsDeadChildAndRelaunches kills the stdio child
// with no client traffic. The background health ping must see the closed
// transport, mark the server Error and then relaunch a new child.
func TestStdioCrash_HealthCheckDetectsDeadChildAndRelaunches(t *testing.T) {
	mc := newStdioCrashClient(t)
	pid1 := helperPID(t, mc)
	killHelper(t, pid1)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && mc.StateManager.GetState() == types.StateReady {
		mc.performHealthCheck()
		time.Sleep(100 * time.Millisecond)
	}
	assertProcessExitState(t, mc)

	relaunchViaHealthLoop(t, mc)
	pid2 := helperPID(t, mc)
	assert.NotEqual(t, pid1, pid2, "a new child process must serve after the relaunch")
	assert.Equal(t, types.StateReady, mc.StateManager.GetState())
}

// TestStdioCrash_CallToolOnDeadChildMarksErrorAndRelaunches kills the child and
// then calls a tool: the failed call must take the server out of Ready (it used
// to stay Ready with "transport closed"), and the health loop must relaunch it.
func TestStdioCrash_CallToolOnDeadChildMarksErrorAndRelaunches(t *testing.T) {
	mc := newStdioCrashClient(t)
	pid1 := helperPID(t, mc)
	killHelper(t, pid1)

	var callErr error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, callErr = mc.CallTool(ctx, "pid", nil)
		cancel()
		if callErr != nil && mc.StateManager.GetState() != types.StateReady {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.Error(t, callErr, "a call to a dead child must fail")
	assertProcessExitState(t, mc)

	relaunchViaHealthLoop(t, mc)
	pid2 := helperPID(t, mc)
	assert.NotEqual(t, pid1, pid2, "a new child process must serve after the relaunch")
}

// TestMarkConnectionLost_IgnoredWhenNotReady checks that a late "transport
// closed" from an in-flight call after a deliberate disconnect does not flip a
// Disconnected server to Error (which would make it relaunch by itself).
func TestMarkConnectionLost_IgnoredWhenNotReady(t *testing.T) {
	mc := newTestClientForHealth(t)
	mc.StateManager.TransitionTo(types.StateDisconnected)

	mc.markConnectionLost(uptransport.ErrTransportClosed)

	assert.Equal(t, types.StateDisconnected, mc.StateManager.GetState())
	assert.Equal(t, 0, mc.StateManager.GetConnectionInfo().RetryCount)
}

// TestIsConnectionError_TransportClosed pins the classification of mcp-go's
// closed-transport error, wrapped or not.
func TestIsConnectionError_TransportClosed(t *testing.T) {
	mc := newTestClientForHealth(t)
	assert.True(t, mc.isConnectionError(uptransport.ErrTransportClosed))
	assert.True(t, mc.isConnectionError(fmt.Errorf("transport error: failed to send request: %w", uptransport.ErrTransportClosed)))
}

// TestPerformHealthCheck_HTTPEOFKeepsReady pins that the closed-transport
// classification stays narrow: a stray EOF on an HTTP ping is still ignored
// as before and does not flip the server to Error on the first miss.
func TestPerformHealthCheck_HTTPEOFKeepsReady(t *testing.T) {
	mc := newTestClientForHealth(t)
	mc.healthProbe = &fakeProber{pingErr: fmt.Errorf(`Post "https://example.invalid/mcp": %w`, io.EOF)}

	mc.performHealthCheck()

	assert.Equal(t, types.StateReady, mc.StateManager.GetState())
}
