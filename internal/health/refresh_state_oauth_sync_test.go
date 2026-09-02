package health_test

// This test lives in the external health_test package (not health) rather
// than calculator_test.go: internal/oauth's status.go now imports
// internal/health (for ApplyToHealthInput's *health.HealthCalculatorInput
// parameter, added in the review follow-up to 3dfeacec). An internal test
// file (package health) importing internal/oauth back would create an
// import cycle — go vet: "import cycle not allowed in test" — because both
// oauth and the health test variant would need to resolve the same package.
// The external health_test package has no such constraint: it is a
// distinct package from health, so it can import both health and oauth
// freely.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/health"
	"github.com/smart-mcp-proxy/mcpproxy-go/internal/oauth"
)

// TestRefreshStateSync ensures health.RefreshState values stay in sync with
// oauth.RefreshState. The health package mirrors oauth.RefreshState for
// decoupling, but the values must match for proper state mapping when
// wiring RefreshManager state into health calculation.
func TestRefreshStateSync(t *testing.T) {
	// Verify that the integer values match between health and oauth packages.
	// This test will fail if either package changes its constants without
	// updating the other.
	assert.Equal(t, int(health.RefreshStateIdle), int(oauth.RefreshStateIdle),
		"RefreshStateIdle values must match between health and oauth packages")
	assert.Equal(t, int(health.RefreshStateScheduled), int(oauth.RefreshStateScheduled),
		"RefreshStateScheduled values must match between health and oauth packages")
	assert.Equal(t, int(health.RefreshStateRetrying), int(oauth.RefreshStateRetrying),
		"RefreshStateRetrying values must match between health and oauth packages")
	assert.Equal(t, int(health.RefreshStateFailed), int(oauth.RefreshStateFailed),
		"RefreshStateFailed values must match between health and oauth packages")
}
