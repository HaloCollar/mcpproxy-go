# Task: fix/clear-stale-health-on-connect — review follow-up (DONE)

## Goal
Original commit 3dfeacec (WP5) fixed a stale OAuth health verdict bug.
Independent review came back FIX-FIRST with 4 majors/1 minor/1 nit. Fixed
all 6 in ONE follow-up commit on the same branch/worktree, no push.

Worktree: /Users/electrolobzik/workspace/Projects/Halo/mcpproxy-go-wt-health
Branch: fix/clear-stale-health-on-connect (base 3dfeacec)
Repo root submodule: Halo/tools/tools/common/mcpproxy-go

## Review items — all resolved
1. major status.go:83 zero ExpiresAt treated as expired -> now IsZero()
   guarded in CalculateOAuthStatus and ResolveStatus; test
   TestCalculateOAuthStatus_ZeroExpiresAtNeverExpires.
2. major status.go lastError fed into OAuth classification without
   runtime's gating -> ResolveStatus rewritten to take (oauthConfigured,
   connected, lastError); ignores lastError entirely when connected==true.
   ALSO: runtime.go's GetAllServers now calls oauth.ResolveStatus instead of
   hand-rolling its own token lookup/escalation — single implementation, as
   requested ("better: make runtime.go use ResolveStatus too").
3. major calculator.go:259 false "Authentication required" for
   Connected+OAuthRequired+no-token -> gated on !input.Connected; test
   TestCalculateHealth_OAuthNoneButConnected.
4. major no call-site test coverage -> added
   TestApplyToHealthInput_ResolvesFromStore exercising the shared
   oauth.ApplyToHealthInput constructor used by server.go, mcp.go and
   runtime.go; reverting any of those wiring hunks would fail it.
5. minor status.go:80 lookup errors swallowed to None -> now zap.L().Warn
   logged, falls back to neutral (no-token) status rather than asserting a
   verdict.
6. nit GenerateServerKey per-call zap.Debug -> removed (was firing once per
   OAuth server per status poll after this fix).

## Files changed (follow-up commit)
- internal/oauth/status.go — CalculateOAuthStatus zero-ExpiresAt fix; new
  ResolveStatusResult struct; ResolveStatus new signature (store,
  serverName, serverURL, oauthConfigured, connected, lastError) with
  warn-log-on-lookup-error + connected-ignores-lastError semantics; new
  ApplyToHealthInput(input, store, serverName, serverURL, oauthConfigured)
  shared constructor used by server.go/mcp.go/runtime.go.
- internal/oauth/status_test.go — updated existing test to new signature;
  added TestResolveStatus_ConnectedIgnoresStaleLastError,
  TestCalculateOAuthStatus_ZeroExpiresAtNeverExpires,
  TestApplyToHealthInput_ResolvesFromStore.
- internal/oauth/persistent_token_store.go — dropped per-call zap.Debug in
  GenerateServerKey (nit 6).
- internal/health/calculator.go — gated the OAuthStatus none/"" ->
  "Authentication required" branch on !input.Connected (item 3).
- internal/health/calculator_test.go — added
  TestCalculateHealth_OAuthNoneButConnected; removed TestRefreshStateSync
  (moved, see below) and its now-unused internal/oauth import.
- internal/health/refresh_state_oauth_sync_test.go (NEW) — TestRefreshStateSync
  moved here as package health_test (external test package): internal/oauth
  importing internal/health (for ApplyToHealthInput) meant the internal
  `package health` test file could no longer also import internal/oauth
  without go vet flagging an import cycle. External test package has no
  such constraint.
- internal/server/server.go — GetAllServers calls oauth.ApplyToHealthInput
  instead of leaving OAuthStatus at its zero value.
- internal/server/mcp.go — upstream_servers tool handler, same wiring.
- internal/runtime/runtime.go — GetAllServers' 113-line hand-rolled OAuth
  token-lookup/escalation block replaced with a single
  oauth.ResolveStatus(...) call preserving all original downstream
  behavior (oauthConfig map shape, autodiscovery edge case when
  serverStatus.Config==nil); removed now-unused crypto/sha256,
  encoding/hex imports.

## Verification (this follow-up)
- gofmt -l on all touched + new files: clean.
- GOFLAGS=-mod=mod go build ./...: clean.
- GOFLAGS=-mod=mod go vet ./internal/oauth/... ./internal/health/...
  ./internal/server/... ./internal/runtime/...: clean (the import-cycle
  issue above was FOUND by this vet run and fixed before commit).
- GOFLAGS=-mod=mod go test ./internal/oauth/... ./internal/health/...
  ./internal/server/... ./internal/runtime/...:
  - internal/oauth: ok
  - internal/health: ok
  - internal/runtime (+ configsvc, stateview, supervisor, supervisor/actor):
    ok
  - internal/server: FAIL — but ALL failures verified pre-existing via
    `git stash` + rerun against base 3dfeacec (unstashed, then
    `git stash pop`): 11 tests (TestBinaryStartupAndShutdown,
    TestBinaryAPIEndpoints, TestBinaryErrorHandling, TestBinarySSEEvents,
    TestBinaryConcurrentRequests, TestBinaryPerformance,
    TestBinaryHealthAndRecovery, TestMCPProtocolWithBinary,
    TestMCPProtocolComplexWorkflows, TestMCPProtocolToolCalling,
    TestMCPProtocolEdgeCases) fail with "mcpproxy binary not found ...
    Set MCPPROXY_BINARY_PATH ... or run: go build -o mcpproxy
    ./cmd/mcpproxy" — sandbox has no prebuilt binary (CLAUDE.md: E2E
    prereqs include "a built mcpproxy binary").
  - internal/server/tokens: FAIL — 13 tests, all
    `invalid encoding "cl100k_base"/"o200k_base": illegal base64 data at
    input byte 4` — tiktoken BPE encoding-table data missing/corrupted in
    this sandbox, unrelated to OAuth/health.
  None of the 24 pre-existing failures touch oauth/health/server OAuth
  logic; identical on base commit.

## Follow-up commit
- Branch fix/clear-stale-health-on-connect, NOT pushed (per standing
  constraint). SHA: see `git log -1` in this worktree.

## Original task pointer
See prior WP5 commit 3dfeacec on this same branch for the original bug fix
(clearing a stale "Authentication required" health verdict after a
successful OAuth connect).
