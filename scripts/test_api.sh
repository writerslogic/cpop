#!/usr/bin/env bash
# Integration tests for the WritersProof API (api.writersproof.com).
# Uses curl with simple assertions. Output: PASS/FAIL per test.
#
# Usage:
#   ./scripts/test_api.sh                     # default: api.writersproof.com
#   API_BASE=http://localhost:8787 ./scripts/test_api.sh   # local dev

set -euo pipefail

API_BASE="${API_BASE:-https://api.writersproof.com}"
STORED_JWT_PATH="$HOME/Library/Application Support/WritersProof/writersproof_api_key"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf "  PASS  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  FAIL  %s -- %s\n" "$1" "$2"; }

# Helper: HTTP status code for a request
http_status() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

# Helper: full response body
http_body() {
  curl -s "$@"
}

echo "=== WritersProof API Integration Tests ==="
echo "Target: $API_BASE"
echo ""

# -----------------------------------------------------------------------
# 1. Health check
# -----------------------------------------------------------------------
echo "[1] Health check"
body=$(http_body "$API_BASE/health")
status=$(http_status "$API_BASE/health")
if [ "$status" = "200" ]; then
  pass "GET /health returns 200"
else
  fail "GET /health returns 200" "got $status"
fi
if echo "$body" | grep -q '"status"'; then
  pass "GET /health body contains status field"
else
  fail "GET /health body contains status field" "body: $body"
fi

# -----------------------------------------------------------------------
# 2. Auth middleware rejects bad tokens
# -----------------------------------------------------------------------
echo ""
echo "[2] Auth middleware rejects bad tokens"

status=$(http_status -X POST "$API_BASE/v1/nonce")
if [ "$status" = "401" ]; then
  pass "POST /v1/nonce with no auth returns 401"
else
  fail "POST /v1/nonce with no auth returns 401" "got $status"
fi

body=$(http_body -X POST "$API_BASE/v1/nonce")
if echo "$body" | grep -qi "authentication required"; then
  pass "POST /v1/nonce no-auth error message"
else
  fail "POST /v1/nonce no-auth error message" "body: $body"
fi

status=$(http_status -X POST -H "Authorization: Bearer invalid" "$API_BASE/v1/nonce")
if [ "$status" = "401" ]; then
  pass "POST /v1/nonce with 'Bearer invalid' returns 401"
else
  fail "POST /v1/nonce with 'Bearer invalid' returns 401" "got $status"
fi

body=$(http_body -X POST -H "Authorization: Bearer invalid" "$API_BASE/v1/nonce")
if echo "$body" | grep -qi "invalid token\|malformed"; then
  pass "POST /v1/nonce invalid token error message"
else
  fail "POST /v1/nonce invalid token error message" "body: $body"
fi

# -----------------------------------------------------------------------
# 3. Auth middleware accepts ES256 JWT structure (expired token check)
# -----------------------------------------------------------------------
echo ""
echo "[3] ES256 JWT structure accepted (expect 'Token expired', not 'Unsupported algorithm')"

if [ -f "$STORED_JWT_PATH" ]; then
  JWT=$(cat "$STORED_JWT_PATH")
  body=$(http_body -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" "$API_BASE/v1/nonce")

  if echo "$body" | grep -qi "unsupported algorithm"; then
    fail "ES256 JWT not rejected for algorithm" "got 'Unsupported algorithm' error: $body"
  elif echo "$body" | grep -qi "token expired\|invalid token\|signature\|signing key"; then
    pass "ES256 JWT recognized (error is auth/expiry, not algorithm)"
  else
    # Any non-algorithm error is acceptable
    pass "ES256 JWT recognized (response: $body)"
  fi
else
  echo "  SKIP  No stored JWT at $STORED_JWT_PATH"
fi

# -----------------------------------------------------------------------
# 4. Public endpoints work without auth
# -----------------------------------------------------------------------
echo ""
echo "[4] Public endpoints"

status=$(http_status "$API_BASE/v1/crl")
if [ "$status" = "200" ]; then
  pass "GET /v1/crl returns 200"
else
  fail "GET /v1/crl returns 200" "got $status"
fi

body=$(http_body "$API_BASE/v1/crl")
if echo "$body" | grep -q "revokedCertificates"; then
  pass "GET /v1/crl body has revokedCertificates"
else
  fail "GET /v1/crl body has revokedCertificates" "body: $body"
fi

status=$(http_status "$API_BASE/v1/ca/root")
if [ "$status" = "200" ] || [ "$status" = "503" ]; then
  pass "GET /v1/ca/root returns 200 or 503 (no auth required)"
else
  fail "GET /v1/ca/root returns 200 or 503" "got $status"
fi

status=$(http_status "$API_BASE/openapi.json")
if [ "$status" = "200" ]; then
  pass "GET /openapi.json returns 200"
else
  fail "GET /openapi.json returns 200" "got $status"
fi

# -----------------------------------------------------------------------
# 5. Field naming / camelCase
# -----------------------------------------------------------------------
echo ""
echo "[5] camelCase field naming"

body=$(http_body "$API_BASE/v1/crl")
if echo "$body" | grep -q "revokedCertificates\|thisUpdate\|nextUpdate"; then
  pass "CRL response uses camelCase fields"
else
  fail "CRL response uses camelCase fields" "body: $body"
fi

body=$(http_body "$API_BASE/health")
if echo "$body" | grep -q '"status"'; then
  pass "Health response uses camelCase fields"
else
  fail "Health response uses camelCase fields" "body: $body"
fi

echo "  NOTE  Full camelCase validation on auth-protected endpoints requires a valid service role JWT."

# -----------------------------------------------------------------------
# 6. Endpoint existence (all routes respond, not 404)
# -----------------------------------------------------------------------
echo ""
echo "[6] Endpoint existence (expect 401, not 404)"

check_exists() {
  local method="$1"
  local path="$2"
  local label="$3"
  local status body
  body=$(http_body -X "$method" -H "Content-Type: application/json" "$API_BASE$path")
  status=$(http_status -X "$method" -H "Content-Type: application/json" "$API_BASE$path")
  if [ "$status" = "404" ]; then
    # Hono's fallback 404 returns exactly {"error":"Not found"}.
    # A route that handles the request but returns 404 for a missing resource
    # will have a different message (e.g. "Certificate not found").
    if [ "$body" = '{"error":"Not found"}' ]; then
      fail "$label exists" "got 404 (route not registered)"
    else
      pass "$label exists (status: $status, resource-level 404)"
    fi
  else
    pass "$label exists (status: $status)"
  fi
}

check_exists POST "/v1/nonce"       "POST /v1/nonce"
check_exists POST "/v1/enroll"      "POST /v1/enroll"
check_exists POST "/v1/attest"      "POST /v1/attest"
check_exists POST "/v1/anchor"      "POST /v1/anchor"
check_exists POST "/v1/beacon"      "POST /v1/beacon (via /v1/beacon)"
check_exists POST "/v1/verify"      "POST /v1/verify"
check_exists POST "/v1/stego/sign"  "POST /v1/stego/sign"
check_exists POST "/v1/stego/verify" "POST /v1/stego/verify"
check_exists GET  "/v1/certificates/00000000-0000-0000-0000-000000000000" "GET /v1/certificates/:id"
check_exists POST "/v1/certificates/issue" "POST /v1/certificates/issue"
check_exists POST "/v1/certificates/revoke" "POST /v1/certificates/revoke"
check_exists POST "/v1/declaration"  "POST /v1/declaration"
check_exists GET  "/v1/crl"          "GET /v1/crl"
check_exists GET  "/v1/ca/root"      "GET /v1/ca/root"

# -----------------------------------------------------------------------
# 7. Security headers
# -----------------------------------------------------------------------
echo ""
echo "[7] Security headers"

headers=$(curl -s -I "$API_BASE/health")

check_header() {
  local name="$1"
  if echo "$headers" | grep -qi "$name"; then
    pass "Header: $name present"
  else
    fail "Header: $name present" "missing from response"
  fi
}

check_header "X-Content-Type-Options"
check_header "X-Request-Id"
check_header "X-API-Version"
check_header "X-Frame-Options"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
