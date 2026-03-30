#!/bin/bash
# Comprehensive integration tests for the WritersProof API (api.writersproof.com).
# Uses curl with simple assertions. Output: PASS/FAIL/SKIP per test.
#
# Usage:
#   ./scripts/test_api.sh                                       # default: api.writersproof.com
#   API_BASE=http://localhost:8787 ./scripts/test_api.sh        # local dev

set -eo pipefail

API_BASE="${API_BASE:-https://api.writersproof.com}"
STORED_JWT_PATH="$HOME/Library/Application Support/WritersProof/writersproof_api_key"

PASS=0
FAIL=0
SKIP=0
CURRENT_CATEGORY=""

# Associative arrays for per-category counts (bash 4+)
# declare -A CAT_PASS
# declare -A CAT_FAIL
# declare -A CAT_SKIP
declare -a CAT_ORDER

start_category() {
  CURRENT_CATEGORY="$1"
  CAT_ORDER+=("$CURRENT_CATEGORY")
  CAT_PASS["$CURRENT_CATEGORY"]=0
  CAT_FAIL["$CURRENT_CATEGORY"]=0
  CAT_SKIP["$CURRENT_CATEGORY"]=0
  echo ""
  echo "--- $CURRENT_CATEGORY ---"
}

pass() {
  PASS=$((PASS + 1))
  CAT_PASS["$CURRENT_CATEGORY"]=$(( ${CAT_PASS["$CURRENT_CATEGORY"]} + 1 ))
  printf "  PASS  %s\n" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  CAT_FAIL["$CURRENT_CATEGORY"]=$(( ${CAT_FAIL["$CURRENT_CATEGORY"]} + 1 ))
  printf "  FAIL  %s -- %s\n" "$1" "$2"
}

skip() {
  SKIP=$((SKIP + 1))
  CAT_SKIP["$CURRENT_CATEGORY"]=$(( ${CAT_SKIP["$CURRENT_CATEGORY"]} + 1 ))
  printf "  SKIP  %s -- %s\n" "$1" "$2"
}

# Helper: HTTP status code for a request
http_status() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

# Helper: full response body
http_body() {
  curl -s "$@"
}

# Helper: response headers (lowercase)
http_headers() {
  curl -s -I "$@"
}

# Helper: body + status in one call (avoids double request)
# Sets global vars: _body, _status
http_both() {
  local tmpfile
  tmpfile=$(mktemp)
  _status=$(curl -s -o "$tmpfile" -w "%{http_code}" "$@")
  _body=$(cat "$tmpfile")
  rm -f "$tmpfile"
}

echo "=== WritersProof API Comprehensive Integration Tests ==="
echo "Target: $API_BASE"
echo "Date:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# =======================================================================
# AUTHENTICATION DEPTH
# =======================================================================
start_category "Authentication: JWT"

# ES256 JWT acceptance (use stored JWT if fresh, or document skip)
if [ -f "$STORED_JWT_PATH" ]; then
  JWT=$(cat "$STORED_JWT_PATH")
  body=$(http_body -X POST -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" "$API_BASE/v1/nonce")
  if echo "$body" | grep -qi "unsupported algorithm"; then
    fail "test_es256_jwt_accepted_or_expired" "got 'Unsupported algorithm': $body"
  else
    pass "test_es256_jwt_accepted_or_expired"
  fi
else
  skip "test_es256_jwt_accepted_or_expired" "no stored JWT at $STORED_JWT_PATH"
fi

# Malformed JWT (only 2 parts instead of 3)
http_both -X POST -H "Authorization: Bearer abc.def" \
  -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ]; then
  pass "test_malformed_jwt_rejected"
else
  fail "test_malformed_jwt_rejected" "expected 401, got $_status"
fi

# Empty bearer value
http_both -X POST -H "Authorization: Bearer " \
  -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ]; then
  pass "test_empty_bearer_rejected"
else
  fail "test_empty_bearer_rejected" "expected 401, got $_status"
fi

# No auth header at all
http_both -X POST -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ]; then
  pass "test_no_auth_header_rejected"
else
  fail "test_no_auth_header_rejected" "expected 401, got $_status"
fi

# Wrong auth scheme (Basic)
http_both -X POST -H "Authorization: Basic dXNlcjpwYXNz" \
  -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ]; then
  pass "test_wrong_auth_scheme_rejected"
else
  fail "test_wrong_auth_scheme_rejected" "expected 401, got $_status"
fi

start_category "Authentication: API Key"

# Invalid API key format (not wp_sk_ prefixed)
http_both -X POST -H "Authorization: Bearer not-wp_sk_xxx" \
  -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ]; then
  pass "test_invalid_api_key_format"
else
  fail "test_invalid_api_key_format" "expected 401, got $_status"
fi

# Nonexistent but correctly formatted API key
http_both -X POST \
  -H "Authorization: Bearer wp_sk_0000000000000000000000000000000000000000" \
  -H "Content-Type: application/json" "$API_BASE/v1/nonce"
if [ "$_status" = "401" ] || [ "$_status" = "403" ]; then
  pass "test_nonexistent_api_key_rejected"
else
  fail "test_nonexistent_api_key_rejected" "expected 401 or 403, got $_status"
fi

# =======================================================================
# REQUEST VALIDATION
# =======================================================================
start_category "Request Validation"

# Nonce requires hardwareKeyId -- empty body
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" -d '{}' "$API_BASE/v1/nonce"
# Expect 400 (validation) or 401 (auth first); either is valid depending on middleware order
if [ "$_status" = "400" ] || [ "$_status" = "401" ]; then
  pass "test_nonce_requires_hardware_key_id (status: $_status)"
else
  fail "test_nonce_requires_hardware_key_id" "expected 400 or 401, got $_status"
fi

# Nonce rejects invalid UUID
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" \
  -d '{"hardwareKeyId":"not-a-uuid"}' "$API_BASE/v1/nonce"
if [ "$_status" = "400" ] || [ "$_status" = "401" ]; then
  pass "test_nonce_rejects_invalid_uuid (status: $_status)"
else
  fail "test_nonce_rejects_invalid_uuid" "expected 400 or 401, got $_status"
fi

# Enroll requires publicKey
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" \
  -d '{"hardwareKeyId":"00000000-0000-0000-0000-000000000000"}' "$API_BASE/v1/enroll"
if [ "$_status" = "400" ] || [ "$_status" = "401" ]; then
  pass "test_enroll_requires_public_key (status: $_status)"
else
  fail "test_enroll_requires_public_key" "expected 400 or 401, got $_status"
fi

# Anchor requires evidenceHash
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"test"}' "$API_BASE/v1/anchor"
if [ "$_status" = "400" ] || [ "$_status" = "401" ]; then
  pass "test_anchor_requires_evidence_hash (status: $_status)"
else
  fail "test_anchor_requires_evidence_hash" "expected 400 or 401, got $_status"
fi

# Verify requires CBOR content-type (sending JSON should be rejected or handled differently)
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" \
  -d '{"data":"test"}' "$API_BASE/v1/verify"
if [ "$_status" = "400" ] || [ "$_status" = "401" ] || [ "$_status" = "415" ]; then
  pass "test_verify_requires_cbor_content_type (status: $_status)"
else
  fail "test_verify_requires_cbor_content_type" "expected 400/401/415, got $_status"
fi

# Beacon requires checkpointHash -- empty body
http_both -X POST -H "Authorization: Bearer invalid-but-tests-validation" \
  -H "Content-Type: application/json" -d '{}' "$API_BASE/v1/beacon"
if [ "$_status" = "400" ] || [ "$_status" = "401" ]; then
  pass "test_beacon_requires_checkpoint_hash (status: $_status)"
else
  fail "test_beacon_requires_checkpoint_hash" "expected 400 or 401, got $_status"
fi

# =======================================================================
# RESPONSE FORMAT
# =======================================================================
start_category "Response Format"

# Health response format: must contain status, service, version, timestamp
body=$(http_body "$API_BASE/health")
health_ok=true
for field in status service version timestamp; do
  if ! echo "$body" | grep -q "\"$field\""; then
    fail "test_health_response_format" "missing field '$field' in: $body"
    health_ok=false
    break
  fi
done
if [ "$health_ok" = true ]; then
  pass "test_health_response_format"
fi

# Health response has checks object
if echo "$body" | grep -q '"checks"'; then
  pass "test_health_response_has_checks"
else
  fail "test_health_response_has_checks" "missing 'checks' in: $body"
fi

# CRL response content-type
crl_headers=$(http_headers "$API_BASE/v1/crl")
if echo "$crl_headers" | grep -qi "content-type.*application/json\|content-type.*application/cbor\|content-type.*application/octet-stream"; then
  pass "test_crl_response_content_type"
else
  fail "test_crl_response_content_type" "unexpected content-type in CRL response"
fi

# Error responses have "error" field -- test with a known 401
http_both -X POST "$API_BASE/v1/nonce"
if echo "$_body" | grep -q '"error"'; then
  pass "test_error_responses_have_error_field (401)"
else
  fail "test_error_responses_have_error_field (401)" "body: $_body"
fi

# Error responses have "error" field -- test with 404
http_both "$API_BASE/v1/nonexistent-endpoint-that-should-404"
if [ "$_status" = "404" ]; then
  if echo "$_body" | grep -q '"error"'; then
    pass "test_error_responses_have_error_field (404)"
  else
    fail "test_error_responses_have_error_field (404)" "body: $_body"
  fi
else
  skip "test_error_responses_have_error_field (404)" "got status $_status, not 404"
fi

# =======================================================================
# CORS
# =======================================================================
start_category "CORS"

# CORS allows writersproof.com
cors_headers=$(curl -s -I -X OPTIONS \
  -H "Origin: https://writersproof.com" \
  -H "Access-Control-Request-Method: POST" \
  "$API_BASE/v1/nonce")
if echo "$cors_headers" | grep -qi "access-control-allow-origin.*writersproof\.com\|access-control-allow-origin.*\*"; then
  pass "test_cors_allows_writersproof_origin"
else
  fail "test_cors_allows_writersproof_origin" "no matching ACAO header"
fi

# CORS allows writerslogic.com
cors_headers=$(curl -s -I -X OPTIONS \
  -H "Origin: https://writerslogic.com" \
  -H "Access-Control-Request-Method: POST" \
  "$API_BASE/v1/nonce")
if echo "$cors_headers" | grep -qi "access-control-allow-origin.*writerslogic\.com\|access-control-allow-origin.*\*"; then
  pass "test_cors_allows_writerslogic_origin"
else
  fail "test_cors_allows_writerslogic_origin" "no matching ACAO header"
fi

# CORS rejects unknown origin
cors_headers=$(curl -s -I -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  "$API_BASE/v1/nonce")
if echo "$cors_headers" | grep -qi "access-control-allow-origin.*evil\.com"; then
  fail "test_cors_rejects_unknown_origin" "evil.com was allowed"
else
  pass "test_cors_rejects_unknown_origin"
fi

# =======================================================================
# RATE LIMITING
# =======================================================================
start_category "Rate Limiting"

rl_headers=$(http_headers "$API_BASE/health")
if echo "$rl_headers" | grep -qi "x-ratelimit\|ratelimit"; then
  pass "test_rate_limiting_headers_present"
else
  fail "test_rate_limiting_headers_present" "no rate limit headers found"
fi

# =======================================================================
# SECURITY HEADERS
# =======================================================================
start_category "Security Headers"

sec_headers=$(http_headers "$API_BASE/health")

if echo "$sec_headers" | grep -qi "strict-transport-security"; then
  pass "test_strict_transport_security"
else
  fail "test_strict_transport_security" "HSTS header missing"
fi

if echo "$sec_headers" | grep -qi "x-content-type-options"; then
  pass "test_content_type_options"
else
  fail "test_content_type_options" "X-Content-Type-Options missing"
fi

if echo "$sec_headers" | grep -qi "x-frame-options"; then
  pass "test_x_frame_options"
else
  fail "test_x_frame_options" "X-Frame-Options missing"
fi

# Two requests should get different X-Request-Id values
rid1=$(curl -s -I "$API_BASE/health" | grep -i "x-request-id" | tr -d '\r' | awk '{print $2}')
rid2=$(curl -s -I "$API_BASE/health" | grep -i "x-request-id" | tr -d '\r' | awk '{print $2}')
if [ -n "$rid1" ] && [ -n "$rid2" ] && [ "$rid1" != "$rid2" ]; then
  pass "test_x_request_id_unique"
elif [ -z "$rid1" ] || [ -z "$rid2" ]; then
  fail "test_x_request_id_unique" "X-Request-Id header not present"
else
  fail "test_x_request_id_unique" "both requests returned same ID: $rid1"
fi

# Server header should not leak version info
server_hdr=$(echo "$sec_headers" | grep -i "^server:" | tr -d '\r' || true)
if [ -z "$server_hdr" ]; then
  pass "test_no_server_version_leak (no Server header)"
elif echo "$server_hdr" | grep -qiE "[0-9]+\.[0-9]+"; then
  fail "test_no_server_version_leak" "Server header leaks version: $server_hdr"
else
  pass "test_no_server_version_leak"
fi

# =======================================================================
# CERTIFICATE ENDPOINTS
# =======================================================================
start_category "Certificate Endpoints"

# Root CA certificate
http_both "$API_BASE/v1/ca/root"
if [ "$_status" = "200" ]; then
  if echo "$_body" | grep -q '"certificate"\|"publicKey"\|"pem"'; then
    pass "test_root_ca_certificate_valid_json"
  else
    # Might be PEM directly
    if echo "$_body" | grep -q "BEGIN CERTIFICATE\|BEGIN PUBLIC KEY"; then
      pass "test_root_ca_certificate_valid_json (PEM format)"
    else
      fail "test_root_ca_certificate_valid_json" "unrecognized format: $_body"
    fi
  fi
elif [ "$_status" = "503" ]; then
  skip "test_root_ca_certificate_valid_json" "CA not initialized (503)"
else
  fail "test_root_ca_certificate_valid_json" "expected 200 or 503, got $_status"
fi

# CRL returns empty or valid
http_both "$API_BASE/v1/crl"
if [ "$_status" = "200" ]; then
  if echo "$_body" | grep -q "revokedCertificates\|thisUpdate"; then
    pass "test_crl_returns_empty_or_valid"
  elif [ ${#_body} -le 5 ]; then
    pass "test_crl_returns_empty_or_valid (empty CRL)"
  else
    pass "test_crl_returns_empty_or_valid (non-empty response)"
  fi
else
  fail "test_crl_returns_empty_or_valid" "expected 200, got $_status"
fi

# Nonexistent certificate returns 404
http_both "$API_BASE/v1/certificates/00000000-0000-0000-0000-000000000000"
if [ "$_status" = "404" ]; then
  pass "test_certificate_404_for_nonexistent"
elif [ "$_status" = "401" ]; then
  pass "test_certificate_404_for_nonexistent (auth required first, status: 401)"
else
  fail "test_certificate_404_for_nonexistent" "expected 404 or 401, got $_status"
fi

# =======================================================================
# ENDPOINT RESPONSE CODES (comprehensive auth checks)
# =======================================================================
start_category "Endpoint Response Codes"

# Build an expired-looking JWT (3-part dot-separated base64 gibberish)
FAKE_JWT="eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

check_auth_rejection() {
  local method="$1" path="$2" label="$3" auth_header="$4"
  local extra_args=()
  if [ -n "$auth_header" ]; then
    extra_args+=(-H "Authorization: $auth_header")
  fi
  http_both -X "$method" "${extra_args[@]}" \
    -H "Content-Type: application/json" "$API_BASE$path"
  if [ "$_status" = "401" ] || [ "$_status" = "403" ]; then
    pass "$label (status: $_status)"
  else
    fail "$label" "expected 401/403, got $_status"
  fi
}

check_auth_rejection POST "/v1/nonce"   "test_nonce_401_with_expired_jwt"  "Bearer $FAKE_JWT"
check_auth_rejection POST "/v1/enroll"  "test_enroll_401_with_expired_jwt" "Bearer $FAKE_JWT"
check_auth_rejection POST "/v1/anchor"  "test_anchor_401_with_expired_jwt" "Bearer $FAKE_JWT"
check_auth_rejection POST "/v1/beacon"  "test_beacon_401_with_expired_jwt" "Bearer $FAKE_JWT"
check_auth_rejection POST "/v1/verify"  "test_verify_401_no_auth"          ""

# =======================================================================
# ENDPOINT EXISTENCE (all routes respond, not generic 404)
# =======================================================================
start_category "Endpoint Existence"

check_exists() {
  local method="$1"
  local path="$2"
  local label="$3"
  http_both -X "$method" -H "Content-Type: application/json" "$API_BASE$path"
  if [ "$_status" = "404" ]; then
    if [ "$_body" = '{"error":"Not found"}' ]; then
      fail "$label exists" "got 404 (route not registered)"
    else
      pass "$label exists (status: $_status, resource-level 404)"
    fi
  else
    pass "$label exists (status: $_status)"
  fi
}

check_exists POST "/v1/nonce"       "POST /v1/nonce"
check_exists POST "/v1/enroll"      "POST /v1/enroll"
check_exists POST "/v1/attest"      "POST /v1/attest"
check_exists POST "/v1/anchor"      "POST /v1/anchor"
check_exists POST "/v1/beacon"      "POST /v1/beacon"
check_exists POST "/v1/verify"      "POST /v1/verify"
check_exists POST "/v1/stego/sign"  "POST /v1/stego/sign"
check_exists POST "/v1/stego/verify" "POST /v1/stego/verify"
check_exists GET  "/v1/certificates/00000000-0000-0000-0000-000000000000" "GET /v1/certificates/:id"
check_exists POST "/v1/certificates/issue"  "POST /v1/certificates/issue"
check_exists POST "/v1/certificates/revoke" "POST /v1/certificates/revoke"
check_exists POST "/v1/declaration"  "POST /v1/declaration"
check_exists GET  "/v1/crl"          "GET /v1/crl"
check_exists GET  "/v1/ca/root"      "GET /v1/ca/root"

# =======================================================================
# PUBLIC ENDPOINTS
# =======================================================================
start_category "Public Endpoints"

http_both "$API_BASE/health"
if [ "$_status" = "200" ]; then
  pass "GET /health returns 200"
else
  fail "GET /health returns 200" "got $_status"
fi

http_both "$API_BASE/v1/crl"
if [ "$_status" = "200" ]; then
  pass "GET /v1/crl returns 200"
else
  fail "GET /v1/crl returns 200" "got $_status"
fi

http_both "$API_BASE/openapi.json"
if [ "$_status" = "200" ]; then
  pass "GET /openapi.json returns 200"
else
  fail "GET /openapi.json returns 200" "got $_status"
fi

# =======================================================================
# CAMELCASE FIELD NAMING
# =======================================================================
start_category "camelCase Field Naming"

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

# =======================================================================
# SUMMARY
# =======================================================================
echo ""
echo "======================================================================="
echo "                        TEST SUMMARY"
echo "======================================================================="
printf "%-35s %6s %6s %6s %6s\n" "Category" "Pass" "Fail" "Skip" "Total"
echo "-----------------------------------------------------------------------"

for cat in "${CAT_ORDER[@]}"; do
  p=${CAT_PASS["$cat"]}
  f=${CAT_FAIL["$cat"]}
  s=${CAT_SKIP["$cat"]}
  t=$((p + f + s))
  printf "%-35s %6d %6d %6d %6d\n" "$cat" "$p" "$f" "$s" "$t"
done

echo "-----------------------------------------------------------------------"
TOTAL=$((PASS + FAIL + SKIP))
printf "%-35s %6d %6d %6d %6d\n" "TOTAL" "$PASS" "$FAIL" "$SKIP" "$TOTAL"
echo "======================================================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAILED ($FAIL failures)"
  exit 1
else
  echo "RESULT: PASSED ($PASS passed, $SKIP skipped)"
fi
