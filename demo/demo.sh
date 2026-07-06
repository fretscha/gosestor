#!/usr/bin/env bash
# Walkthrough of the gosestor demo. Start the stack first:
#   docker compose up --build
# then run this script (proxy is on http://localhost:8080 by default).
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
ADMIN=${ADMIN:-http://localhost:2019}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

hr() { printf '%s\n' "------------------------------------------------------------"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
# Last __gosestor value in the jar; awk (unlike grep) exits 0 on no match, so
# an empty jar reaches the explicit checks instead of tripping set -e.
proxy_cookie() { awk '/__gosestor/ {v=$7} END{print v}' "$JAR"; }

hr
echo "1) LOGIN — backend sets JSESSIONID (stored) + X-Auth-User (owner-bound)."
echo "   Expect: only __gosestor is Set-Cookie; no JSESSIONID, no X-Auth-User."
hr
curl -si -c "$JAR" "$BASE/login" | grep -iE '^HTTP/|^set-cookie:|^x-auth-user:' || true
echo
echo "Stored proxy cookie:"
grep -i __gosestor "$JAR" | awk '{print "  "$6" = "$7}' || true

hr
echo "2) AUTHENTICATED REQUEST — replay the proxy cookie."
echo "   Expect: backend reports JSESSIONID PRESENT (re-injected server-side)."
hr
curl -s -b "$JAR" "$BASE/"

hr
echo "3) FORWARDED COOKIE — /csrf sets XSRF-TOKEN (forward list)."
echo "   Expect: XSRF-TOKEN appears in Set-Cookie."
hr
curl -si -b "$JAR" "$BASE/csrf" | grep -iE '^set-cookie:' || echo "  (none)"

hr
echo "4) DROPPED COOKIE — /tracker sets adtrack (unlisted)."
echo "   Expect: NO Set-Cookie for adtrack (deny-by-default)."
hr
curl -si -b "$JAR" "$BASE/tracker" | grep -iE '^set-cookie:' || echo "  (none — dropped, as expected)"

hr
echo "5) SPOOF ATTEMPT — a fresh client forges X-Auth-User and JSESSIONID."
echo "   Expect: forged identity is stripped; forged JSESSIONID does NOT reach the"
echo "   backend (backend reports JSESSIONID ABSENT)."
hr
curl -s -H 'X-Auth-User: 999' -H 'Cookie: JSESSIONID=forged-by-client' "$BASE/"

hr
echo "6) KEY ROTATION — rotate_interval is 15s in this demo."
echo "   Expect: after waiting, the next response carries a NEW __gosestor value,"
echo "   the session survives (JSESSIONID PRESENT), and the OLD key is dead."
hr
OLD_KEY=$(proxy_cookie)
[ -n "$OLD_KEY" ] || fail "no proxy cookie in the jar before rotation"
echo "waiting 16s for the rotation interval to elapse..."
sleep 16
BODY=$(curl -s -b "$JAR" -c "$JAR" "$BASE/")
echo "$BODY"
NEW_KEY=$(proxy_cookie)
[ -n "$NEW_KEY" ] || fail "proxy cookie vanished after rotation window"
[ "$NEW_KEY" != "$OLD_KEY" ] || fail "KEY_ID did not rotate after the interval"
echo "$BODY" | grep -q 'JSESSIONID PRESENT' || fail "session lost across rotation"
echo "rotated: ...${OLD_KEY: -8} -> ...${NEW_KEY: -8} (session intact)"
# The pre-rotation key must be hard-dead — replaying it is an anonymous request.
curl -s -H "Cookie: __gosestor=$OLD_KEY" "$BASE/" | grep -q 'JSESSIONID ABSENT' \
    || fail "old KEY_ID still resolves after rotation"
echo "old KEY_ID no longer resolves (hard-deleted), as expected"

hr
echo "7) LOGOUT EVERYWHERE — POST $ADMIN/gosestor/revoke/42 (Caddy admin API,"
echo "   host-loopback only). Expect: 204, then the session is gone."
hr
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ADMIN/gosestor/revoke/42")
[ "$CODE" = "204" ] || fail "revoke returned HTTP $CODE, want 204"
echo "revoke owner 42 -> HTTP $CODE"
curl -s -b "$JAR" "$BASE/" | grep -q 'JSESSIONID ABSENT' \
    || fail "session survived owner revocation"
echo "authenticated session is dead after revoke, as expected"
# Owner ids must be positive integers; 0 (anonymous sentinel) is rejected.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ADMIN/gosestor/revoke/0")
[ "$CODE" = "400" ] || fail "revoke/0 returned HTTP $CODE, want 400"
echo "revoke owner 0 -> HTTP $CODE (rejected, as expected)"

echo
echo "Done — all checks passed."
