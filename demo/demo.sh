#!/usr/bin/env bash
# Walkthrough of the gosestor demo. Start the stack first:
#   docker compose up --build
# then run this script (proxy is on http://localhost:8080 by default).
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

hr() { printf '%s\n' "------------------------------------------------------------"; }

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
echo
echo "Done."
