// Command backend is a tiny stub origin server for the gosestor demo. It sets
// the cookies and identity header that the session_store handler is meant to
// intercept, so the demo can show what does (and does not) reach the client and
// what the backend actually receives on subsequent requests.
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	// Root echoes the Cookie header the backend received. After login this
	// should contain JSESSIONID even though the client never stored it — proof
	// that gosestor re-injects the cached cookie upstream.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "backend received Cookie header: %q\n", r.Header.Get("Cookie"))
		if hasCookie(r, "JSESSIONID") {
			fmt.Fprintln(w, "-> JSESSIONID PRESENT: the cached session cookie was re-injected by gosestor.")
		} else {
			fmt.Fprintln(w, "-> JSESSIONID ABSENT: anonymous request (log in via /login first).")
		}
	})

	// Login sets a session cookie (stored server-side), an identity header
	// (binds the owner, then stripped), and grants the `default` label — one
	// response exercising owner binding + label grant with a single key swap.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "secret-sess-abc123", Path: "/"})
		w.Header().Set("X-Auth-User", "42")
		w.Header().Set("X-Session-Labels", "default")
		fmt.Fprintln(w, "backend set JSESSIONID (stored), X-Auth-User (owner-bound), and granted label: default.")
	})

	// Current-session logout expires the backend cookie and asks gosestor to
	// delete the complete proxy session. Both control values are consumed by
	// the proxy and never reach the client.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "", Path: "/", MaxAge: -1})
		w.Header().Set("X-Session-Revoke", "1")
		fmt.Fprintln(w, "backend requested current-session logout.")
	})

	// CSRF sets a forward-listed cookie: it should reach the client unchanged.
	mux.HandleFunc("/csrf", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: "t0ken", Path: "/"})
		fmt.Fprintln(w, "backend set XSRF-TOKEN — forwarded to the client.")
	})

	// Tracker sets an unlisted cookie: deny-by-default should drop it entirely.
	mux.HandleFunc("/tracker", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "adtrack", Value: "noisy", Path: "/"})
		fmt.Fprintln(w, "backend set adtrack — should be dropped (deny-by-default).")
	})

	// Account requires the `default` label at the proxy; reaching this handler
	// proves the label was granted and accepted.
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "account area — default label was accepted by the proxy.")
	})

	// Admin requires the `adm` label at the proxy.
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "admin area — adm label was accepted by the proxy.")
	})

	// MFA step-up: grants adm. Labels REPLACE the whole set, so `default`
	// must be restated alongside the new privilege.
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Labels", "default adm")
		fmt.Fprintln(w, "backend granted labels: default adm (step-up).")
	})

	// Step-down: back to default only — adm is revoked by the same REPLACE
	// mechanism that granted it.
	mux.HandleFunc("/stepdown", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Labels", "default")
		fmt.Fprintln(w, "backend granted labels: default (adm revoked).")
	})

	log.Println("demo backend listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func hasCookie(r *http.Request, name string) bool {
	c, err := r.Cookie(name)
	return err == nil && c.Value != ""
}
