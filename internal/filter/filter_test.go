package filter

import "testing"

func TestDecide(t *testing.T) {
	f := New([]string{"XSRF-TOKEN"}, []string{"JSESSIONID", "sessionid"})
	cases := []struct {
		name string
		want Decision
	}{
		{"JSESSIONID", Store},
		{"sessionid", Store},
		{"XSRF-TOKEN", Forward},
		{"random_ad_cookie", Drop}, // unlisted → dropped
	}
	for _, c := range cases {
		if got := f.Decide(c.name); got != c.want {
			t.Errorf("Decide(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStoreWinsOverForward(t *testing.T) {
	// A name in both lists must be stored (never leaked to the client).
	f := New([]string{"dup"}, []string{"dup"})
	if got := f.Decide("dup"); got != Store {
		t.Errorf("Decide(dup) = %v, want Store", got)
	}
}
