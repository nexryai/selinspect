package selinux

import "testing"

func TestContexts(t *testing.T) {
	for _, raw := range []string{"system_u:system_r:alpha_t:s0", "u:r:t:s0-s0:c0.c1023\n", "u:object_r:t:s0:c1,c2\x00"} {
		c, e := ParseContext(raw)
		if e != nil || c.Type == "" {
			t.Fatalf("%q: %+v %v", raw, c, e)
		}
	}
	c, _ := ParseContext("u:r:t:s0-s0:c0.c1023")
	if c.Range != "s0-s0:c0.c1023" {
		t.Fatal(c)
	}
	for _, raw := range []string{"", "u:r:t", "::t:s0", "u:r:t:", "u:r:t:s0\nbad"} {
		if _, e := ParseContext(raw); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
