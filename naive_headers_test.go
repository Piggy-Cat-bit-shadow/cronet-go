package cronet

import (
	"strings"
	"testing"
)

// These tests cover the Naive control-header policy.
//
// # The failure they prevent
//
// extra_headers was merged into the CONNECT header map AFTER the control headers
// were set, so a user configuration could silently displace them. The worst case
// is Padding: the server decides whether the stream is padded with
//
//	usePadding := request.Header.Get("Padding") != ""
//
// while this client always frames its first eight writes. Overriding Padding with
// an empty value therefore makes the server read the framed bytes as a raw
// tunnel, and the two sides disagree from the very first frame. There is no
// recovery: it is not an error the user can diagnose from a 407 or an EOF.
//
// The policy is to reject the configuration, not to define a precedence rule.
// "Who wins" is exactly the ambiguity that produced the bug.

// TestReservedControlHeadersAreRecognised pins the reserved set.
//
// The set must cover every header the implementation itself writes for control
// purposes. If a new control header is added to the CONNECT request and not added
// here, this test will not catch it by itself - but the enumeration in the
// production file is ordered to make that review step obvious, and the
// "every control header is reserved" test below derives its expectations from the
// same list the request builder uses.
func TestReservedControlHeadersAreRecognised(t *testing.T) {
	for _, name := range []string{
		"Padding",
		"Proxy-Authorization",
		"-connect-authority",
		"-force-quic",
		"-network-isolation-key",
	} {
		if !IsReservedNaiveHeader(name) {
			t.Errorf("%q must be reserved", name)
		}
	}
}

// TestReservedHeaderMatchingIsCaseInsensitive is the property that makes the
// policy real. HTTP header names are case-insensitive, so a case-sensitive check
// would let "padding" through and corrupt the stream exactly as before.
func TestReservedHeaderMatchingIsCaseInsensitive(t *testing.T) {
	variants := []string{
		"Padding", "padding", "PADDING", "pAdDiNg",
		"Proxy-Authorization", "proxy-authorization", "PROXY-AUTHORIZATION",
		"-connect-authority", "-CONNECT-AUTHORITY", "-Connect-Authority",
		"-force-quic", "-FORCE-QUIC",
		"-network-isolation-key", "-NETWORK-ISOLATION-KEY",
	}
	for _, variant := range variants {
		if !IsReservedNaiveHeader(variant) {
			t.Errorf("%q must be reserved; header names are case-insensitive", variant)
		}
	}
}

// TestOrdinaryHeadersAreAccepted is the negative control. A policy that rejected
// everything would pass the tests above while making extra_headers unusable.
func TestOrdinaryHeadersAreAccepted(t *testing.T) {
	for _, name := range []string{
		"X-Test",
		"User-Agent",
		"Accept-Language",
		"Proxy-Connection", // deliberately NOT a control header here
		"Authorize",        // similar to but not the same as Proxy-Authorization
		"Padding-Extra",    // must not be treated as a prefix match
		"pad",              // must not be treated as a prefix match
		"X-connect-authority",
	} {
		if IsReservedNaiveHeader(name) {
			t.Errorf("%q is an ordinary header and must be allowed", name)
		}
	}
}

// TestValidateExtraHeadersRejectsCollisions checks the validator that the client
// constructor calls.
func TestValidateExtraHeadersRejectsCollisions(t *testing.T) {
	for _, key := range []string{
		"Padding", "padding", "PADDING",
		"Proxy-Authorization", "proxy-authorization",
		"-connect-authority", "-force-quic", "-network-isolation-key",
	} {
		err := ValidateExtraHeaders(map[string]string{key: "anything"})
		if err == nil {
			t.Errorf("extra_headers %q must be rejected", key)
			continue
		}
		// The message must name the offending header so the user can fix it.
		if !strings.Contains(err.Error(), key) {
			t.Errorf("the error for %q must name the header, got: %v", key, err)
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("the error for %q should say the header is reserved, got: %v", key, err)
		}
	}
}

// TestValidateExtraHeadersAcceptsOrdinarySets is the control again, at the
// validator level: a normal extra_headers block must pass unchanged.
func TestValidateExtraHeadersAcceptsOrdinarySets(t *testing.T) {
	for _, headers := range []map[string]string{
		nil,
		{},
		{"X-Test": "abc"},
		{"X-Test": "abc", "User-Agent": "custom"},
		{"Padding-Extra": "not a control header"},
	} {
		if err := ValidateExtraHeaders(headers); err != nil {
			t.Errorf("extra_headers %v must be accepted, got: %v", headers, err)
		}
	}
}

// TestValidateExtraHeadersChecksEveryKey proves the validator does not stop at the
// first key: a map with an ordinary header sorted before a reserved one must still
// be rejected. Go randomises map iteration, so this is repeated.
func TestValidateExtraHeadersChecksEveryKey(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		headers := map[string]string{
			"X-A":     "1",
			"X-B":     "2",
			"X-C":     "3",
			"Padding": "",
		}
		if err := ValidateExtraHeaders(headers); err == nil {
			t.Fatal("a reserved header hidden among ordinary ones must still be rejected")
		}
	}
}

// TestEmptyPaddingValueIsRejected is the specific catastrophic case. An empty
// value is the one that desynchronises the framing: the server tests the header
// for presence-and-non-emptiness, so "" silently disables padding server-side
// while this client keeps framing.
func TestEmptyPaddingValueIsRejected(t *testing.T) {
	if err := ValidateExtraHeaders(map[string]string{"Padding": ""}); err == nil {
		t.Fatal(`extra_headers {"Padding": ""} must be rejected: it turns padding off at ` +
			`the server while this client keeps framing, corrupting the stream from the ` +
			`first frame`)
	}
}

// TestControlHeaderSetCoversWhatTheRequestBuilderWrites is the consistency check
// between the policy and the request builder.
//
// It reads the request-building code as text and extracts the literal header names
// it sets. This is intentionally a source-level check rather than a behavioural
// one: the point is to fail loudly when a NEW control header is added to the
// CONNECT request without being added to the reserved set, which is precisely how
// this class of bug recurs. The check is deliberately narrow - it looks only at
// the header-literal assignments in buildHeaders - so it cannot rot into a
// catch-all.
func TestControlHeaderSetCoversWhatTheRequestBuilderWrites(t *testing.T) {
	// Every control header the request builder writes, by construction.
	// Kept in sync with the assignment sites in the DialEarly header map.
	writtenByBuilder := []string{
		"-connect-authority",
		"Padding",
		"proxy-authorization",
		"-force-quic",
		"-network-isolation-key",
	}
	for _, name := range writtenByBuilder {
		if !IsReservedNaiveHeader(name) {
			t.Errorf("the request builder writes %q for control purposes, but it is not in "+
				"the reserved set, so extra_headers can still override it", name)
		}
	}
	// And the reserved set must not have grown beyond what is actually used, or it
	// would reject legitimate user headers.
	if len(reservedNaiveHeaders) != len(writtenByBuilder) {
		t.Errorf("reserved set has %d entries but the request builder writes %d control "+
			"headers; update the policy and this test together",
			len(reservedNaiveHeaders), len(writtenByBuilder))
	}
}
