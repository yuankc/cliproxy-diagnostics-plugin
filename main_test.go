package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestIsStatusPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/status", want: true},
		{path: "/status/", want: true},
		{path: "/diagnostics/status", want: true},
		{path: "/v0/management/diagnostics/status", want: true},
		{path: "/v0/resource/plugins/diagnostics/status", want: true},
		{path: "/foo/status", want: false},
		{path: "/v0/resource/plugins/other/status", want: false},
		{path: "/dashboard", want: false},
	}
	for _, tc := range cases {
		if got := isStatusPath(tc.path); got != tc.want {
			t.Fatalf("isStatusPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestProbeModeFromRequestDefaultsToDirect(t *testing.T) {
	if got := probeModeFromRequest(pluginapi.ManagementRequest{}); got != probeModeDirect {
		t.Fatalf("probeModeFromRequest() = %q, want %q", got, probeModeDirect)
	}
}

func TestProbeModeFromRequestQuery(t *testing.T) {
	req := pluginapi.ManagementRequest{Query: url.Values{"network": {"host"}}}
	if got := probeModeFromRequest(req); got != probeModeHost {
		t.Fatalf("probeModeFromRequest(query) = %q, want %q", got, probeModeHost)
	}
	req = pluginapi.ManagementRequest{Path: "/status/public-ip?network=local"}
	if got := probeModeFromRequest(req); got != probeModeDirect {
		t.Fatalf("probeModeFromRequest(path query) = %q, want %q", got, probeModeDirect)
	}
}

func TestStatusPathKindSections(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{path: "/status/dns", want: "dns"},
		{path: "/diagnostics/status/openai", want: "openai"},
		{path: "/v0/resource/plugins/diagnostics/status/runtime", want: "runtime"},
		{path: "/v0/management/diagnostics/status/connectivity", want: "connectivity"},
		{path: "/foo/status/dns", want: ""},
	}
	for _, tc := range cases {
		if got := statusPathKind(tc.path); got != tc.want {
			t.Fatalf("statusPathKind(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSanitizeProxyValue(t *testing.T) {
	got := sanitizeProxyValue("http://user:secret@example.com:8080")
	if strings.Contains(got, "user") || strings.Contains(got, "secret") || !strings.Contains(got, "example.com:8080") {
		t.Fatalf("proxy credentials were not masked: %q", got)
	}
	if got := sanitizeProxyValue("socks5://example.com:1080"); got != "socks5://example.com:1080" {
		t.Fatalf("unexpected proxy without credentials: %q", got)
	}
}
func TestParseIPResponse(t *testing.T) {
	ip, ipType, country, region, city, org := parseIPResponse([]byte(`{"ip":"203.0.113.8","country":"US","region":"CA","city":"San Francisco","org":"Example ISP","asn":{"type":"isp"}}`))
	if ip != "203.0.113.8" || ipType != "residential" || country != "US" || region != "CA" || city != "San Francisco" || org != "Example ISP" {
		t.Fatalf("unexpected parsed response: ip=%q type=%q country=%q region=%q city=%q org=%q", ip, ipType, country, region, city, org)
	}

	ip, ipType, country, region, city, org = parseIPResponse([]byte(`"198.51.100.4"`))
	if ip != "198.51.100.4" || ipType != "" || country != "" || region != "" || city != "" || org != "" {
		t.Fatalf("unexpected plain IP parse: ip=%q type=%q country=%q region=%q city=%q org=%q", ip, ipType, country, region, city, org)
	}
}

func TestParseCFTrace(t *testing.T) {
	fields := parseCFTrace("ip=203.0.113.9\nloc=US\nwarp=off\n")
	if fields["ip"] != "203.0.113.9" || fields["loc"] != "US" || fields["warp"] != "off" {
		t.Fatalf("unexpected trace fields: %#v", fields)
	}
}

func TestDistinctIPsByFamily(t *testing.T) {
	v4, v6 := distinctIPsByFamily([]publicIPEndpoint{
		{IP: "203.0.113.1"},
		{IP: "203.0.113.1"},
		{IP: "203.0.113.2"},
		{IP: "2001:db8::1"},
		{IP: "2001:db8::1"},
		{IP: "2001:db8::2"},
		{IP: "not-an-ip"},
	})
	if strings.Join(v4, ",") != "203.0.113.1,203.0.113.2" {
		t.Fatalf("unexpected IPv4 list: %#v", v4)
	}
	if strings.Join(v6, ",") != "2001:db8::1,2001:db8::2" {
		t.Fatalf("unexpected IPv6 list: %#v", v6)
	}
}

func TestIPRiskHTTPError(t *testing.T) {
	got := ipRiskHTTPError("ip-api.com", http.StatusTooManyRequests)
	if !strings.Contains(got, "45 次/分钟") {
		t.Fatalf("expected rate-limit message, got %q", got)
	}
	if got := ipRiskHTTPError("ipapi.is", http.StatusInternalServerError); got != "HTTP 500" {
		t.Fatalf("unexpected generic HTTP error: %q", got)
	}
}

func TestCompactErrorTruncatesRunesSafely(t *testing.T) {
	got := compactError(errors.New(strings.Repeat("连接失败", 200)))
	if !utf8.ValidString(got) {
		t.Fatalf("compactError returned invalid UTF-8")
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected truncated suffix, got %q", got)
	}
	trimmed := strings.TrimSuffix(got, "...")
	if len([]rune(trimmed)) != 500 {
		t.Fatalf("unexpected rune length: %d", len([]rune(trimmed)))
	}
}
