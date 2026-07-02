package main

import "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

type registration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  capabilities       `json:"capabilities"`
}

type capabilities struct {
	ManagementAPI bool `json:"management_api"`
}

type diagnostics struct {
	CheckedAt       string             `json:"checked_at"`
	Runtime         runtimeInfo        `json:"runtime"`
	Proxy           proxyInfo          `json:"proxy"`
	Egress          egressComparison   `json:"egress"`
	LocalIPs        []localIP          `json:"local_ips"`
	OutboundSources []outboundSource   `json:"outbound_sources"`
	PublicIP        publicIPResult     `json:"public_ip"`
	IPRisk          ipRiskProfile      `json:"ip_risk"`
	OpenAI          openAIAvailability `json:"openai"`
	Geo             geoConsistency     `json:"geo_consistency"`
	DNS             []dnsResult        `json:"dns"`
	Connectivity    []connectivityTest `json:"connectivity"`
	DurationMS      int64              `json:"duration_ms"`
}

type runtimeInfo struct {
	Hostname     string `json:"hostname"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	PID          int    `json:"pid"`
	TimezoneName string `json:"timezone_name,omitempty"`
	TimezoneUTC  string `json:"timezone_utc,omitempty"`
}

type proxyInfo struct {
	Detected  bool            `json:"detected"`
	Variables []proxyVariable `json:"variables"`
	Note      string          `json:"note"`
}

type proxyVariable struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Set   bool   `json:"set"`
}

type egressComparison struct {
	HostHTTPAvailable bool           `json:"host_http_available"`
	ActivePath        string         `json:"active_path"`
	Direct            publicIPResult `json:"direct"`
	Host              publicIPResult `json:"host"`
	SameIP            bool           `json:"same_ip"`
	Compared          bool           `json:"compared"`
	Signals           []string       `json:"signals"`
	Note              string         `json:"note"`
}

type localIP struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Version   string `json:"version"`
	Private   bool   `json:"private"`
	Loopback  bool   `json:"loopback"`
}

type outboundSource struct {
	Target  string `json:"target"`
	LocalIP string `json:"local_ip,omitempty"`
	Latency int64  `json:"latency_ms,omitempty"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

type publicIPResult struct {
	IP        string             `json:"ip,omitempty"`
	Path      string             `json:"path,omitempty"`
	Type      string             `json:"type,omitempty"`
	Country   string             `json:"country,omitempty"`
	Region    string             `json:"region,omitempty"`
	City      string             `json:"city,omitempty"`
	Org       string             `json:"org,omitempty"`
	Source    string             `json:"source,omitempty"`
	LatencyMS int64              `json:"latency_ms,omitempty"`
	Checks    []publicIPEndpoint `json:"checks"`
}

type publicIPEndpoint struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	URL       string `json:"url"`
	IP        string `json:"ip,omitempty"`
	Type      string `json:"type,omitempty"`
	Country   string `json:"country,omitempty"`
	Region    string `json:"region,omitempty"`
	City      string `json:"city,omitempty"`
	Org       string `json:"org,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

type dnsResult struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses,omitempty"`
	LatencyMS int64    `json:"latency_ms,omitempty"`
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
}

type connectivityTest struct {
	Name         string `json:"name"`
	Path         string `json:"path,omitempty"`
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code,omitempty"`
	LatencyMS    int64  `json:"latency_ms,omitempty"`
	Reachable    bool   `json:"reachable"`
	Blocked      bool   `json:"blocked"`
	ExpectedNote string `json:"expected_note"`
	Error        string `json:"error,omitempty"`
}

// ipRiskProfile combines multiple IP reputation sources into factual egress IP labels.
type ipRiskProfile struct {
	IP         string        `json:"ip,omitempty"`
	Type       string        `json:"type,omitempty"` // residential / hosting / mobile / business / unknown
	IsDatacen  bool          `json:"is_datacenter"`
	IsProxy    bool          `json:"is_proxy"`
	IsVPN      bool          `json:"is_vpn"`
	IsTor      bool          `json:"is_tor"`
	IsAbuser   bool          `json:"is_abuser"`
	IsMobile   bool          `json:"is_mobile"`
	ASN        string        `json:"asn,omitempty"`
	Org        string        `json:"org,omitempty"`
	Source     string        `json:"source,omitempty"`
	LatencyMS  int64         `json:"latency_ms,omitempty"`
	Determined bool          `json:"determined"`
	Checks     []ipRiskCheck `json:"checks"`
}

type ipRiskCheck struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	URL       string `json:"url"`
	Type      string `json:"type,omitempty"`
	IsDatacen bool   `json:"is_datacenter"`
	IsProxy   bool   `json:"is_proxy"`
	IsVPN     bool   `json:"is_vpn"`
	IsTor     bool   `json:"is_tor"`
	IsAbuser  bool   `json:"is_abuser"`
	IsMobile  bool   `json:"is_mobile"`
	ASN       string `json:"asn,omitempty"`
	Org       string `json:"org,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// openAIAvailability captures OpenAI/ChatGPT availability signals beyond simple connectivity.
type openAIAvailability struct {
	Path               string `json:"path,omitempty"`
	Supported          bool   `json:"supported"`
	UnsupportedCountry bool   `json:"unsupported_country"`
	CFCountry          string `json:"cf_country,omitempty"` // Country detected by chatgpt.com Cloudflare edge
	CFIP               string `json:"cf_ip,omitempty"`      // Egress IP returned by Cloudflare trace
	ComplianceOK       bool   `json:"compliance_ok"`        // Whether the compliance endpoint returned successfully
	ComplianceBody     string `json:"compliance_body,omitempty"`
	LatencyMS          int64  `json:"latency_ms,omitempty"`
	Determined         bool   `json:"determined"`
	Note               string `json:"note"`
	Error              string `json:"error,omitempty"`
}

// geoConsistency compares public IP and Cloudflare country signals; timezone is supplemental context.
type geoConsistency struct {
	IPCountry    string   `json:"ip_country,omitempty"`
	CFCountry    string   `json:"cf_country,omitempty"`
	TimezoneName string   `json:"timezone_name,omitempty"`
	TimezoneUTC  string   `json:"timezone_utc,omitempty"`
	Consistent   bool     `json:"consistent"`
	Signals      []string `json:"signals"`
}
