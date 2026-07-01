package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	pluginName    = "CPA Diagnostics"
	pluginVersion = "0.1.4"
	pluginAuthor  = "yuankc"
	pluginRepo    = "https://github.com/yuankc/cliproxy-diagnostics-plugin"
)

var (
	httpClient = &http.Client{Timeout: 5 * time.Second}

	diagnosticsCacheMu      sync.Mutex
	diagnosticsCacheData    diagnostics
	diagnosticsCacheExpires time.Time
)

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
	LocalIPs        []localIP          `json:"local_ips"`
	OutboundSources []outboundSource   `json:"outbound_sources"`
	PublicIP        publicIPResult     `json:"public_ip"`
	IPRisk          ipRiskProfile      `json:"ip_risk"`
	OpenAI          openAIAvailability `json:"openai"`
	Geo             geoConsistency     `json:"geo_consistency"`
	DNS             []dnsResult        `json:"dns"`
	Connectivity    []connectivityTest `json:"connectivity"`
	Risk            riskSummary        `json:"risk"`
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
	URL       string `json:"url"`
	IP        string `json:"ip,omitempty"`
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
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code,omitempty"`
	LatencyMS    int64  `json:"latency_ms,omitempty"`
	Reachable    bool   `json:"reachable"`
	Blocked      bool   `json:"blocked"`
	ExpectedNote string `json:"expected_note"`
	Error        string `json:"error,omitempty"`
}

// ipRiskProfile combines multiple IP reputation sources to identify high-risk egress IP types.
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

type riskSummary struct {
	Level   string   `json:"level"`
	Label   string   `json:"label"`
	Signals []string `json:"signals"`
	Note    string   `json:"note"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	_ = host
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var payload []byte
	if request != nil && requestLen > 0 {
		payload = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), payload)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(registrationPayload())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(pluginapi.ManagementRegistrationResponse{
			Routes: []pluginapi.ManagementRoute{
				{Method: http.MethodGet, Path: "/diagnostics/status", Description: "Returns CPA process network diagnostics as JSON."},
			},
			Resources: []pluginapi.ResourceRoute{
				{Path: "/dashboard", Menu: "网络诊断", Description: "显示公网 IP、本地 IP、DNS 和 OpenAI 连接情况。"},
				{Path: "/status", Description: "Returns CPA process network diagnostics as JSON for the diagnostics dashboard."},
			},
		})
	case pluginabi.MethodManagementHandle:
		var req pluginapi.ManagementRequest
		if len(payload) > 0 {
			if errDecode := json.Unmarshal(payload, &req); errDecode != nil {
				return nil, errDecode
			}
		}
		return okEnvelope(handleManagement(req))
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func registrationPayload() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           pluginAuthor,
			GitHubRepository: pluginRepo,
			Logo:             "",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "timeout_seconds", Type: pluginapi.ConfigFieldTypeInteger, Description: "Reserved for future custom probe timeout configuration."},
				{Name: "extra_targets", Type: pluginapi.ConfigFieldTypeArray, Description: "Reserved for future custom HTTP probe targets."},
			},
		},
		Capabilities: capabilities{ManagementAPI: true},
	}
}

func handleManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if strings.HasSuffix(req.Path, "/diagnostics/status") || strings.HasSuffix(req.Path, "/status") {
		return diagnosticsJSONResponse()
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"content-type":  {"text/html; charset=utf-8"},
			"cache-control": {"no-store"},
		},
		Body: []byte(renderDashboardHTML()),
	}
}

func diagnosticsJSONResponse() pluginapi.ManagementResponse {
	body, errMarshal := json.MarshalIndent(cachedDiagnostics(), "", "  ")
	if errMarshal != nil {
		return textResponse(http.StatusInternalServerError, errMarshal.Error())
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"content-type":  {"application/json; charset=utf-8"},
			"cache-control": {"no-store"},
		},
		Body: body,
	}
}

func cachedDiagnostics() diagnostics {
	now := time.Now()
	diagnosticsCacheMu.Lock()
	if !diagnosticsCacheExpires.IsZero() && now.Before(diagnosticsCacheExpires) {
		cached := diagnosticsCacheData
		diagnosticsCacheMu.Unlock()
		return cached
	}
	diagnosticsCacheMu.Unlock()

	data := collectDiagnostics()
	diagnosticsCacheMu.Lock()
	diagnosticsCacheData = data
	diagnosticsCacheExpires = time.Now().Add(30 * time.Second)
	diagnosticsCacheMu.Unlock()
	return data
}

func collectDiagnostics() diagnostics {
	started := time.Now()
	hostname, _ := os.Hostname()
	tzName, tzUTC := localTimezone()

	localIPs := collectLocalIPs()
	publicIP, dnsResults, connectivity, outbound := publicIPResult{}, []dnsResult{}, []connectivityTest{}, []outboundSource{}
	openAI := openAIAvailability{}

	// Run independent probes concurrently.
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		publicIP = detectPublicIP()
	}()
	go func() {
		defer wg.Done()
		dnsResults = checkDNS([]string{"chatgpt.com", "api.openai.com", "auth.openai.com", "cdn.openai.com"})
	}()
	go func() {
		defer wg.Done()
		connectivity = checkConnectivity()
	}()
	go func() {
		defer wg.Done()
		outbound = detectOutboundSources([]string{"api.openai.com:443", "chatgpt.com:443", "1.1.1.1:443"})
	}()
	go func() {
		defer wg.Done()
		openAI = detectOpenAIAvailability()
	}()
	wg.Wait()

	// Run probes that depend on the detected public IP.
	ipRisk := ipRiskProfile{}
	if publicIP.IP != "" {
		ipRisk = detectIPRisk(publicIP.IP)
	}
	geo := evaluateGeoConsistency(publicIP, openAI, tzName, tzUTC)

	out := diagnostics{
		CheckedAt: time.Now().Format(time.RFC3339),
		Runtime: runtimeInfo{
			Hostname:     hostname,
			GOOS:         runtime.GOOS,
			GOARCH:       runtime.GOARCH,
			PID:          os.Getpid(),
			TimezoneName: tzName,
			TimezoneUTC:  tzUTC,
		},
		LocalIPs:        localIPs,
		OutboundSources: outbound,
		PublicIP:        publicIP,
		IPRisk:          ipRisk,
		OpenAI:          openAI,
		Geo:             geo,
		DNS:             dnsResults,
		Connectivity:    connectivity,
		DurationMS:      time.Since(started).Milliseconds(),
	}
	out.Risk = summarizeRisk(out)
	return out
}

func localTimezone() (name string, utc string) {
	now := time.Now()
	zone, offset := now.Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	hours := offset / 3600
	minutes := (offset % 3600) / 60
	return zone, fmt.Sprintf("UTC%s%02d:%02d", sign, hours, minutes)
}

func collectLocalIPs() []localIP {
	interfaces, errInterfaces := net.Interfaces()
	if errInterfaces != nil {
		return nil
	}
	items := make([]localIP, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, errAddrs := iface.Addrs()
		if errAddrs != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip == nil {
				continue
			}
			version := "IPv6"
			if ip.To4() != nil {
				version = "IPv4"
			}
			items = append(items, localIP{
				Interface: iface.Name,
				Address:   ip.String(),
				Version:   version,
				Private:   ip.IsPrivate(),
				Loopback:  ip.IsLoopback(),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Loopback != items[j].Loopback {
			return !items[i].Loopback
		}
		if items[i].Version != items[j].Version {
			return items[i].Version < items[j].Version
		}
		return items[i].Address < items[j].Address
	})
	return items
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func detectOutboundSources(targets []string) []outboundSource {
	out := make([]outboundSource, len(targets))
	var wg sync.WaitGroup
	for index, target := range targets {
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()
			out[index] = probeOutboundSource(target)
		}(index, target)
	}
	wg.Wait()
	return out
}

func probeOutboundSource(target string) outboundSource {
	started := time.Now()
	conn, errDial := net.DialTimeout("tcp", target, 4*time.Second)
	item := outboundSource{Target: target, Latency: time.Since(started).Milliseconds(), OK: errDial == nil}
	if errDial != nil {
		item.Error = compactError(errDial)
		return item
	}
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcp.IP != nil {
		item.LocalIP = tcp.IP.String()
	}
	if errClose := conn.Close(); errClose != nil && item.Error == "" {
		item.Error = compactError(errClose)
	}
	return item
}

func detectPublicIP() publicIPResult {
	endpoints := []struct {
		name string
		url  string
	}{
		{name: "ipify", url: "https://api.ipify.org?format=json"},
		{name: "ifconfig.co", url: "https://ifconfig.co/json"},
		{name: "ipinfo", url: "https://ipinfo.io/json"},
		{name: "ip.sb", url: "https://api.ip.sb/geoip"},
		{name: "ipapi.co", url: "https://ipapi.co/json/"},
		{name: "ipwho.is", url: "https://ipwho.is/"},
	}
	checks := make([]publicIPEndpoint, len(endpoints))
	var wg sync.WaitGroup
	for index, endpoint := range endpoints {
		wg.Add(1)
		go func(index int, name string, url string) {
			defer wg.Done()
			checks[index] = fetchPublicIP(name, url)
		}(index, endpoint.name, endpoint.url)
	}
	wg.Wait()

	result := publicIPResult{Checks: checks}
	for _, check := range checks {
		if result.IP == "" && check.OK && check.IP != "" {
			result.IP = check.IP
			result.Country = check.Country
			result.Region = check.Region
			result.City = check.City
			result.Org = check.Org
			result.Source = check.Name
			result.LatencyMS = check.LatencyMS
		}
	}
	return result
}

func fetchPublicIP(name, url string) publicIPEndpoint {
	check := publicIPEndpoint{Name: name, URL: url}
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		check.Error = compactError(errReq)
		return check
	}
	req.Header.Set("accept", "application/json,text/plain;q=0.8")
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)

	var resp *http.Response
	var errDo error
	started := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			req = req.Clone(context.Background())
			started = time.Now()
		}
		resp, errDo = httpClient.Do(req)
		check.LatencyMS = time.Since(started).Milliseconds()
		if errDo == nil || !retryablePublicIPError(errDo) {
			break
		}
	}
	if errDo != nil {
		check.Error = publicIPErrorMessage(errDo)
		return check
	}
	defer closeBody(resp.Body)
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if errRead != nil {
		check.Error = publicIPErrorMessage(errRead)
		return check
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		check.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return check
	}
	ip, country, region, city, org := parseIPResponse(body)
	check.IP = ip
	check.Country = country
	check.Region = region
	check.City = city
	check.Org = org
	check.OK = ip != ""
	if !check.OK {
		check.Error = "no IP field in response"
	}
	return check
}

func parseIPResponse(body []byte) (ip string, country string, region string, city string, org string) {
	text := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(strings.Trim(text, "\"")); parsed != nil {
		return parsed.String(), "", "", "", ""
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(body, &payload); errJSON != nil {
		return "", "", "", "", ""
	}
	ip = firstString(payload, "ip", "query", "origin", "address")
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	country = firstString(payload, "country", "country_code", "countryCode")
	region = firstString(payload, "region", "region_name", "regionName")
	city = firstString(payload, "city")
	org = firstString(payload, "org", "organization", "isp", "asn_org")
	if org == "" {
		org = nestedString(payload, "connection", "org")
	}
	if org == "" {
		org = nestedString(payload, "asn", "name")
	}
	return ip, country, region, city, org
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if text, okString := value.(string); okString && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func nestedString(payload map[string]any, path ...string) string {
	var current any = payload
	for _, key := range path {
		values, okValues := current.(map[string]any)
		if !okValues {
			return ""
		}
		current = values[key]
	}
	text, okText := current.(string)
	if !okText {
		return ""
	}
	return strings.TrimSpace(text)
}

func checkDNS(hosts []string) []dnsResult {
	resolver := net.DefaultResolver
	results := make([]dnsResult, len(hosts))
	var wg sync.WaitGroup
	for index, host := range hosts {
		wg.Add(1)
		go func(index int, host string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			started := time.Now()
			addrs, errLookup := resolver.LookupHost(ctx, host)
			cancel()
			item := dnsResult{Host: host, LatencyMS: time.Since(started).Milliseconds(), OK: errLookup == nil}
			if errLookup != nil {
				item.Error = compactError(errLookup)
			} else {
				sort.Strings(addrs)
				item.Addresses = addrs
			}
			results[index] = item
		}(index, host)
	}
	wg.Wait()
	return results
}

func checkConnectivity() []connectivityTest {
	targets := []struct {
		name string
		url  string
		note string
	}{
		{name: "ChatGPT Web", url: "https://chatgpt.com/", note: "2xx/3xx/401 说明网络已到达站点；403 + 拦截页说明该 IP 被 Cloudflare 拒绝。"},
		{name: "OpenAI API", url: "https://api.openai.com/v1/models", note: "未带 API key 时 401 是正常可达。"},
		{name: "OpenAI Auth", url: "https://auth.openai.com/", note: "登录域名可达性。"},
		{name: "OpenAI CDN", url: "https://cdn.openai.com/", note: "静态资源域名可达性。"},
	}
	results := make([]connectivityTest, len(targets))
	var wg sync.WaitGroup
	for index, target := range targets {
		wg.Add(1)
		go func(index int, name, url, note string) {
			defer wg.Done()
			results[index] = probeHTTP(name, url, note)
		}(index, target.name, target.url, target.note)
	}
	wg.Wait()
	return results
}

func probeHTTP(name, url, note string) connectivityTest {
	started := time.Now()
	item := connectivityTest{Name: name, URL: url, ExpectedNote: note}
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		item.Error = compactError(errReq)
		return item
	}
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)
	resp, errDo := httpClient.Do(req)
	item.LatencyMS = time.Since(started).Milliseconds()
	if errDo != nil {
		item.Error = compactError(errDo)
		return item
	}
	defer closeBody(resp.Body)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	item.StatusCode = resp.StatusCode
	// Reaching the site is not the same as the service being usable.
	item.Reachable = resp.StatusCode > 0 && resp.StatusCode < 500
	// Detect Cloudflare/OpenAI block pages for datacenter or restricted IPs.
	item.Blocked = isBlockedResponse(resp.StatusCode, body)
	return item
}

// isBlockedResponse reports whether the response looks like an IP block page.
func isBlockedResponse(status int, body []byte) bool {
	if body != nil && bodyHasBlockMarker(body) {
		return true
	}
	// Treat 403/451 as blocked when no stronger signal is available.
	if status == http.StatusForbidden || status == http.StatusUnavailableForLegalReasons {
		return true
	}
	return false
}

// bodyHasBlockMarker checks Cloudflare/OpenAI block-page markers.
func bodyHasBlockMarker(body []byte) bool {
	text := strings.ToLower(string(body))
	needles := []string{
		"you have been blocked",
		"sorry, you have been blocked",
		"cf-error-details",
		"attention required",
		"access denied",
		"unsupported_country",
	}
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// detectIPRisk profiles the public IP with multiple reputation sources.
func detectIPRisk(ip string) ipRiskProfile {
	endpoints := []struct {
		name string
		url  string
	}{
		{name: "ipapi.is", url: "https://api.ipapi.is/?q=" + ip},
		{name: "ip-api.com", url: "http://ip-api.com/json/" + ip + "?fields=status,message,proxy,hosting,mobile,as,org,isp,countryCode"},
	}
	checks := make([]ipRiskCheck, len(endpoints))
	var wg sync.WaitGroup
	for index, endpoint := range endpoints {
		wg.Add(1)
		go func(index int, name, url string) {
			defer wg.Done()
			checks[index] = fetchIPRisk(name, url)
		}(index, endpoint.name, endpoint.url)
	}
	wg.Wait()

	profile := ipRiskProfile{IP: ip, Type: "unknown", Checks: checks}
	for _, check := range checks {
		if !check.OK {
			continue
		}
		profile.Determined = true
		// Merge boolean risk signals conservatively.
		profile.IsDatacen = profile.IsDatacen || check.IsDatacen
		profile.IsProxy = profile.IsProxy || check.IsProxy
		profile.IsVPN = profile.IsVPN || check.IsVPN
		profile.IsTor = profile.IsTor || check.IsTor
		profile.IsAbuser = profile.IsAbuser || check.IsAbuser
		profile.IsMobile = profile.IsMobile || check.IsMobile
		if profile.ASN == "" && check.ASN != "" {
			profile.ASN = check.ASN
		}
		if profile.Org == "" && check.Org != "" {
			profile.Org = check.Org
		}
		if profile.Source == "" {
			profile.Source = check.Name
			profile.LatencyMS = check.LatencyMS
		}
		if check.Type != "" && profile.Type == "unknown" {
			profile.Type = check.Type
		}
	}
	// Prefer explicit datacenter/mobile signals over residential defaults.
	switch {
	case profile.IsDatacen:
		profile.Type = "hosting"
	case profile.IsMobile:
		profile.Type = "mobile"
	case profile.Determined && profile.Type == "unknown":
		profile.Type = "residential"
	}
	return profile
}

func fetchIPRisk(name, url string) ipRiskCheck {
	check := ipRiskCheck{Name: name, URL: url}
	body, status, latency, err := httpGetJSON(url)
	check.LatencyMS = latency
	if err != nil {
		check.Error = publicIPErrorMessage(err)
		return check
	}
	if status < 200 || status >= 300 {
		check.Error = fmt.Sprintf("HTTP %d", status)
		return check
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(body, &payload); errJSON != nil {
		check.Error = "响应不是有效 JSON"
		return check
	}
	switch name {
	case "ipapi.is":
		parseIPAPIIs(payload, &check)
	case "ip-api.com":
		if firstString(payload, "status") == "fail" {
			check.Error = valueOr(firstString(payload, "message"), "查询失败")
			return check
		}
		parseIPAPICom(payload, &check)
	}
	check.OK = true
	return check
}

// parseIPAPIIs parses ipapi.is reputation fields.
func parseIPAPIIs(payload map[string]any, check *ipRiskCheck) {
	check.IsDatacen = boolField(payload, "is_datacenter")
	check.IsProxy = boolField(payload, "is_proxy")
	check.IsVPN = boolField(payload, "is_vpn")
	check.IsTor = boolField(payload, "is_tor")
	check.IsAbuser = boolField(payload, "is_abuser")
	check.IsMobile = boolField(payload, "is_mobile")
	if asn, ok := payload["asn"].(map[string]any); ok {
		check.ASN = firstString(asn, "asn", "org")
		if org, okOrg := asn["org"].(string); okOrg {
			check.Org = strings.TrimSpace(org)
		}
		if t, okType := asn["type"].(string); okType {
			check.Type = normalizeIPType(t)
		}
	}
	if company, ok := payload["company"].(map[string]any); ok {
		if check.Org == "" {
			check.Org = firstString(company, "name")
		}
		if check.Type == "" {
			if t, okType := company["type"].(string); okType {
				check.Type = normalizeIPType(t)
			}
		}
	}
}

// parseIPAPICom parses ip-api.com fields.
func parseIPAPICom(payload map[string]any, check *ipRiskCheck) {
	check.IsProxy = boolField(payload, "proxy")
	check.IsDatacen = boolField(payload, "hosting")
	check.IsMobile = boolField(payload, "mobile")
	check.ASN = firstString(payload, "as")
	check.Org = firstString(payload, "org", "isp")
	if check.IsDatacen {
		check.Type = "hosting"
	} else if check.IsMobile {
		check.Type = "mobile"
	}
}

// normalizeIPType maps provider-specific IP type labels.
func normalizeIPType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "hosting", "datacenter", "data center":
		return "hosting"
	case "isp", "residential":
		return "residential"
	case "business":
		return "business"
	case "mobile", "cellular":
		return "mobile"
	default:
		return "unknown"
	}
}

// detectOpenAIAvailability checks OpenAI-side availability signals, not just connectivity.
func detectOpenAIAvailability() openAIAvailability {
	result := openAIAvailability{}
	started := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	var complianceBody []byte
	var complianceStatus int
	var complianceErr error
	go func() {
		defer wg.Done()
		complianceBody, complianceStatus, _, complianceErr = httpGetJSON("https://api.openai.com/compliance/cookie_requirements")
	}()

	var traceText string
	var traceErr error
	go func() {
		defer wg.Done()
		traceText, traceErr = fetchCFTrace("https://chatgpt.com/cdn-cgi/trace")
	}()
	wg.Wait()
	result.LatencyMS = time.Since(started).Milliseconds()

	// Parse Cloudflare trace.
	if traceErr == nil && traceText != "" {
		fields := parseCFTrace(traceText)
		if fields["loc"] != "" || fields["ip"] != "" {
			result.CFCountry = fields["loc"]
			result.CFIP = fields["ip"]
		}
	}

	// Parse the compliance endpoint response.
	if complianceErr != nil {
		result.Error = publicIPErrorMessage(complianceErr)
	} else {
		sample := strings.ToLower(string(complianceBody))
		result.ComplianceBody = strings.TrimSpace(truncate(string(complianceBody), 300))
		if complianceStatus >= 200 && complianceStatus < 300 {
			result.ComplianceOK = true
			result.Determined = true
			if strings.Contains(sample, "unsupported_country") {
				result.UnsupportedCountry = true
				result.Supported = false
				result.Note = "OpenAI compliance 接口返回 unsupported_country，当前出口 IP 所在国家/地区不被支持。"
			} else {
				result.Supported = true
				result.Note = "OpenAI compliance 接口成功返回且未出现 unsupported_country，当前出口 IP 所在地区大概率可用。"
			}
		} else {
			result.Error = fmt.Sprintf("OpenAI compliance HTTP %d", complianceStatus)
		}
	}
	if result.Note == "" {
		if result.CFCountry != "" {
			result.Determined = true
			result.Note = "compliance 接口未确认，依据 Cloudflare 识别国家 " + result.CFCountry + " 判断。"
		} else {
			result.Note = "无法确认 OpenAI 可用性，接口不可达。"
		}
	}
	return result
}

func fetchCFTrace(url string) (string, error) {
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		return "", errReq
	}
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)
	resp, errDo := httpClient.Do(req)
	if errDo != nil {
		return "", errDo
	}
	defer closeBody(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("cloudflare trace HTTP %d", resp.StatusCode)
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if errRead != nil {
		return "", errRead
	}
	return string(body), nil
}

// parseCFTrace parses the key=value cdn-cgi/trace format.
func parseCFTrace(text string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return fields
}

// evaluateGeoConsistency compares public IP and Cloudflare country signals.
func evaluateGeoConsistency(pub publicIPResult, openAI openAIAvailability, tzName, tzUTC string) geoConsistency {
	geo := geoConsistency{
		IPCountry:    pub.Country,
		CFCountry:    openAI.CFCountry,
		TimezoneName: tzName,
		TimezoneUTC:  tzUTC,
		Consistent:   true,
		Signals:      make([]string, 0),
	}
	ipCountry := strings.ToUpper(strings.TrimSpace(pub.Country))
	cfCountry := strings.ToUpper(strings.TrimSpace(openAI.CFCountry))
	if ipCountry != "" && cfCountry != "" && ipCountry != cfCountry {
		geo.Consistent = false
		geo.Signals = append(geo.Signals, "出口 IP 国家("+ipCountry+")与 Cloudflare 识别国家("+cfCountry+")不一致")
	}
	if len(geo.Signals) == 0 {
		geo.Signals = append(geo.Signals, "出口 IP 国家、Cloudflare 识别国家一致；进程时区仅作参考")
	}
	return geo
}

// httpGetJSON performs a GET request and returns body, status, and latency.
func httpGetJSON(url string) (body []byte, status int, latencyMS int64, err error) {
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		return nil, 0, 0, errReq
	}
	req.Header.Set("accept", "application/json,text/plain;q=0.8")
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)

	var resp *http.Response
	var errDo error
	started := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			req = req.Clone(context.Background())
			started = time.Now()
		}
		resp, errDo = httpClient.Do(req)
		latencyMS = time.Since(started).Milliseconds()
		if errDo == nil || !retryablePublicIPError(errDo) {
			break
		}
	}
	if errDo != nil {
		return nil, 0, latencyMS, errDo
	}
	defer closeBody(resp.Body)
	data, errRead := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if errRead != nil {
		return nil, resp.StatusCode, latencyMS, errRead
	}
	return data, resp.StatusCode, latencyMS, nil
}

func boolField(payload map[string]any, key string) bool {
	value, ok := payload[key]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	case float64:
		return v != 0
	default:
		return false
	}
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}

func summarizeRisk(data diagnostics) riskSummary {
	signals := make([]string, 0)
	level := "low"

	if data.PublicIP.IP == "" {
		level = maxRisk(level, "unknown")
		signals = append(signals, "所有公共 IP 查询接口均失败，无法确认出口 IP")
	}

	// Compare egress IPs by address family to avoid dual-stack false positives.
	v4, v6 := distinctIPsByFamily(data.PublicIP.Checks)
	if len(v4) > 1 {
		level = maxRisk(level, "warning")
		signals = append(signals, "多个服务返回了不同的 IPv4 出口地址（"+strings.Join(v4, ", ")+"），可能存在代理链、NAT 或接口异常")
	}
	if len(v6) > 1 {
		level = maxRisk(level, "warning")
		signals = append(signals, "多个服务返回了不同的 IPv6 出口地址，可能存在多出口或代理异常")
	}

	// IP reputation signals are high-value indicators for AI service blocks.
	if data.IPRisk.Determined {
		if data.IPRisk.IsTor {
			level = maxRisk(level, "high")
			signals = append(signals, "出口 IP 被识别为 Tor 出口节点，几乎必然被 AI 服务拦截")
		}
		if data.IPRisk.IsProxy {
			level = maxRisk(level, "high")
			signals = append(signals, "出口 IP 被标记为公共代理，属于高风险类型")
		}
		if data.IPRisk.IsAbuser {
			level = maxRisk(level, "high")
			signals = append(signals, "出口 IP 有滥用/攻击历史记录，风控评分高")
		}
		if data.IPRisk.IsVPN {
			level = maxRisk(level, "warning")
			signals = append(signals, "出口 IP 被识别为 VPN，部分 AI 服务会限制此类访问")
		}
		if data.IPRisk.IsDatacen && !data.IPRisk.IsVPN && !data.IPRisk.IsProxy {
			level = maxRisk(level, "warning")
			signals = append(signals, "出口 IP 属于机房/IDC 地址（"+valueOr(data.IPRisk.Org, data.IPRisk.ASN)+"），比住宅 IP 更容易触发 AI 风控")
		}
	}

	// OpenAI availability is different from raw connectivity.
	if data.OpenAI.Determined {
		if data.OpenAI.UnsupportedCountry {
			level = maxRisk(level, "high")
			signals = append(signals, "OpenAI 判定当前出口 IP 所在国家/地区不受支持（unsupported_country），无法正常使用")
		}
	}

	// Geography consistency.
	if !data.Geo.Consistent {
		level = maxRisk(level, "warning")
		signals = append(signals, data.Geo.Signals...)
	}

	for _, item := range data.DNS {
		if !item.OK {
			level = maxRisk(level, "warning")
			signals = append(signals, "DNS 解析失败: "+item.Host)
		}
	}
	for _, item := range data.Connectivity {
		if item.Blocked {
			level = maxRisk(level, "high")
			signals = append(signals, "目标站点返回 IP 拦截页: "+item.Name)
		} else if !item.Reachable {
			level = maxRisk(level, "warning")
			signals = append(signals, "OpenAI 相关连通性失败: "+item.Name)
		}
	}

	if len(signals) == 0 {
		signals = append(signals, "出口 IP、IP 画像、OpenAI 可用性、DNS、连通性均正常")
	}
	return riskSummary{
		Level:   level,
		Label:   riskLabel(level),
		Signals: signals,
		Note:    "风险画像来自第三方 IP 风控接口与 OpenAI 侧信号，结果依赖接口可用性，供参考不构成绝对结论。",
	}
}

// distinctIPsByFamily deduplicates detected egress IPs by address family.
func distinctIPsByFamily(checks []publicIPEndpoint) (v4 []string, v6 []string) {
	seen4 := make(map[string]struct{})
	seen6 := make(map[string]struct{})
	for _, check := range checks {
		if check.IP == "" {
			continue
		}
		parsed := net.ParseIP(check.IP)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			if _, ok := seen4[check.IP]; !ok {
				seen4[check.IP] = struct{}{}
				v4 = append(v4, check.IP)
			}
			continue
		}
		if _, ok := seen6[check.IP]; !ok {
			seen6[check.IP] = struct{}{}
			v6 = append(v6, check.IP)
		}
	}
	return v4, v6
}

func riskLabel(level string) string {
	switch level {
	case "high":
		return "存在高风险信号"
	case "warning":
		return "存在需关注的信号"
	case "unknown":
		return "部分检测无法确认"
	default:
		return "未发现明显风险"
	}
}

func maxRisk(current, next string) string {
	order := map[string]int{"low": 1, "unknown": 2, "warning": 3, "high": 4}
	if order[next] > order[current] {
		return next
	}
	return current
}

func renderDashboardHTML() string {
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CPA 网络诊断</title>
<style>
:root{color-scheme:light;--bg:#f5f7fb;--panel:#ffffff;--text:#1f2937;--muted:#6b7280;--line:#e5e7eb;--line-strong:#d1d5db;--primary:#1677ff;--primary-hover:#0958d9;--good:#15803d;--warn:#b45309;--bad:#dc2626;--soft-blue:#eff6ff;--soft-green:#ecfdf3;--soft-red:#fef2f2;--soft-amber:#fffbeb;--shadow:0 1px 2px rgba(16,24,40,.04)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#111827;--panel:#1f2937;--text:#f9fafb;--muted:#9ca3af;--line:#374151;--line-strong:#4b5563;--primary:#4096ff;--primary-hover:#69b1ff;--soft-blue:#102a43;--soft-green:#0f2f24;--soft-red:#3b1115;--soft-amber:#33260a;--shadow:none}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(1180px,calc(100% - 40px));margin:0 auto;padding:24px 0 36px}.pageHeader{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:16px}.pageTitle{font-size:24px;line-height:1.25;margin:0 0 6px;font-weight:650}.pageDesc{margin:0;color:var(--muted)}.toolbar{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.btn{border:1px solid var(--line-strong);background:var(--panel);color:var(--text);height:34px;padding:0 12px;border-radius:6px;text-decoration:none;display:inline-flex;align-items:center;gap:6px;font-size:13px;cursor:pointer}.btn:hover{border-color:var(--primary);color:var(--primary)}.btnPrimary{border-color:var(--primary);background:var(--primary);color:#fff}.btnPrimary:hover{background:var(--primary-hover);border-color:var(--primary-hover);color:#fff}.btn[disabled]{opacity:.58;cursor:not-allowed}.summary{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:var(--shadow);margin-bottom:14px}.summaryGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}.label{color:var(--muted);font-size:12px;margin-bottom:6px}.ip{font-size:30px;line-height:1.15;font-weight:700;overflow-wrap:anywhere}.value{font-size:15px;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;box-shadow:var(--shadow)}.panelHead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}.panel h2{font-size:15px;margin:0;font-weight:650}.rows{display:grid;gap:8px}.row{display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:10px;align-items:start;border-top:1px solid var(--line);padding-top:8px}.row:first-child{border-top:0;padding-top:0}.name{font-weight:600;overflow-wrap:anywhere}.meta{color:var(--muted);overflow-wrap:anywhere}.status{font-weight:650;white-space:nowrap}.ok{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:2px 8px;font-size:12px;font-weight:650}.badgeOk{background:var(--soft-green);color:var(--good)}.badgeWarn{background:var(--soft-amber);color:var(--warn)}.badgeBad{background:var(--soft-red);color:var(--bad)}.badgeInfo{background:var(--soft-blue);color:var(--primary)}.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{background:var(--soft-blue);color:var(--primary);border-radius:999px;padding:3px 8px;font-size:12px}.ipCards{display:grid;gap:10px}.ipCard{border:1px solid var(--line);border-radius:8px;padding:12px;background:rgba(148,163,184,.04)}.ipCardHead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}.ipCardTitle{font-weight:650}.kvGrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.kv{min-width:0}.kvLabel{color:var(--muted);font-size:12px;margin-bottom:2px}.kvValue{overflow-wrap:anywhere}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.small{font-size:12px;color:var(--muted);margin-top:12px}.browser{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.loadingBox{background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:34px 18px;margin-bottom:14px;display:flex;align-items:center;justify-content:center;gap:12px;color:var(--muted)}.spinner{width:22px;height:22px;border:3px solid var(--line);border-top-color:var(--primary);border-radius:999px;animation:spin .8s linear infinite}.skeleton{position:relative;overflow:hidden;background:linear-gradient(90deg,rgba(148,163,184,.14),rgba(148,163,184,.28),rgba(148,163,184,.14));background-size:240% 100%;animation:shimmer 1.2s ease-in-out infinite;border-radius:6px;min-height:16px}.hidden{display:none!important}.errorBox{border:1px solid #fecaca;background:var(--soft-red);color:var(--bad);border-radius:8px;padding:12px 14px;margin-bottom:14px}@keyframes spin{to{transform:rotate(360deg)}}@keyframes shimmer{to{background-position:-240% 0}}@media (max-width:900px){main{width:min(100% - 20px,1180px);padding-top:18px}.pageHeader{display:block}.toolbar{justify-content:flex-start;margin-top:12px}.summaryGrid,.grid,.browser,.kvGrid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.status{white-space:normal}.ip{font-size:25px}}
</style>
</head>
<body>
<main>
  <section class="pageHeader">
    <div>
      <h1 class="pageTitle">CPA 网络诊断</h1>
      <p class="pageDesc">检测位置：CPA 插件进程所在环境。无论主机直装、Docker 还是云容器部署，这里显示的都是实际运行环境看到的出口状态。</p>
    </div>
    <div class="toolbar">
      <button class="btn btnPrimary" id="refreshBtn" type="button">重新检测</button>
      <a class="btn" href="/v0/management/diagnostics/status">JSON API</a>
    </div>
  </section>

  <div id="loading" class="loadingBox">
    <span class="spinner" aria-hidden="true"></span>
    <span>正在检测部署环境的出口 IP、DNS 和 OpenAI 连通性...</span>
  </div>
  <div id="error" class="errorBox hidden"></div>
  <div id="content" class="hidden"></div>
</main>
<script>
const statusUrl = '/v0/resource/plugins/diagnostics/status';
const loading = document.getElementById('loading');
const errorBox = document.getElementById('error');
const content = document.getElementById('content');
const refreshBtn = document.getElementById('refreshBtn');

refreshBtn.addEventListener('click', function(){ runDiagnostics(); });
runDiagnostics();

async function runDiagnostics(){
  loading.classList.remove('hidden');
  errorBox.classList.add('hidden');
  content.classList.add('hidden');
  refreshBtn.disabled = true;
  try {
    const resp = await fetch(statusUrl + '?t=' + Date.now(), {cache:'no-store'});
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    content.innerHTML = render(data);
    content.classList.remove('hidden');
    renderBrowserInfo();
  } catch (err) {
    errorBox.textContent = '诊断加载失败：' + (err && err.message ? err.message : String(err));
    errorBox.classList.remove('hidden');
  } finally {
    loading.classList.add('hidden');
    refreshBtn.disabled = false;
  }
}

function render(data){
  const pub = data.public_ip || {};
  const risk = data.risk || {};
  const ipRisk = data.ip_risk || {};
  const openai = data.openai || {};
  return '<section class="summary">' +
    '<div class="summaryGrid">' +
      metric('公共出口 IP', pub.ip || '未获取', 'ip mono') +
      metric('国家/地区', pub.country || '未知', 'value') +
      metric('IP 类型', ipTypeBadge(ipRisk), 'value raw') +
      metric('OpenAI 可用性', openaiBadge(openai), 'value raw') +
      metric('运营商/组织', pub.org || ipRisk.org || '未知', 'value') +
      metric('风险概览', badge(risk.level, risk.label || '未知'), 'value raw') +
    '</div>' +
    '<div class="small">检测时间：' + esc(data.checked_at || '-') + '，耗时 ' + esc(data.duration_ms || 0) + ' ms，来源：' + esc(pub.source || '无') + '。</div>' +
  '</section>' +
  '<section class="grid">' +
    panel('风险信号', renderRisk(risk)) +
    panel('IP 风险画像', renderIPRisk(ipRisk)) +
    panel('OpenAI 可用性', renderOpenAI(openai)) +
    panel('地区一致性', renderGeo(data.geo_consistency || {})) +
    panel('运行环境', renderRuntime(data.runtime || {})) +
    panel('本机 IP', renderLocalIPs(data.local_ips || [])) +
    panel('出口源地址', renderOutbound(data.outbound_sources || [])) +
    panel('公共 IP 查询', renderPublicChecks((pub.checks || []))) +
    panel('DNS 解析', renderDNS(data.dns || [])) +
    panel('OpenAI 连通性', renderConnectivity(data.connectivity || [])) +
    panel('浏览器信息', '<div id="browser" class="browser"></div><div class="small">浏览器信息来自当前页面，用来对比访问者环境和 CPA 进程环境。</div>') +
  '</section>';
}

function metric(label, value, cls){
  const raw = cls && cls.indexOf('raw') >= 0;
  return '<div><div class="label">' + esc(label) + '</div><div class="' + esc(cls || 'value') + '">' + (raw ? value : esc(value)) + '</div></div>';
}
function panel(title, body){
  return '<div class="panel"><div class="panelHead"><h2>' + esc(title) + '</h2></div>' + body + '</div>';
}
function rows(items){
  return items.length ? '<div class="rows">' + items.join('') + '</div>' : '<div class="meta">暂无数据</div>';
}
function row(name, meta, right){
  return '<div class="row"><div class="name">' + esc(name) + '</div><div class="meta mono">' + esc(meta || '未知') + '</div><div>' + (right || '') + '</div></div>';
}
function renderRisk(risk){
  const signals = risk.signals || [];
  return rows(signals.map(function(signal){ return row('信号', signal, ''); })) +
    '<div class="small">' + esc(risk.note || '这是基础网络可达性与出口一致性检测，不等同于专业 IP 风控评分。') + '</div>';
}
function renderRuntime(info){
  return rows([
    row('Hostname', info.hostname || '-', ''),
    row('OS / Arch', compact([info.goos, info.goarch], ' / ') || '-', ''),
    row('时区', compact([info.timezone_name, info.timezone_utc], ' ') || '-', ''),
    row('PID', String(info.pid || '-'), '')
  ]);
}
function renderLocalIPs(items){
  return rows(items.map(function(item){
    const tags = [item.version || 'IP'];
    if (item.private) tags.push('private');
    if (item.loopback) tags.push('loopback');
    return row(item.interface || '-', item.address || '-', chips(tags));
  }));
}
function renderOutbound(items){
  return rows(items.map(function(item){
    return row(item.target || '-', item.local_ip || item.error || '-', status(item.ok, item.latency_ms));
  }));
}
function renderPublicChecks(items){
  if (!items.length) return '<div class="meta">暂无数据</div>';
  return '<div class="ipCards">' + items.map(function(item){
    return '<div class="ipCard">' +
      '<div class="ipCardHead"><div class="ipCardTitle">' + esc(item.name || '查询源') + '</div>' + status(item.ok, item.latency_ms) + '</div>' +
      '<div class="kvGrid">' +
        kv('IP 地址', item.ip || '未获取', true) +
        kv('国家/地区', item.country || '未知') +
        kv('地区', item.region || '未知') +
        kv('城市', item.city || '未知') +
        kv('运营商/组织', item.org || '未知') +
        kv('接口地址', item.url || '-', true) +
      '</div>' +
      (item.error ? '<div class="small bad">说明：' + esc(item.error) + '</div>' : '') +
    '</div>';
  }).join('') + '</div>';
}
function renderDNS(items){
  return rows(items.map(function(item){
    return row(item.host || '-', (item.addresses || []).join(', ') || item.error || '-', status(item.ok, item.latency_ms));
  }));
}
function renderConnectivity(items){
  return rows(items.map(function(item){
    const meta = item.status_code ? ('HTTP ' + item.status_code + ' | ' + (item.expected_note || '')) : (item.error || '-');
    const right = item.blocked ? '<span class="status bad">被拦截' + (item.latency_ms || item.latency_ms === 0 ? ' · ' + esc(item.latency_ms) + ' ms' : '') + '</span>' : status(item.reachable, item.latency_ms);
    return row(item.name || '-', meta, right);
  }));
}
function renderIPRisk(ip){
  if (!ip.determined) return '<div class="meta">未能确定 IP 画像（风控接口不可达或未获取到出口 IP）。</div>';
  const flags = [];
  if (ip.is_datacenter) flags.push('机房/IDC');
  if (ip.is_proxy) flags.push('代理');
  if (ip.is_vpn) flags.push('VPN');
  if (ip.is_tor) flags.push('Tor');
  if (ip.is_abuser) flags.push('滥用历史');
  if (ip.is_mobile) flags.push('移动网络');
  return rows([
    row('IP 类型', ipTypeLabel(ip.type), ipTypeBadge(ip)),
    row('风险标记', flags.length ? flags.join('、') : '无代理/VPN/机房标记', flags.length ? '<span class="status bad">命中</span>' : '<span class="status ok">干净</span>'),
    row('ASN', ip.asn || '-', ''),
    row('组织', ip.org || '-', ''),
    row('数据来源', ip.source || '-', '')
  ]);
}
function renderOpenAI(o){
  if (!o.determined) return '<div class="meta">未能确定 OpenAI 可用性（compliance 接口与 Cloudflare trace 均不可达）。</div><div class="small">' + esc(o.note || '') + '</div>';
  const supported = o.supported && !o.unsupported_country;
  return rows([
    row('可用性结论', supported ? '当前出口 IP 可用' : '当前出口 IP 不可用/受限', supported ? '<span class="status ok">可用</span>' : '<span class="status bad">不可用</span>'),
    row('unsupported_country', o.unsupported_country ? '命中（该地区不被支持）' : '未命中', o.unsupported_country ? '<span class="status bad">命中</span>' : '<span class="status ok">正常</span>'),
    row('CF 识别国家', o.cf_country || '-', ''),
    row('compliance 接口', o.compliance_ok ? '成功返回' : (o.error || '未响应'), status(o.compliance_ok, o.latency_ms))
  ]) + '<div class="small">' + esc(o.note || '') + '</div>';
}
function renderGeo(g){
  const signals = g.signals || [];
  return rows([
    row('IP 国家', g.ip_country || '-', ''),
    row('CF 识别国家', g.cf_country || '-', ''),
    row('进程时区', compact([g.timezone_name, g.timezone_utc], ' ') || '-', g.consistent ? '<span class="status ok">一致</span>' : '<span class="status bad">不一致</span>')
  ]) + '<div class="rows" style="margin-top:8px">' + signals.map(function(s){ return row('信号', s, ''); }).join('') + '</div>' +
    '<div class="small">进程时区用于辅助判断部署环境，当前版本不把时区直接计入一致性结论。</div>';
}
function ipTypeLabel(t){
  const map = {hosting:'机房 / 数据中心', residential:'住宅宽带', mobile:'移动网络', business:'商业宽带', unknown:'未知'};
  return map[t] || '未知';
}
function ipTypeBadge(ip){
  if (!ip || !ip.determined) return '<span class="badge badgeInfo">未知</span>';
  const t = ip.type;
  let cls = 'badgeInfo';
  if (t === 'residential' || t === 'mobile' || t === 'business') cls = 'badgeOk';
  if (t === 'hosting') cls = 'badgeBad';
  return '<span class="badge ' + cls + '">' + esc(ipTypeLabel(t)) + '</span>';
}
function openaiBadge(o){
  if (!o || !o.determined) return '<span class="badge badgeInfo">未知</span>';
  const supported = o.supported && !o.unsupported_country;
  return '<span class="badge ' + (supported ? 'badgeOk' : 'badgeBad') + '">' + (supported ? '可用' : '不可用') + '</span>';
}
function renderBrowserInfo(){
  const browser = document.getElementById('browser');
  if (!browser) return;
  const items = [
    ['语言', navigator.language || '未知'],
    ['平台', navigator.platform || '未知'],
    ['时区', Intl.DateTimeFormat().resolvedOptions().timeZone || '未知'],
    ['User Agent', navigator.userAgent || '未知'],
    ['页面地址', location.href]
  ];
  browser.innerHTML = items.map(function(item){
    return '<div><div class="label">' + esc(item[0]) + '</div><div class="value mono">' + esc(item[1]) + '</div></div>';
  }).join('');
}
function status(ok, ms){
  return '<span class="status ' + (ok ? 'ok' : 'bad') + '">' + (ok ? '正常' : '失败') + (ms || ms === 0 ? ' · ' + esc(ms) + ' ms' : '') + '</span>';
}
function kv(label, value, mono){
  return '<div class="kv"><div class="kvLabel">' + esc(label) + '</div><div class="kvValue ' + (mono ? 'mono' : '') + '">' + esc(value) + '</div></div>';
}
function badge(level, label){
  let cls = 'badgeInfo';
  if (level === 'low') cls = 'badgeOk';
  if (level === 'warning') cls = 'badgeWarn';
  if (level === 'high' || level === 'unknown') cls = 'badgeBad';
  return '<span class="badge ' + cls + '">' + esc(label || level || '未知') + '</span>';
}
function chips(values){
  return '<span class="chips">' + values.map(function(value){ return '<span class="chip">' + esc(value) + '</span>'; }).join('') + '</span>';
}
function compact(values, sep){
  return values.filter(function(v){ return v !== undefined && v !== null && String(v).trim() !== ''; }).join(sep);
}
function esc(value){
  return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
  });
}
</script>
</body>
</html>`
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return "未知"
}

func textResponse(status int, text string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    map[string][]string{"content-type": {"text/plain; charset=utf-8"}},
		Body:       []byte(text),
	}
}

func okEnvelope(result any) ([]byte, error) {
	raw, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: json.RawMessage(raw)})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: &pluginabi.Error{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func closeBody(body io.Closer) {
	if body == nil {
		return
	}
	_ = body.Close()
}

func compactError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.Name != "" {
		text = dnsErr.Err + ": " + dnsErr.Name
	}
	if len(text) > 180 {
		return text[:180] + "..."
	}
	return text
}

func retryablePublicIPError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "forcibly closed") ||
		strings.Contains(text, "connection reset") ||
		strings.Contains(text, "wsarecv") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "timeout")
}

func publicIPErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "forcibly closed") || strings.Contains(text, "connection reset") || strings.Contains(text, "wsarecv") {
		return "连接被远程服务关闭，已跳过该查询源"
	}
	if strings.Contains(text, "timeout") {
		return "查询超时，已跳过该查询源"
	}
	if strings.Contains(text, "no such host") {
		return "DNS 解析失败，已跳过该查询源"
	}
	return compactError(err)
}
