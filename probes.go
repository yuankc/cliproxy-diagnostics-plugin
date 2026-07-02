package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

type probeMode string

const (
	probeModeDirect probeMode = "direct"
	probeModeHost   probeMode = "host"
)

func collectDiagnostics() diagnostics {
	return collectDiagnosticsFor(probeModeDirect)
}

func collectDiagnosticsFor(mode probeMode) diagnostics {
	started := time.Now()
	hostname, _ := os.Hostname()
	tzName, tzUTC := localTimezone()
	proxy := collectProxyInfo()

	localIPs := collectLocalIPs()
	publicIP, directPublicIP, hostPublicIP, dnsResults, connectivity, outbound := publicIPResult{}, publicIPResult{}, publicIPResult{}, []dnsResult{}, []connectivityTest{}, []outboundSource{}
	openAI := openAIAvailability{}

	// Run independent probes concurrently.
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		directPublicIP = detectPublicIPFor(probeModeDirect)
		if hostHTTPAvailable() {
			hostPublicIP = detectPublicIPFor(probeModeHost)
		}
		publicIP = activePublicIP(directPublicIP, hostPublicIP, mode)
	}()
	go func() {
		defer wg.Done()
		dnsResults = checkDNS([]string{"chatgpt.com", "api.openai.com", "auth.openai.com", "cdn.openai.com"})
	}()
	go func() {
		defer wg.Done()
		connectivity = checkConnectivityFor(mode)
	}()
	go func() {
		defer wg.Done()
		outbound = detectOutboundSources([]string{"api.openai.com:443", "chatgpt.com:443", "1.1.1.1:443"})
	}()
	go func() {
		defer wg.Done()
		openAI = detectOpenAIAvailabilityFor(mode)
	}()
	wg.Wait()

	// Run probes that depend on the detected public IP.
	ipRisk := ipRiskProfile{}
	if publicIP.IP != "" {
		ipRisk = detectIPRiskFor(mode, publicIP.IP)
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
		Proxy:           proxy,
		Egress:          compareEgress(directPublicIP, hostPublicIP, mode),
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

func activeProbeMode() probeMode {
	return probeModeDirect
}

func probeModeFromString(value string) probeMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(probeModeHost), "proxy", "cpa":
		return probeModeHost
	case string(probeModeDirect), "local", "native":
		return probeModeDirect
	default:
		return ""
	}
}

func modeFromPath(path string) probeMode {
	if path == string(probeModeHost) {
		return probeModeHost
	}
	return probeModeDirect
}

func activePublicIP(direct publicIPResult, host publicIPResult, mode probeMode) publicIPResult {
	if mode == probeModeHost {
		return host
	}
	return direct
}

func compareEgress(direct publicIPResult, host publicIPResult, mode probeMode) egressComparison {
	out := egressComparison{
		HostHTTPAvailable: hostHTTPAvailable(),
		ActivePath:        string(mode),
		Direct:            direct,
		Host:              host,
		Signals:           make([]string, 0),
	}
	if !out.HostHTTPAvailable {
		out.Note = "当前运行环境没有可用的宿主 HTTP 回调，检测只能使用插件直连通道。"
		out.Signals = append(out.Signals, "宿主 HTTP 回调不可用，无法验证 CPA proxy-url 是否生效")
		return out
	}
	if direct.IP != "" && host.IP != "" {
		out.Compared = true
		out.SameIP = direct.IP == host.IP
		if out.SameIP {
			out.Signals = append(out.Signals, "direct 与 host 出口 IP 相同，CPA 全局代理可能未配置、未生效，或代理出口与直连出口一致")
		} else {
			out.Signals = append(out.Signals, "direct 与 host 出口 IP 不同，CPA 宿主出站策略正在改变出口路径")
		}
	} else if host.IP == "" {
		out.Signals = append(out.Signals, "host 通道未获取到出口 IP，CPA 代理或宿主 HTTP 出站可能异常")
	} else if direct.IP == "" {
		out.Signals = append(out.Signals, "direct 通道未获取到出口 IP，但 host 通道可用，裸网络可能受限或仅代理可出站")
	}
	out.Note = "direct 表示插件进程裸网络；host 表示通过 CPA 宿主 HTTP 回调发起请求，会应用 CPA 宿主出站策略。"
	return out
}

func collectProxyInfo() proxyInfo {
	names := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}
	out := proxyInfo{Variables: make([]proxyVariable, 0, len(names)), Note: "未检测到代理环境变量。"}
	hasProxy := false
	for _, name := range names {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		masked := sanitizeProxyValue(value)
		out.Variables = append(out.Variables, proxyVariable{Name: name, Value: masked, Set: true})
		upper := strings.ToUpper(name)
		if value != "" && upper != "NO_PROXY" {
			hasProxy = true
		}
	}
	out.Detected = hasProxy
	switch {
	case hasProxy:
		out.Note = "检测到代理环境变量，CPA 进程的外部请求可能经过代理，公共出口 IP 通常会显示为代理服务器出口。"
	case len(out.Variables) > 0:
		out.Note = "仅检测到 NO_PROXY 等代理排除配置，未检测到实际代理入口。"
	}
	return out
}

func sanitizeProxyValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.User != nil {
		parsed.User = url.UserPassword("***", "***")
		return parsed.String()
	}
	at := strings.LastIndex(value, "@")
	if at > 0 {
		return "***@" + value[at+1:]
	}
	return value
}

func doHTTPRequest(mode probeMode, req *http.Request, bodyLimit int64) ([]byte, int, http.Header, int64, error) {
	if req == nil {
		return nil, 0, nil, 0, fmt.Errorf("request is nil")
	}
	started := time.Now()
	if mode == probeModeHost {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		resp, errDo := hostHTTPDo(ctx, hostHTTPRequest{
			Method:  req.Method,
			URL:     req.URL.String(),
			Headers: req.Header.Clone(),
		})
		latencyMS := time.Since(started).Milliseconds()
		if errDo != nil {
			return nil, 0, nil, latencyMS, errDo
		}
		body := resp.Body
		if bodyLimit > 0 && int64(len(body)) > bodyLimit {
			body = body[:bodyLimit]
		}
		return body, resp.StatusCode, resp.Headers, latencyMS, nil
	}

	resp, errDo := httpClient.Do(req)
	latencyMS := time.Since(started).Milliseconds()
	if errDo != nil {
		return nil, 0, nil, latencyMS, errDo
	}
	defer closeBody(resp.Body)
	limit := bodyLimit
	if limit <= 0 {
		limit = 64 * 1024
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, limit))
	if errRead != nil {
		return nil, resp.StatusCode, resp.Header.Clone(), latencyMS, errRead
	}
	return body, resp.StatusCode, resp.Header.Clone(), latencyMS, nil
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
	if hostHTTPAvailable() {
		host := detectPublicIPFor(probeModeHost)
		if host.IP != "" {
			return host
		}
	}
	return detectPublicIPFor(probeModeDirect)
}

func detectPublicIPFor(mode probeMode) publicIPResult {
	endpoints := []struct {
		name string
		url  string
	}{
		{name: "ifconfig.co", url: "https://ifconfig.co/json"},
		{name: "ipinfo", url: "https://ipinfo.io/json"},
		{name: "ip.sb", url: "https://api.ip.sb/geoip"},
		{name: "ipwho.is", url: "https://ipwho.is/"},
	}
	checks := make([]publicIPEndpoint, len(endpoints))
	var wg sync.WaitGroup
	for index, endpoint := range endpoints {
		wg.Add(1)
		go func(index int, name string, url string) {
			defer wg.Done()
			checks[index] = fetchPublicIPFor(mode, name, url)
		}(index, endpoint.name, endpoint.url)
	}
	wg.Wait()

	result := publicIPResult{Path: string(mode), Checks: checks}
	for _, check := range checks {
		if result.IP == "" && check.OK && check.IP != "" {
			result.IP = check.IP
			result.Type = check.Type
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
	return fetchPublicIPFor(activeProbeMode(), name, url)
}

func fetchPublicIPFor(mode probeMode, name, url string) publicIPEndpoint {
	check := publicIPEndpoint{Name: name, Path: string(mode), URL: url}
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		check.Error = compactError(errReq)
		return check
	}
	req.Header.Set("accept", "application/json,text/plain;q=0.8")
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)

	var errDo error
	var body []byte
	var status int
	var latency int64
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			req = req.Clone(context.Background())
		}
		body, status, _, latency, errDo = doHTTPRequest(mode, req, 64*1024)
		check.LatencyMS = latency
		if errDo == nil || !retryablePublicIPError(errDo) {
			break
		}
	}
	if errDo != nil {
		check.Error = publicIPErrorMessage(errDo)
		return check
	}
	if status < 200 || status >= 300 {
		check.Error = fmt.Sprintf("HTTP %d", status)
		return check
	}
	ip, ipType, country, region, city, org := parseIPResponse(body)
	check.IP = ip
	check.Type = ipType
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

func parseIPResponse(body []byte) (ip string, ipType string, country string, region string, city string, org string) {
	text := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(strings.Trim(text, "\"")); parsed != nil {
		return parsed.String(), "", "", "", "", ""
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(body, &payload); errJSON != nil {
		return "", "", "", "", "", ""
	}
	ip = firstString(payload, "ip", "query", "origin", "address")
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	ipType = publicIPTypeFromPayload(payload)
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
	return ip, ipType, country, region, city, org
}

func publicIPTypeFromPayload(payload map[string]any) string {
	for _, path := range [][2]string{
		{"connection", "type"},
		{"asn", "type"},
		{"company", "type"},
	} {
		if value := normalizeIPType(nestedString(payload, path[0], path[1])); value != "unknown" {
			return value
		}
	}
	if privacy, ok := payload["privacy"].(map[string]any); ok {
		switch {
		case boolField(privacy, "hosting"):
			return "hosting"
		case boolField(privacy, "vpn") || boolField(privacy, "proxy") || boolField(privacy, "tor"):
			return "hosting"
		}
	}
	return ""
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
	return checkConnectivityFor(activeProbeMode())
}

func checkConnectivityFor(mode probeMode) []connectivityTest {
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
			results[index] = probeHTTPFor(mode, name, url, note)
		}(index, target.name, target.url, target.note)
	}
	wg.Wait()
	return results
}

func probeHTTP(name, url, note string) connectivityTest {
	return probeHTTPFor(activeProbeMode(), name, url, note)
}

func probeHTTPFor(mode probeMode, name, url, note string) connectivityTest {
	item := connectivityTest{Name: name, Path: string(mode), URL: url, ExpectedNote: note}
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		item.Error = compactError(errReq)
		return item
	}
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)
	body, status, _, latency, errDo := doHTTPRequest(mode, req, 16*1024)
	item.LatencyMS = latency
	if errDo != nil {
		item.Error = compactError(errDo)
		return item
	}
	item.StatusCode = status
	// Reaching the site is not the same as the service being usable.
	item.Reachable = status > 0 && status < 500
	// Detect Cloudflare/OpenAI block pages for datacenter or restricted IPs.
	item.Blocked = isBlockedResponse(status, body)
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
	return detectIPRiskFor(activeProbeMode(), ip)
}

func detectIPRiskFor(mode probeMode, ip string) ipRiskProfile {
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
			checks[index] = fetchIPRiskFor(mode, name, url)
		}(index, endpoint.name, endpoint.url)
	}
	wg.Wait()

	profile := ipRiskProfile{IP: ip, Type: "unknown", Checks: checks}
	for _, check := range checks {
		if !check.OK {
			continue
		}
		profile.Determined = true
		// Merge boolean labels conservatively.
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

func ipRiskHTTPError(name string, status int) string {
	if name == "ip-api.com" && status == http.StatusTooManyRequests {
		return "ip-api.com 查询频率过高，免费接口限制 45 次/分钟，请稍后重试"
	}
	return fmt.Sprintf("HTTP %d", status)
}
func fetchIPRisk(name, url string) ipRiskCheck {
	return fetchIPRiskFor(activeProbeMode(), name, url)
}

func fetchIPRiskFor(mode probeMode, name, url string) ipRiskCheck {
	check := ipRiskCheck{Name: name, Path: string(mode), URL: url}
	body, status, latency, err := httpGetJSONFor(mode, url)
	check.LatencyMS = latency
	if err != nil {
		check.Error = publicIPErrorMessage(err)
		return check
	}
	if status < 200 || status >= 300 {
		check.Error = ipRiskHTTPError(name, status)
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
	return detectOpenAIAvailabilityFor(activeProbeMode())
}

func detectOpenAIAvailabilityFor(mode probeMode) openAIAvailability {
	result := openAIAvailability{Path: string(mode)}
	started := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	var complianceBody []byte
	var complianceStatus int
	var complianceErr error
	go func() {
		defer wg.Done()
		complianceBody, complianceStatus, _, complianceErr = httpGetJSONFor(mode, "https://api.openai.com/compliance/cookie_requirements")
	}()

	var traceText string
	var traceErr error
	go func() {
		defer wg.Done()
		traceText, traceErr = fetchCFTraceFor(mode, "https://chatgpt.com/cdn-cgi/trace")
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
	return fetchCFTraceFor(activeProbeMode(), url)
}

func fetchCFTraceFor(mode probeMode, url string) (string, error) {
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		return "", errReq
	}
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)
	body, status, _, _, errDo := doHTTPRequest(mode, req, 4096)
	if errDo != nil {
		return "", errDo
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("cloudflare trace HTTP %d", status)
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
	return httpGetJSONFor(activeProbeMode(), url)
}

func httpGetJSONFor(mode probeMode, url string) (body []byte, status int, latencyMS int64, err error) {
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if errReq != nil {
		return nil, 0, 0, errReq
	}
	req.Header.Set("accept", "application/json,text/plain;q=0.8")
	req.Header.Set("user-agent", "cliproxy-diagnostics-plugin/"+pluginVersion)

	var errDo error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			req = req.Clone(context.Background())
		}
		body, status, _, latencyMS, errDo = doHTTPRequest(mode, req, 64*1024)
		if errDo == nil || !retryablePublicIPError(errDo) {
			break
		}
	}
	if errDo != nil {
		return nil, 0, latencyMS, errDo
	}
	return body, status, latencyMS, nil
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
