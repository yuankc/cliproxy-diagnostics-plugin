package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	diagnosticsCacheMu      sync.Mutex
	diagnosticsCacheData    = make(map[probeMode]diagnosticsCacheEntry)
	diagnosticsCacheLoading bool
	diagnosticsCacheCond    = sync.NewCond(&diagnosticsCacheMu)
)

type diagnosticsCacheEntry struct {
	data    diagnostics
	expires time.Time
}

func handleMethod(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(registrationPayload())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(pluginapi.ManagementRegistrationResponse{
			Routes: []pluginapi.ManagementRoute{
				{Method: http.MethodGet, Path: "/diagnostics/status", Description: "Returns CPA process network check results as JSON."},
			},
			Resources: []pluginapi.ResourceRoute{
				{Path: "/dashboard", Menu: "网络检测", Description: "显示公网 IP、本地 IP、DNS 和 OpenAI 连接情况。"},
				{Path: "/status", Description: "Returns CPA process network check results as JSON for the network check dashboard."},
				{Path: "/status/runtime", Description: "Returns runtime, local IP, and proxy check results."},
				{Path: "/status/egress", Description: "Returns direct vs host egress check results."},
				{Path: "/status/public-ip", Description: "Returns public IP check results."},
				{Path: "/status/ip-risk", Description: "Returns IP reputation check results."},
				{Path: "/status/openai", Description: "Returns OpenAI availability check results."},
				{Path: "/status/geo", Description: "Returns geographic consistency check results."},
				{Path: "/status/dns", Description: "Returns DNS check results."},
				{Path: "/status/connectivity", Description: "Returns HTTP connectivity check results."},
				{Path: "/status/outbound", Description: "Returns outbound source address check results."},
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
		},
		Capabilities: capabilities{ManagementAPI: true},
	}
}

func handleManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if kind := statusPathKind(req.Path); kind != "" {
		return diagnosticsJSONResponse(kind, probeModeFromRequest(req))
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

func diagnosticsJSONResponse(kind string, mode probeMode) pluginapi.ManagementResponse {
	body, errMarshal := json.MarshalIndent(diagnosticsPayload(kind, mode), "", "  ")
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

func isStatusPath(path string) bool {
	return statusPathKind(path) != ""
}

func statusPathKind(path string) string {
	if index := strings.Index(path, "?"); index >= 0 {
		path = path[:index]
	}
	cleaned := "/" + strings.Trim(strings.TrimSuffix(path, "/"), "/")
	bases := []string{"/status", "/diagnostics/status", "/v0/management/diagnostics/status", "/v0/resource/plugins/diagnostics/status"}
	for _, base := range bases {
		if cleaned == base {
			return "full"
		}
		if strings.HasPrefix(cleaned, base+"/") {
			kind := strings.TrimPrefix(cleaned, base+"/")
			switch kind {
			case "runtime", "proxy", "egress", "public-ip", "ip-risk", "openai", "geo", "dns", "connectivity", "outbound":
				return kind
			}
		}
	}
	return ""
}

func probeModeFromRequest(req pluginapi.ManagementRequest) probeMode {
	if mode := probeModeFromString(req.Query.Get("network")); mode != "" {
		return mode
	}
	if mode := probeModeFromString(req.Query.Get("mode")); mode != "" {
		return mode
	}
	if index := strings.Index(req.Path, "?"); index >= 0 && index+1 < len(req.Path) {
		values, errParse := url.ParseQuery(req.Path[index+1:])
		if errParse == nil {
			if mode := probeModeFromString(values.Get("network")); mode != "" {
				return mode
			}
			if mode := probeModeFromString(values.Get("mode")); mode != "" {
				return mode
			}
		}
	}
	return probeModeDirect
}

func diagnosticsPayload(kind string, mode probeMode) any {
	switch kind {
	case "runtime":
		hostname, _ := os.Hostname()
		tzName, tzUTC := localTimezone()
		proxy := collectProxyInfo()
		return map[string]any{
			"runtime":   runtimeInfo{Hostname: hostname, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, PID: os.Getpid(), TimezoneName: tzName, TimezoneUTC: tzUTC},
			"local_ips": collectLocalIPs(),
			"proxy":     proxy,
		}
	case "proxy":
		return collectProxyInfo()
	case "egress":
		directPublicIP := detectPublicIPFor(probeModeDirect)
		hostPublicIP := publicIPResult{}
		if hostHTTPAvailable() {
			hostPublicIP = detectPublicIPFor(probeModeHost)
		}
		return compareEgress(directPublicIP, hostPublicIP, mode)
	case "public-ip":
		return detectPublicIPFor(mode)
	case "ip-risk":
		publicIP := detectPublicIPFor(mode)
		payload := map[string]any{"public_ip": publicIP, "ip_risk": ipRiskProfile{}}
		if publicIP.IP != "" {
			payload["ip_risk"] = detectIPRiskFor(mode, publicIP.IP)
		}
		return payload
	case "openai":
		return detectOpenAIAvailabilityFor(mode)
	case "geo":
		tzName, tzUTC := localTimezone()
		publicIP := detectPublicIPFor(mode)
		openAI := detectOpenAIAvailabilityFor(mode)
		return evaluateGeoConsistency(publicIP, openAI, tzName, tzUTC)
	case "dns":
		return checkDNS([]string{"chatgpt.com", "api.openai.com", "auth.openai.com", "cdn.openai.com"})
	case "connectivity":
		return checkConnectivityFor(mode)
	case "outbound":
		return detectOutboundSources([]string{"api.openai.com:443", "chatgpt.com:443", "1.1.1.1:443"})
	default:
		return cachedDiagnostics(mode)
	}
}

func cachedDiagnostics(mode probeMode) diagnostics {
	now := time.Now()
	diagnosticsCacheMu.Lock()
	for {
		if cache, ok := diagnosticsCacheData[mode]; ok && !cache.expires.IsZero() && now.Before(cache.expires) {
			cached := cache.data
			diagnosticsCacheMu.Unlock()
			return cached
		}
		if !diagnosticsCacheLoading {
			diagnosticsCacheLoading = true
			diagnosticsCacheMu.Unlock()

			data := collectDiagnosticsFor(mode)

			diagnosticsCacheMu.Lock()
			diagnosticsCacheData[mode] = diagnosticsCacheEntry{data: data, expires: time.Now().Add(30 * time.Second)}
			diagnosticsCacheLoading = false
			diagnosticsCacheCond.Broadcast()
			diagnosticsCacheMu.Unlock()
			return data
		}
		diagnosticsCacheCond.Wait()
		now = time.Now()
	}
}
