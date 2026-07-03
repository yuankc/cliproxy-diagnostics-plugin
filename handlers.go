package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	diagnosticsCacheMu   sync.Mutex
	diagnosticsCacheData = make(map[probeMode]*diagnosticsCacheEntry)
)

type diagnosticsCacheEntry struct {
	data    diagnostics
	expires time.Time
	loading bool
	cond    *sync.Cond
}

func handleMethod(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(registrationPayload())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(pluginapi.ManagementRegistrationResponse{
			Routes: []pluginapi.ManagementRoute{
				{Method: http.MethodGet, Path: "/diagnostics/status", Description: "Returns CPA process network check results as JSON."},
				{Method: http.MethodGet, Path: "/diagnostics/status/runtime", Description: "Returns runtime, local IP, and proxy check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/proxy", Description: "Returns proxy environment check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/egress", Description: "Returns direct vs host egress check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/public-ip", Description: "Returns public IP check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/ip-risk", Description: "Returns IP reputation check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/openai", Description: "Returns OpenAI availability check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/geo", Description: "Returns geographic consistency check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/dns", Description: "Returns DNS check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/connectivity", Description: "Returns HTTP connectivity check results."},
				{Method: http.MethodGet, Path: "/diagnostics/status/outbound", Description: "Returns outbound source address check results."},
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
		return diagnosticsJSONResponse(kind, probeModeFromRequest(req), isResourceRequest(req.Path))
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

func diagnosticsJSONResponse(kind string, mode probeMode, public bool) pluginapi.ManagementResponse {
	payload := diagnosticsPayload(kind, mode)
	if public {
		payload = redactDiagnosticsPayload(kind, payload)
	}
	body, errMarshal := json.MarshalIndent(payload, "", "  ")
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

func isResourceRequest(path string) bool {
	if index := strings.Index(path, "?"); index >= 0 {
		path = path[:index]
	}
	cleaned := "/" + strings.Trim(strings.TrimSuffix(path, "/"), "/")
	return strings.HasPrefix(cleaned, "/v0/resource/plugins/") || strings.HasPrefix(cleaned, "/plugins/")
}

func isStatusPath(path string) bool {
	return statusPathKind(path) != ""
}

func statusPathKind(path string) string {
	if index := strings.Index(path, "?"); index >= 0 {
		path = path[:index]
	}
	cleaned := "/" + strings.Trim(strings.TrimSuffix(path, "/"), "/")
	bases := []string{
		"/status",
		"/diagnostics/status",
		"/" + pluginStoreID + "/status",
		"/v0/management/diagnostics/status",
		"/v0/management/" + pluginStoreID + "/status",
		"/v0/resource/plugins/diagnostics/status",
		"/v0/resource/plugins/" + pluginStoreID + "/status",
	}
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
	data := cachedDiagnostics(mode)
	switch kind {
	case "runtime":
		return map[string]any{
			"runtime":   data.Runtime,
			"local_ips": data.LocalIPs,
			"proxy":     data.Proxy,
		}
	case "proxy":
		return data.Proxy
	case "egress":
		return data.Egress
	case "public-ip":
		return data.PublicIP
	case "ip-risk":
		return map[string]any{"public_ip": data.PublicIP, "ip_risk": data.IPRisk}
	case "openai":
		return data.OpenAI
	case "geo":
		return data.Geo
	case "dns":
		return data.DNS
	case "connectivity":
		return data.Connectivity
	case "outbound":
		return data.OutboundSources
	default:
		return data
	}
}

func cachedDiagnostics(mode probeMode) diagnostics {
	now := time.Now()
	diagnosticsCacheMu.Lock()
	for {
		cache := diagnosticsCacheData[mode]
		if cache == nil {
			cache = &diagnosticsCacheEntry{}
			cache.cond = sync.NewCond(&diagnosticsCacheMu)
			diagnosticsCacheData[mode] = cache
		}
		if !cache.expires.IsZero() && now.Before(cache.expires) {
			cached := cache.data
			diagnosticsCacheMu.Unlock()
			return cached
		}
		if !cache.loading {
			cache.loading = true
			diagnosticsCacheMu.Unlock()

			data := collectDiagnosticsFor(mode)

			diagnosticsCacheMu.Lock()
			cache.data = data
			cache.expires = time.Now().Add(30 * time.Second)
			cache.loading = false
			cache.cond.Broadcast()
			diagnosticsCacheMu.Unlock()
			return data
		}
		cache.cond.Wait()
		now = time.Now()
	}
}

func redactDiagnosticsPayload(kind string, payload any) any {
	switch value := payload.(type) {
	case diagnostics:
		return redactDiagnostics(value)
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			switch key {
			case "runtime":
				if runtimeValue, ok := item.(runtimeInfo); ok {
					out[key] = redactRuntimeInfo(runtimeValue)
				} else {
					out[key] = item
				}
			case "local_ips":
				out[key] = []localIP{}
			case "proxy":
				if proxyValue, ok := item.(proxyInfo); ok {
					out[key] = redactProxyInfo(proxyValue)
				} else {
					out[key] = item
				}
			case "public_ip":
				if publicIP, ok := item.(publicIPResult); ok {
					out[key] = redactPublicIPResult(publicIP)
				} else {
					out[key] = item
				}
			case "ip_risk":
				if risk, ok := item.(ipRiskProfile); ok {
					out[key] = redactIPRiskProfile(risk)
				} else {
					out[key] = item
				}
			default:
				out[key] = item
			}
		}
		return out
	case runtimeInfo:
		return redactRuntimeInfo(value)
	case proxyInfo:
		return redactProxyInfo(value)
	case egressComparison:
		return redactEgressComparison(value)
	case publicIPResult:
		return redactPublicIPResult(value)
	case ipRiskProfile:
		return redactIPRiskProfile(value)
	case openAIAvailability:
		return redactOpenAIAvailability(value)
	case geoConsistency:
		return redactGeoConsistency(value)
	case []outboundSource:
		return redactOutboundSources(value)
	default:
		_ = kind
		return payload
	}
}

func redactDiagnostics(data diagnostics) diagnostics {
	data.Runtime = redactRuntimeInfo(data.Runtime)
	data.Proxy = redactProxyInfo(data.Proxy)
	data.Egress = redactEgressComparison(data.Egress)
	data.LocalIPs = nil
	data.OutboundSources = redactOutboundSources(data.OutboundSources)
	data.PublicIP = redactPublicIPResult(data.PublicIP)
	data.IPRisk = redactIPRiskProfile(data.IPRisk)
	data.OpenAI = redactOpenAIAvailability(data.OpenAI)
	data.Geo = redactGeoConsistency(data.Geo)
	return data
}

func redactRuntimeInfo(info runtimeInfo) runtimeInfo {
	info.Hostname = ""
	info.PID = 0
	return info
}

func redactProxyInfo(info proxyInfo) proxyInfo {
	for index := range info.Variables {
		info.Variables[index].Value = ""
	}
	if info.Detected {
		info.Note = "检测到代理环境变量；公开资源接口已隐藏具体变量值。"
	}
	return info
}

func redactEgressComparison(egress egressComparison) egressComparison {
	egress.Direct = redactPublicIPResult(egress.Direct)
	egress.Host = redactPublicIPResult(egress.Host)
	return egress
}

func redactPublicIPResult(result publicIPResult) publicIPResult {
	for index := range result.Checks {
		result.Checks[index].Error = ""
	}
	return result
}

func redactIPRiskProfile(profile ipRiskProfile) ipRiskProfile {
	for index := range profile.Checks {
		profile.Checks[index].Error = ""
	}
	return profile
}

func redactOpenAIAvailability(openAI openAIAvailability) openAIAvailability {
	openAI.CFIP = ""
	openAI.ComplianceBody = ""
	return openAI
}

func redactGeoConsistency(geo geoConsistency) geoConsistency {
	return geo
}

func redactOutboundSources(items []outboundSource) []outboundSource {
	out := make([]outboundSource, len(items))
	for index, item := range items {
		item.LocalIP = ""
		out[index] = item
	}
	return out
}
