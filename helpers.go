package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	return truncateRunes(text, 500)
}

func truncateRunes(text string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max]) + "..."
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

func distinctIPsByFamily(checks []publicIPEndpoint) ([]string, []string) {
	seen4 := make(map[string]struct{})
	seen6 := make(map[string]struct{})
	ipv4 := make([]string, 0)
	ipv6 := make([]string, 0)
	for _, check := range checks {
		parsed := net.ParseIP(strings.TrimSpace(check.IP))
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			key := parsed.String()
			if _, ok := seen4[key]; ok {
				continue
			}
			seen4[key] = struct{}{}
			ipv4 = append(ipv4, key)
			continue
		}
		key := parsed.String()
		if _, ok := seen6[key]; ok {
			continue
		}
		seen6[key] = struct{}{}
		ipv6 = append(ipv6, key)
	}
	return ipv4, ipv6
}
