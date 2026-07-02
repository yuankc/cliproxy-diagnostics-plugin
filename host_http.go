package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

var errHostUnavailable = errors.New("host HTTP callback is unavailable")

type hostHTTPRequest struct {
	Method  string      `json:"method,omitempty"`
	URL     string      `json:"url,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
	Body    []byte      `json:"body,omitempty"`
}

type hostHTTPResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers,omitempty"`
	Body       []byte      `json:"Body,omitempty"`
}

func hostHTTPDo(ctx context.Context, req hostHTTPRequest) (hostHTTPResponse, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return hostHTTPResponse{}, ctx.Err()
		default:
		}
	}
	rawReq, errMarshal := json.Marshal(req)
	if errMarshal != nil {
		return hostHTTPResponse{}, errMarshal
	}
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		rawResp, errCall := callHost(pluginabi.MethodHostHTTPDo, rawReq)
		done <- result{raw: rawResp, err: errCall}
	}()
	var res result
	if ctx == nil {
		res = <-done
	} else {
		select {
		case <-ctx.Done():
			return hostHTTPResponse{}, ctx.Err()
		case res = <-done:
		}
	}
	if res.err != nil {
		return hostHTTPResponse{}, res.err
	}
	return decodeHostEnvelope[hostHTTPResponse](res.raw)
}

func decodeHostEnvelope[T any](raw []byte) (T, error) {
	var zero T
	var envelope pluginabi.Envelope
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		return zero, fmt.Errorf("decode host envelope: %w", errUnmarshal)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return zero, fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return zero, errors.New("host callback failed")
	}
	if len(envelope.Result) == 0 {
		return zero, nil
	}
	var out T
	if errUnmarshal := json.Unmarshal(envelope.Result, &out); errUnmarshal != nil {
		return zero, fmt.Errorf("decode host result: %w", errUnmarshal)
	}
	return out, nil
}
