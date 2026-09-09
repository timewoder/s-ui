package core

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/alireza0/s-ui/database/model"

	"github.com/sagernet/sing-box/option"
)

// TestEndpointDefaults builds one endpoint of every type the panel UI can
// create. Unlike inbounds, the OpenConnect and OpenVPN endpoints need details
// only the operator has (a server to dial, certificate paths), so the cases
// below add exactly those and nothing else. Anything a case has to add beyond
// the UI defaults is a field the UI must expose, which is what this guards.
func TestEndpointDefaults(t *testing.T) {
	certPath, keyPath := writeTestCert(t)

	testCases := []struct {
		name    string
		options map[string]any
	}{
		{name: "wireguard", options: map[string]any{
			"type": "wireguard", "address": []string{"10.0.0.2/32"},
			"private_key": "8I9OMDoO5jlvbSraQFxIvUAoluHrM8izP+xuBuT9jFg=",
			"listen_port": 43201, "peers": []any{}}},
		{name: "tailscale", options: map[string]any{
			"type": "tailscale", "state_directory": t.TempDir()}},
		// operator supplies: server
		{name: "openconnect", options: map[string]any{
			"type": "openconnect", "server": "vpn.example.com", "flavor": "anyconnect"}},
		// operator supplies: server, and a tls block (an empty one reads as absent)
		{name: "openvpn-client", options: map[string]any{
			"type": "openvpn-client", "server": "vpn.example.com", "server_port": 1194,
			"mode": "tls", "network": "udp",
			"tls": map[string]any{"certificate_path": certPath}}},
		// static_key mode has no TLS session to negotiate over, so the client
		// carries its own tunnel address, the peer's, and a cipher. It has to
		// be a CBC one: GCM needs the TLS key exchange for IV uniqueness.
		{name: "openvpn-client-static-key", options: map[string]any{
			"type": "openvpn-client", "server": "vpn.example.com", "server_port": 1194,
			"mode": "static_key", "network": "udp", "address": []string{"10.8.0.2/24"},
			"peer_address": "10.8.0.1", "static_key_path": keyPath, "cipher": "AES-256-CBC"}},
		// operator supplies: certificate and key paths
		{name: "openvpn-server", options: map[string]any{
			"type": "openvpn-server", "listen": "127.0.0.1", "listen_port": 43202,
			"mode": "tls", "network": "udp", "address": []string{"10.8.0.1/24"},
			"tls": map[string]any{"certificate_path": certPath, "key_path": keyPath}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint := map[string]any{"tag": testCase.name + "-ep"}
			for key, value := range testCase.options {
				endpoint[key] = value
			}
			raw, err := json.Marshal(map[string]any{
				"log":       map[string]any{"level": "error"},
				"endpoints": []any{endpoint},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx := Context(context.Background(), InboundRegistry(), OutboundRegistry(),
				EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
			var options option.Options
			if err = options.UnmarshalJSONContext(ctx, raw); err != nil {
				t.Fatalf("parse: %v", err)
			}
			instance, err := NewBox(Options{Context: ctx, Options: options})
			skipIfFeatureMissing(t, err)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			instance.Close()
		})
	}
}

// TestEndpointInlineTLS builds the TLS-bearing endpoints from the `tls` object
// the panel UI now writes, in sing-box's own field names. It covers the shapes
// the OpenVPN and OpenConnect forms produce, control_wrap among them, which is
// the setting a shared panel TLS config could never express (#1253).
func TestEndpointInlineTLS(t *testing.T) {
	certPath, keyPath := writeTestCert(t)
	quotedCert, quotedKey := strconv.Quote(certPath), strconv.Quote(keyPath)

	testCases := []struct {
		name     string
		endpoint model.Endpoint
	}{
		// The server presents `certificate`/`key` and verifies clients against
		// `client_certificate`, which is the opposite of what those two names
		// mean on the client below.
		{name: "openvpn-server", endpoint: model.Endpoint{
			Type: "openvpn-server", Tag: "ovs-tls",
			Options: json.RawMessage(`{"listen":"127.0.0.1","listen_port":44101,"mode":"tls","network":"udp","address":["10.8.0.1/24"],
				"tls":{"certificate_path":` + quotedCert + `,"key_path":` + quotedKey + `}}`),
		}},
		{name: "openvpn-server-mtls", endpoint: model.Endpoint{
			Type: "openvpn-server", Tag: "ovs-mtls",
			Options: json.RawMessage(`{"listen":"127.0.0.1","listen_port":44102,"mode":"tls","network":"udp","address":["10.8.0.1/24"],
				"tls":{"certificate_path":` + quotedCert + `,"key_path":` + quotedKey + `,
					"client_certificate_path":` + quotedCert + `,"verify_client_certificate":"require"}}`),
		}},
		// tls-crypt wraps the control channel in a pre-shared key. Nearly every
		// real deployment uses one.
		{name: "openvpn-server-control-wrap", endpoint: model.Endpoint{
			Type: "openvpn-server", Tag: "ovs-wrap",
			Options: json.RawMessage(`{"listen":"127.0.0.1","listen_port":44103,"mode":"tls","network":"udp","address":["10.8.0.1/24"],
				"tls":{"certificate_path":` + quotedCert + `,"key_path":` + quotedKey + `,
					"control_wrap":{"type":"tls_crypt","key_path":` + quotedKey + `}}}`),
		}},
		// On the client `certificate` is the CA it checks the server against.
		{name: "openvpn-client", endpoint: model.Endpoint{
			Type: "openvpn-client", Tag: "ovc-tls",
			Options: json.RawMessage(`{"server":"vpn.example.com","server_port":1194,"mode":"tls","network":"udp",
				"tls":{"certificate_path":` + quotedCert + `,"version_min":"1.2"}}`),
		}},
		{name: "openvpn-client-mtls", endpoint: model.Endpoint{
			Type: "openvpn-client", Tag: "ovc-mtls",
			Options: json.RawMessage(`{"server":"vpn.example.com","server_port":1194,"mode":"tls","network":"udp",
				"tls":{"certificate_path":` + quotedCert + `,"client_certificate_path":` + quotedCert + `,
					"client_key_path":` + quotedKey + `,"remote_certificate_tls":"server"}}`),
		}},
		// A peer fingerprint stands in for a certificate authority.
		{name: "openvpn-client-fingerprint", endpoint: model.Endpoint{
			Type: "openvpn-client", Tag: "ovc-pin",
			Options: json.RawMessage(`{"server":"vpn.example.com","server_port":1194,"mode":"tls","network":"udp",
				"tls":{"peer_fingerprint":["030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"]}}`),
		}},
		// OpenConnect names the trust anchor after its role.
		{name: "openconnect", endpoint: model.Endpoint{
			Type: "openconnect", Tag: "oc-tls",
			Options: json.RawMessage(`{"server":"vpn.example.com","flavor":"anyconnect",
				"tls":{"certificate_authority_path":` + quotedCert + `,"server_name":"vpn.example.com"}}`),
		}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			endpointJSON, err := testCase.endpoint.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]any{
				"log":       map[string]any{"level": "error"},
				"endpoints": []any{json.RawMessage(endpointJSON)},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx := Context(context.Background(), InboundRegistry(), OutboundRegistry(),
				EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
			var options option.Options
			if err = options.UnmarshalJSONContext(ctx, raw); err != nil {
				t.Fatalf("parse (endpoint was %s): %v", endpointJSON, err)
			}
			instance, err := NewBox(Options{Context: ctx, Options: options})
			skipIfFeatureMissing(t, err)
			if err != nil {
				t.Fatalf("build (endpoint was %s): %v", endpointJSON, err)
			}
			instance.Close()
		})
	}
}
