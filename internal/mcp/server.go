package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/secryn/secryn-cli/internal/client"
	secretservice "github.com/secryn/secryn-cli/internal/secrets"
)

const (
	ProtocolVersion       = "2025-11-25"
	ModernProtocolVersion = "2026-07-28"
	MaxInputFrame         = 1024 * 1024
	MaxOutputFrame        = 4 * 1024 * 1024
)

var legacyProtocolVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18", ProtocolVersion}

var supportedProtocolVersions = func() map[string]struct{} {
	versions := make(map[string]struct{}, len(legacyProtocolVersions))
	for _, version := range legacyProtocolVersions {
		versions[version] = struct{}{}
	}
	return versions
}()

type SecretProvider interface {
	List(context.Context, string) ([]client.Secret, error)
	Get(context.Context, string, string) (client.Secret, error)
	ListResources(context.Context, string, string) ([]secretservice.DecryptedResource, error)
	GetResourceByName(context.Context, string, string, string) (secretservice.DecryptedResource, error)
}

type Server struct {
	provider    SecretProvider
	vaultURI    string
	version     string
	diagnostics io.Writer

	mu          sync.Mutex
	era         string
	initialized bool
	ready       bool
	active      map[string]context.CancelFunc
	writeMu     sync.Mutex
	wg          sync.WaitGroup
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func New(provider SecretProvider, vaultURI, version string, diagnostics io.Writer) (*Server, error) {
	if provider == nil || vaultURI == "" {
		return nil, fmt.Errorf("MCP secret provider and vault URI are required")
	}
	if version == "" {
		version = "dev"
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	return &Server{provider: provider, vaultURI: vaultURI, version: version, diagnostics: diagnostics, active: make(map[string]context.CancelFunc)}, nil
}

// Serve processes newline-delimited JSON-RPC frames. stdout must be dedicated
// to this method; all diagnostics are written to the separate diagnostics sink.
func (s *Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if input == nil || output == nil {
		return fmt.Errorf("MCP input and output are required")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), MaxInputFrame)
	type scanResult struct {
		frame []byte
		err   error
		done  bool
	}
	results := make(chan scanResult)
	go func() {
		defer close(results)
		for scanner.Scan() {
			result := scanResult{frame: append([]byte(nil), scanner.Bytes()...)}
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
		result := scanResult{err: scanner.Err(), done: true}
		select {
		case results <- result:
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			s.cancelAll()
			s.wg.Wait()
			return ctx.Err()
		case result, ok := <-results:
			if !ok || result.done {
				if result.err != nil {
					s.writeError(output, nil, -32700, "Parse error")
					s.cancelAll()
					s.wg.Wait()
					return fmt.Errorf("read MCP frame: %w", result.err)
				}
				s.cancelAll()
				s.wg.Wait()
				return nil
			}
			if len(bytes.TrimSpace(result.frame)) == 0 {
				s.writeError(output, nil, -32700, "Parse error")
				continue
			}
			if err := s.accept(ctx, output, result.frame); err != nil {
				s.cancelAll()
				s.wg.Wait()
				return err
			}
		}
	}
}

func (s *Server) accept(parent context.Context, output io.Writer, frame []byte) error {
	var incoming request
	if err := json.Unmarshal(frame, &incoming); err != nil {
		if json.Valid(frame) {
			s.writeError(output, nil, -32600, "Invalid Request")
		} else {
			s.writeError(output, nil, -32700, "Parse error")
		}
		return nil
	}
	if incoming.JSONRPC != "2.0" || incoming.Method == "" || !validID(incoming.ID) {
		if len(incoming.ID) == 0 {
			return nil
		}
		s.writeError(output, responseID(incoming.ID), -32600, "Invalid Request")
		return nil
	}
	if len(incoming.ID) == 0 {
		modern, valid := s.validateNotification(incoming)
		if valid {
			s.handleNotification(incoming, modern)
		}
		return nil
	}
	modern, eraError := s.resolveEra(incoming)
	if eraError != nil {
		s.writeRPCError(output, responseID(incoming.ID), eraError)
		return nil
	}
	switch incoming.Method {
	case "server/discover":
		if !modern {
			s.writeError(output, incoming.ID, -32601, "Method not found")
			return nil
		}
		s.writeResult(output, incoming.ID, map[string]any{
			"supportedVersions": []string{ModernProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"instructions":      "Secrets and cryptographic resources are decrypted locally. Requested private material is plaintext and must be handled as sensitive data.",
		}, true)
	case "initialize":
		s.handleInitialize(output, incoming)
	case "tools/list":
		if !modern && !s.isReady() {
			s.writeError(output, incoming.ID, -32002, "Server not initialized")
			return nil
		}
		s.writeResult(output, incoming.ID, map[string]any{"tools": toolDefinitions()}, modern)
	case "tools/call":
		if !modern && !s.isReady() {
			s.writeError(output, incoming.ID, -32002, "Server not initialized")
			return nil
		}
		s.startToolCall(parent, output, incoming, modern)
	default:
		s.writeError(output, incoming.ID, -32601, "Method not found")
	}
	return nil
}

func (s *Server) validateNotification(incoming request) (modern, valid bool) {
	present, metadataValid, unsupported := modernRequestMetadata(incoming.Params)
	if unsupported || incoming.Method == "server/discover" {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.era {
	case "modern":
		if incoming.Method == "notifications/initialized" || !present || !metadataValid {
			return false, false
		}
		return true, true
	case "legacy":
		return false, !present
	default:
		// Notifications never select an era. Compatible notifications may be
		// handled, but only a request can pin the connection.
		if present {
			return true, metadataValid
		}
		return false, true
	}
}

// resolveEra validates 2026 per-request metadata and pins the stdio connection
// to one protocol era, so a peer cannot silently switch semantics midstream.
func (s *Server) resolveEra(incoming request) (bool, *rpcError) {
	present, valid, unsupported := modernRequestMetadata(incoming.Params)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.era {
	case "modern":
		if unsupported {
			return false, s.unsupportedProtocolVersionError()
		}
		if incoming.Method == "initialize" || incoming.Method == "notifications/initialized" {
			return false, &rpcError{Code: -32600, Message: "protocol era mismatch"}
		}
		if !present || !valid {
			return false, &rpcError{Code: -32600, Message: "missing or invalid modern protocol metadata"}
		}
		return true, nil
	case "legacy":
		if incoming.Method == "server/discover" || present {
			return false, &rpcError{Code: -32600, Message: "protocol era mismatch"}
		}
		return false, nil
	}
	if unsupported {
		return false, s.unsupportedProtocolVersionError()
	}

	if incoming.Method == "server/discover" {
		if !present || !valid {
			return false, &rpcError{Code: -32600, Message: "missing or invalid modern protocol metadata"}
		}
		s.era = "modern"
		return true, nil
	}
	if present {
		if !valid {
			return false, &rpcError{Code: -32600, Message: "missing or invalid modern protocol metadata"}
		}
		if incoming.Method == "initialize" || incoming.Method == "notifications/initialized" {
			return false, &rpcError{Code: -32600, Message: "protocol era mismatch"}
		}
		s.era = "modern"
		return true, nil
	}
	if incoming.Method != "initialize" {
		s.era = "legacy"
	}
	return false, nil
}

func (s *Server) unsupportedProtocolVersionError() *rpcError {
	return &rpcError{
		Code:    -32022,
		Message: "Unsupported protocol version",
		Data: map[string]any{
			"supportedVersions": []string{ModernProtocolVersion},
			"_meta":             map[string]any{"io.modelcontextprotocol/serverInfo": s.serverInfo()},
		},
	}
}

func modernRequestMetadata(raw json.RawMessage) (present, valid, unsupported bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, false, false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(raw, &params) != nil {
		return false, false, false
	}
	metaRaw, present := params["_meta"]
	if !present {
		return false, false, false
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(metaRaw, &meta) != nil {
		return true, false, false
	}
	var version string
	if json.Unmarshal(meta["io.modelcontextprotocol/protocolVersion"], &version) != nil || version == "" {
		return true, false, false
	}
	if version != ModernProtocolVersion {
		return true, false, true
	}
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(meta["io.modelcontextprotocol/clientCapabilities"], &capabilities) != nil || capabilities == nil {
		return true, false, false
	}
	if clientInfoRaw, ok := meta["io.modelcontextprotocol/clientInfo"]; ok {
		var clientInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(clientInfoRaw, &clientInfo) != nil || clientInfo.Name == "" || clientInfo.Version == "" {
			return true, false, false
		}
	}
	return true, true, false
}

func (s *Server) handleInitialize(output io.Writer, incoming request) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(incoming.Params) == 0 || json.Unmarshal(incoming.Params, &params) != nil {
		s.writeError(output, incoming.ID, -32602, "Invalid params")
		return
	}
	if _, supported := supportedProtocolVersions[params.ProtocolVersion]; !supported {
		s.writeRPCError(output, incoming.ID, &rpcError{
			Code:    -32022,
			Message: "Unsupported protocol version",
			Data:    map[string]any{"supportedVersions": legacyProtocolVersions},
		})
		return
	}
	s.mu.Lock()
	if s.era == "modern" || s.initialized {
		s.mu.Unlock()
		s.writeError(output, incoming.ID, -32600, "Already initialized")
		return
	}
	s.initialized = true
	s.era = "legacy"
	s.mu.Unlock()
	s.writeResult(output, incoming.ID, map[string]any{
		"protocolVersion": params.ProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "secryn", "version": s.version},
		"instructions":    "Secrets are decrypted locally. Tool results containing values are plaintext and must be handled as sensitive data.",
	}, false)
}

func (s *Server) handleNotification(incoming request, modern bool) {
	switch incoming.Method {
	case "notifications/initialized":
		if modern {
			return
		}
		s.mu.Lock()
		if s.initialized {
			s.ready = true
		}
		s.mu.Unlock()
	case "notifications/cancelled":
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(incoming.Params, &params) != nil || !validID(params.RequestID) || len(params.RequestID) == 0 {
			return
		}
		s.mu.Lock()
		cancel := s.active[string(params.RequestID)]
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

func (s *Server) startToolCall(parent context.Context, output io.Writer, incoming request, modern bool) {
	key := string(incoming.ID)
	callCtx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	if _, duplicate := s.active[key]; duplicate {
		s.mu.Unlock()
		cancel()
		s.writeError(output, incoming.ID, -32600, "Duplicate request ID")
		return
	}
	s.active[key] = cancel
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer func() {
			s.mu.Lock()
			delete(s.active, key)
			s.mu.Unlock()
		}()
		result, protocolError := s.callTool(callCtx, incoming.Params)
		if errors.Is(callCtx.Err(), context.Canceled) {
			return
		}
		if protocolError != nil {
			s.writeError(output, incoming.ID, protocolError.Code, protocolError.Message)
			return
		}
		s.writeResult(output, incoming.ID, result, modern)
	}()
}

func (s *Server) callTool(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &params) != nil || params.Name == "" {
		return nil, &rpcError{Code: -32602, Message: "Invalid params"}
	}
	switch params.Name {
	case "secryn_secret_list":
		if !emptyArguments(params.Arguments) {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		items, err := s.provider.List(ctx, s.vaultURI)
		if err != nil {
			s.diagnostic("secryn_secret_list failed")
			return toolFailure("Secret listing failed."), nil
		}
		values := make([]map[string]string, 0, len(items))
		for _, item := range items {
			values = append(values, map[string]string{"name": item.Name, "updated_at": item.UpdatedAt})
		}
		return toolSuccess(values)
	case "secryn_secret_get":
		var arguments struct {
			Name string `json:"name"`
		}
		var argumentFields map[string]json.RawMessage
		if len(params.Arguments) == 0 || json.Unmarshal(params.Arguments, &argumentFields) != nil || len(argumentFields) != 1 ||
			json.Unmarshal(params.Arguments, &arguments) != nil ||
			arguments.Name == "" || len(arguments.Name) > 1024 || !utf8.ValidString(arguments.Name) {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		item, err := s.provider.Get(ctx, s.vaultURI, arguments.Name)
		if err != nil {
			s.diagnostic("secryn_secret_get failed")
			return toolFailure("Secret retrieval failed."), nil
		}
		return toolSuccess(item)
	case "secryn_key_list", "secryn_certificate_list":
		if !emptyArguments(params.Arguments) {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		resourceType := "key"
		if params.Name == "secryn_certificate_list" {
			resourceType = "certificate"
		}
		items, err := s.provider.ListResources(ctx, s.vaultURI, resourceType)
		if err != nil {
			s.diagnostic(params.Name + " failed")
			return toolFailure("Resource listing failed."), nil
		}
		values := make([]map[string]string, 0, len(items))
		for _, item := range items {
			values = append(values, map[string]string{"name": item.Name, "updated_at": item.UpdatedAt})
		}
		return toolSuccess(values)
	case "secryn_key_get":
		var arguments struct {
			Name           string `json:"name"`
			Format         string `json:"format"`
			IncludePrivate bool   `json:"include_private"`
		}
		if !validArguments(params.Arguments, []string{"name", "format", "include_private"}, &arguments) ||
			arguments.Name == "" || len(arguments.Name) > 1024 || !utf8.ValidString(arguments.Name) ||
			(arguments.Format != "" && arguments.Format != "pem" && arguments.Format != "ssh") {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		if arguments.Format == "" {
			arguments.Format = "pem"
		}
		item, err := s.provider.GetResourceByName(ctx, s.vaultURI, "key", arguments.Name)
		if err != nil {
			s.diagnostic("secryn_key_get failed")
			return toolFailure("Key retrieval failed."), nil
		}
		material := selectMCPKeyMaterial(item.Material, arguments.Format, arguments.IncludePrivate)
		if material == "" {
			return toolFailure("Requested key material is unavailable."), nil
		}
		return toolSuccess(map[string]any{"name": item.Name, "format": arguments.Format, "material": material, "private": arguments.IncludePrivate})
	case "secryn_certificate_get":
		var arguments struct {
			Name           string `json:"name"`
			IncludePrivate bool   `json:"include_private"`
		}
		if !validArguments(params.Arguments, []string{"name", "include_private"}, &arguments) ||
			arguments.Name == "" || len(arguments.Name) > 1024 || !utf8.ValidString(arguments.Name) {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		item, err := s.provider.GetResourceByName(ctx, s.vaultURI, "certificate", arguments.Name)
		if err != nil {
			s.diagnostic("secryn_certificate_get failed")
			return toolFailure("Certificate retrieval failed."), nil
		}
		value := map[string]any{"name": item.Name, "certificatePem": item.CertificatePEM}
		if arguments.IncludePrivate {
			if item.PrivateKeyPEM == "" {
				return toolFailure("Certificate private key material is unavailable."), nil
			}
			value["privateKeyPem"] = item.PrivateKeyPEM
		}
		return toolSuccess(value)
	default:
		return nil, &rpcError{Code: -32602, Message: "Unknown tool"}
	}
}

func toolSuccess(value any) (any, *rpcError) {
	payload, err := json.Marshal(value)
	if err != nil {
		return toolFailure("Tool result exceeds the local MCP output limit."), nil
	}
	return map[string]any{"content": []content{{Type: "text", Text: string(payload)}}, "isError": false}, nil
}

func toolFailure(message string) map[string]any {
	return map[string]any{"content": []content{{Type: "text", Text: message}}, "isError": true}
}

func toolDefinitions() []map[string]any {
	annotations := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	return []map[string]any{
		{
			"name": "secryn_secret_list", "description": "List decrypted secret names and update timestamps from the configured Secryn E2EE vault. Values are not returned.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "annotations": annotations,
		},
		{
			"name": "secryn_secret_get", "description": "Retrieve one secret by exact case-sensitive name. The returned tool content contains plaintext secret material.",
			"inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024}},
				"required": []string{"name"}, "additionalProperties": false,
			}, "annotations": annotations,
		},
		{
			"name": "secryn_key_list", "description": "List decrypted key names and update timestamps from the configured Secryn E2EE vault. Key material is not returned.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "annotations": annotations,
		},
		{
			"name": "secryn_key_get", "description": "Retrieve public key material by exact name. Set include_private=true explicitly to request private material.",
			"inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{
					"name":            map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
					"format":          map[string]any{"type": "string", "enum": []string{"pem", "ssh"}, "default": "pem"},
					"include_private": map[string]any{"type": "boolean", "default": false},
				}, "required": []string{"name"}, "additionalProperties": false,
			}, "annotations": annotations,
		},
		{
			"name": "secryn_certificate_list", "description": "List decrypted certificate names and update timestamps. Certificate material is not returned.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "annotations": annotations,
		},
		{
			"name": "secryn_certificate_get", "description": "Retrieve a certificate by exact name. Set include_private=true explicitly to include its private key.",
			"inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{
					"name":            map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
					"include_private": map[string]any{"type": "boolean", "default": false},
				}, "required": []string{"name"}, "additionalProperties": false,
			}, "annotations": annotations,
		},
	}
}

func validArguments(raw json.RawMessage, allowed []string, destination any) bool {
	if len(raw) == 0 || json.Unmarshal(raw, destination) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range fields {
		if _, ok := allowedSet[name]; !ok {
			return false
		}
	}
	return true
}

func selectMCPKeyMaterial(material *secretservice.KeyMaterial, format string, includePrivate bool) string {
	if material == nil {
		return ""
	}
	if format == "pem" {
		if includePrivate {
			return material.PEMPrivate
		}
		return material.PEMPublic
	}
	if includePrivate {
		return material.OpenSSHPrivate
	}
	return material.OpenSSHPublic
}

func (s *Server) isReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

func (s *Server) cancelAll() {
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.active))
	for _, cancel := range s.active {
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *Server) writeResult(output io.Writer, id json.RawMessage, result any, modern bool) {
	if modern {
		if mapped, ok := result.(map[string]any); ok {
			mapped["resultType"] = "complete"
			mapped["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": s.serverInfo()}
			result = mapped
		}
	}
	s.write(output, response{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) writeError(output io.Writer, id json.RawMessage, code int, message string) {
	s.writeRPCError(output, id, &rpcError{Code: code, Message: message})
}

func (s *Server) writeRPCError(output io.Writer, id json.RawMessage, rpcErr *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	s.mu.Lock()
	if s.era == "modern" {
		data, ok := rpcErr.Data.(map[string]any)
		if !ok {
			data = make(map[string]any)
		}
		data["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": s.serverInfo()}
		rpcErr.Data = data
	}
	s.mu.Unlock()
	s.write(output, response{JSONRPC: "2.0", ID: id, Error: rpcErr})
}

func (s *Server) serverInfo() map[string]any {
	return map[string]any{"name": "secryn", "version": s.version}
}

func (s *Server) write(output io.Writer, value response) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload)+1 > MaxOutputFrame {
		value = response{JSONRPC: "2.0", ID: value.ID, Error: &rpcError{Code: -32001, Message: "Response exceeds the local MCP output limit"}}
		s.mu.Lock()
		if s.era == "modern" {
			value.Error.Data = map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": s.serverInfo()}}
		}
		s.mu.Unlock()
		payload, err = json.Marshal(value)
		if err != nil || len(payload)+1 > MaxOutputFrame {
			return
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = output.Write(append(payload, '\n'))
}

func (s *Server) diagnostic(message string) {
	_, _ = fmt.Fprintln(s.diagnostics, "MCP:", message)
}

func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	var value any
	if json.Unmarshal(id, &value) != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func responseID(id json.RawMessage) json.RawMessage {
	if validID(id) && len(id) > 0 {
		return id
	}
	return nil
}

func emptyArguments(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && len(value) == 0
}
