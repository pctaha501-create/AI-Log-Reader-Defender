package ingest

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

var jsonRecordKeys = []string{"events", "records", "logs", "items", "results", "data"}

func readStructuredJSON(data []byte) ([]model.Event, bool, error) {
	var document any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&document); err != nil { return nil, false, nil }
	records := jsonRecords(document)
	if len(records) == 0 { return nil, false, nil }
	events := make([]model.Event, 0, len(records))
	for i, record := range records {
		object, ok := record.(map[string]any)
		if !ok {
			raw := map[string]any{"source": "json-structured", "message": fmt.Sprint(record), "raw_record": record, "record_index": i}
			events = append(events, normalize(raw))
			continue
		}
		raw := map[string]any{"source": "json-structured", "raw_record": object}
		flattenJSON(raw, "", object)
		applyCommonAliases(raw)
		events = append(events, normalize(raw))
	}
	return events, true, nil
}

func jsonRecords(value any) []any {
	switch v := value.(type) {
	case []any: return v
	case map[string]any:
		for _, key := range jsonRecordKeys {
			if child, ok := v[key]; ok {
				if records := jsonRecords(child); len(records) > 0 { return records }
			}
		}
		return []any{v}
	default: return nil
	}
}

func flattenJSON(dst map[string]any, prefix string, value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			name := strings.ToLower(strings.TrimSpace(key))
			if name == "" { continue }
			path := name
			if prefix != "" { path = prefix + "." + name }
			flattenJSON(dst, path, child)
			if _, exists := dst[name]; !exists {
				if scalar, ok := scalarValue(child); ok { dst[name] = scalar }
			}
		}
	case []any:
		if prefix != "" {
			encoded, _ := json.Marshal(v)
			if _, exists := dst[prefix]; !exists { dst[prefix] = string(encoded) }
		}
	default:
		if prefix != "" {
			if scalar, ok := scalarValue(v); ok { dst[prefix] = scalar }
		}
	}
}

func scalarValue(v any) (any, bool) {
	switch v.(type) {
	case nil, map[string]any, []any: return nil, false
	default: return v, true
	}
}

func applyCommonAliases(raw map[string]any) {
	aliases := map[string][]string{
		"timestamp": {"timecreated.systemtime", "system.timecreated.systemtime", "systemtime", "timecreated", "datetime", "event_time", "eventtime", "generated", "created_at", "occurred_at"},
		"event_id": {"eventid", "event_code", "eventcode", "signature_id", "signatureid", "logid"},
		"provider": {"provider.name", "providername", "source_name", "sourcename", "service", "application"},
		"host": {"computer", "hostname", "device_name", "devicename", "observer.name"},
		"user": {"username", "account_name", "accountname", "subjectusername", "targetusername", "principal"},
		"source_ip": {"src_ip", "srcip", "sourceip", "remoteaddress", "client_ip", "clientip", "ipaddress"},
		"destination_ip": {"dst_ip", "dstip", "destinationip", "remote_ip", "server_ip"},
		"message": {"eventmessage", "rendereddescription", "description", "msg", "message_text", "event_description"},
		"level": {"severity", "priority", "log_level", "loglevel", "levelname"},
	}
	for target, keys := range aliases {
		if strings.TrimSpace(str(raw[target])) != "" { continue }
		for _, key := range keys {
			if value := raw[key]; value != nil && strings.TrimSpace(str(value)) != "" { raw[target] = value; break }
		}
	}
}

type xmlLogNode struct {
	Name string
	Attrs map[string]string
	Text string
	Children []xmlLogNode
}

func readStructuredXML(data []byte) ([]model.Event, bool, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var root xmlLogNode
	for {
		token, err := dec.Token()
		if err == io.EOF { return nil, false, nil }
		if err != nil { return nil, false, fmt.Errorf("parse XML log: %w", err) }
		if start, ok := token.(xml.StartElement); ok {
			root, err = decodeXMLNode(dec, start)
			if err != nil { return nil, false, fmt.Errorf("parse XML log: %w", err) }
			break
		}
	}
	records := collectXMLRecords(root)
	if len(records) == 0 { records = []xmlLogNode{root} }
	events := make([]model.Event, 0, len(records))
	for i, record := range records {
		raw := map[string]any{"source": "xml-structured", "record_index": i, "raw_xml_element": record.Name}
		flattenXML(raw, "", record)
		applyCommonAliases(raw)
		events = append(events, normalize(raw))
	}
	return events, true, nil
}

func decodeXMLNode(dec *xml.Decoder, start xml.StartElement) (xmlLogNode, error) {
	node := xmlLogNode{Name: start.Name.Local, Attrs: map[string]string{}}
	for _, attr := range start.Attr { node.Attrs[strings.ToLower(attr.Name.Local)] = attr.Value }
	if strings.EqualFold(node.Name, "Data") && node.Attrs["name"] != "" {
		node.Name = node.Attrs["name"]
	}
	if strings.EqualFold(node.Name, "Provider") && node.Attrs["name"] != "" {
		node.Attrs["provider"] = node.Attrs["name"]
	}
	for {
		token, err := dec.Token()
		if err != nil { return node, err }
		switch value := token.(type) {
		case xml.StartElement:
			child, err := decodeXMLNode(dec, value)
			if err != nil { return node, err }
			node.Children = append(node.Children, child)
		case xml.CharData:
			node.Text += string(value)
		case xml.EndElement:
			return node, nil
		}
	}
}

func collectXMLRecords(node xmlLogNode) []xmlLogNode {
	switch strings.ToLower(node.Name) {
	case "event", "record", "entry", "log", "auditrecord", "securityevent": return []xmlLogNode{node}
	}
	var records []xmlLogNode
	for _, child := range node.Children { records = append(records, collectXMLRecords(child)...)}
	if len(records) > 0 { return records }
	if len(node.Children) > 0 { return node.Children }
	return []xmlLogNode{node}
}

func flattenXML(dst map[string]any, prefix string, node xmlLogNode) {
	path := strings.ToLower(node.Name)
	if prefix != "" { path = prefix + "." + path }
	for key, value := range node.Attrs {
		name := path + "." + key
		dst[name] = value
		if _, exists := dst[key]; !exists { dst[key] = value }
	}
	text := strings.TrimSpace(node.Text)
	if text != "" {
		dst[path] = text
		if _, exists := dst[strings.ToLower(node.Name)]; !exists { dst[strings.ToLower(node.Name)] = text }
	}
	for _, child := range node.Children { flattenXML(dst, path, child) }
}
