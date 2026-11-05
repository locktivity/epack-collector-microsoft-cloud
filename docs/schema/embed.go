// Package schema embeds the JSON Schemas of the collector's detailed
// artifacts, the methods for its normalized artifacts, and its trace map.
package schema

import (
	_ "embed"
	"encoding/json"
)

//go:embed microsoft-cloud.entra.v1.0.0.json
var entra []byte

//go:embed microsoft-cloud.azure.v1.0.0.json
var azure []byte

// methods is methods.json: for each normalized schema ID, the fields the
// collector writes that the detailed artifacts do not hold as they are, each
// with one plain sentence on how the collector measures it.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps each detailed artifact's schema ID to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. The normalized artifacts are checked
// against the SDK's own schemas for their types.
func Schemas(entraSchema, azureSchema string) map[string][]byte {
	return map[string][]byte{entraSchema: entra, azureSchema: azure}
}

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. The SDK writes each one as the
// x-epack-method of its field in the SDK's own schema for the type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
