package microsoft

import (
	"bytes"
	"encoding/json"
	"strings"
)

// lacking returns the first of paths that item holds no value at, or "". A
// path names a field below the item, with "/" between keys and "*" for each
// item of a list, as in keyCredentials/*/endDateTime. A field is missing when
// it is absent, null or an empty string. A list that is itself missing has no
// items to check, so a path that must also find the list names it on its own.
func lacking(item json.RawMessage, paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(item))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "a value that is not JSON"
	}
	for _, path := range paths {
		if !holds(value, strings.Split(path, "/")) {
			return path
		}
	}
	return ""
}

// holds reports whether value holds a value at every field the keys lead to.
func holds(value any, keys []string) bool {
	if len(keys) == 0 {
		return value != nil && value != ""
	}
	if keys[0] == "*" {
		items, ok := value.([]any)
		if !ok {
			return value == nil
		}
		for _, item := range items {
			if !holds(item, keys[1:]) {
				return false
			}
		}
		return true
	}
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	child := object[keys[0]]
	if child == nil && len(keys) > 1 && keys[1] == "*" {
		return true
	}
	return holds(child, keys[1:])
}

// checked is a type that knows a rule its items must meet beyond holding the
// fields their call requires. problem says how an item breaks it, or is "".
type checked interface {
	problem() string
}

// decodeItems decodes a page's items and checks each one. It returns how the
// first one that fails is wrong, or "".
func decodeItems[T any](raw []json.RawMessage, required []string) ([]T, string, error) {
	out := make([]T, len(raw))
	for i, item := range raw {
		if path := lacking(item, required); path != "" {
			return nil, "lists an item with no " + path, nil
		}
		if err := json.Unmarshal(item, &out[i]); err != nil {
			return nil, "", err
		}
		if c, ok := any(out[i]).(checked); ok {
			if problem := c.problem(); problem != "" {
				return nil, "lists an item that " + problem, nil
			}
		}
	}
	return out, "", nil
}
