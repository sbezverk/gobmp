package main

import (
	"encoding/json"
	"testing"
)

func TestValidateExpectedContainsArrayField(t *testing.T) {
	msg := map[string]any{
		"labels": []any{json.Number("1000")},
	}
	expect := ExpectSpec{
		Contains: map[string]any{
			"labels": []any{json.Number("1000")},
		},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedContainsNestedMapSubset(t *testing.T) {
	msg := map[string]any{
		"base_attrs": map[string]any{
			"origin":               "igp",
			"as_path":              []any{json.Number("50123"), json.Number("64512"), json.Number("64513")},
			"community_list":       []any{"64512:100", "65535:65281"},
			"large_community_list": []any{"64512:10:100"},
			"med":                  json.Number("100"),
		},
	}
	expect := ExpectSpec{
		Contains: map[string]any{
			"base_attrs": map[string]any{
				"origin":         "igp",
				"as_path":        []any{json.Number("50123"), json.Number("64512"), json.Number("64513")},
				"community_list": []any{"64512:100"},
			},
		},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedEqualsRequiresFullArrayEquality(t *testing.T) {
	msg := map[string]any{
		"labels": []any{json.Number("1000"), json.Number("2000")},
	}
	expect := ExpectSpec{
		Equals: map[string]any{
			"labels": []any{json.Number("1000")},
		},
	}

	if err := validateExpected(msg, expect); err == nil {
		t.Fatal("validateExpected succeeded for partial array equality")
	}
}

func TestValidateExpectedPresentAbsentSupportNestedPaths(t *testing.T) {
	msg := map[string]any{
		"base_attrs": map[string]any{
			"base_attr_hash": "abc123",
		},
	}
	expect := ExpectSpec{
		Present: []string{"base_attrs.base_attr_hash"},
		Absent:  []string{"base_attrs.missing", "missing"},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedNonEmptySupportNestedPaths(t *testing.T) {
	msg := map[string]any{
		"hash": "prefix-hash",
		"base_attrs": map[string]any{
			"base_attr_hash": "attr-hash",
		},
	}
	expect := ExpectSpec{
		NonEmpty: []string{"hash", "base_attrs.base_attr_hash"},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedNonEmptyRejectsEmptyValue(t *testing.T) {
	msg := map[string]any{
		"hash": "   ",
	}
	expect := ExpectSpec{
		NonEmpty: []string{"hash"},
	}

	if err := validateExpected(msg, expect); err == nil {
		t.Fatal("validateExpected succeeded for whitespace-only non_empty field")
	}
}
