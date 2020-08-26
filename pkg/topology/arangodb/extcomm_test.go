package arangodb

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestExtCommGetDiff(t *testing.T) {
	tests := []struct {
		name        string
		extCommType string
		extCommO    []string
		extCommN    []string
		toAdd       []string
		toDel       []string
	}{
		{
			name:        "no ext comm type, empty input slices",
			extCommType: "",
			extCommO:    []string{},
			extCommN:    []string{},
			toAdd:       []string{},
			toDel:       []string{},
		},
		{
			name:        "no ext comm type, O and N slices are the same",
			extCommType: "",
			extCommO:    []string{"rt=100:100"},
			extCommN:    []string{"rt=100:100"},
			toAdd:       []string{},
			toDel:       []string{},
		},
		{
			name:        "no ext comm type, O and N slices are different",
			extCommType: "",
			extCommO:    []string{"rt=100:100"},
			extCommN:    []string{"rt=200:100"},
			toAdd:       []string{"rt=200:100"},
			toDel:       []string{"rt=100:100"},
		},
		{
			name:        "rt ext comm type, O and N slices have rt the same",
			extCommType: "rt=",
			extCommO:    []string{"rt=100:100", "color=17867323"},
			extCommN:    []string{"rt=100:100"},
			toAdd:       []string{},
			toDel:       []string{},
		},
		{
			name:        "rt ext comm type, O and N slices are different, new lost one community",
			extCommType: "rt=",
			extCommO:    []string{"rt=100:100", "rt=200:100", "color=17867323"},
			extCommN:    []string{"rt=100:100"},
			toAdd:       []string{},
			toDel:       []string{"rt=200:100"},
		},
		{
			name:        "rt ext comm type, O and N slices are different, new got new community",
			extCommType: "rt=",
			extCommO:    []string{"rt=100:100", "color=17867323"},
			extCommN:    []string{"rt=100:100", "rt=200:100"},
			toAdd:       []string{"rt=200:100"},
			toDel:       []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToAdd, gotToDel := ExtCommGetDiff(tt.extCommType, tt.extCommO, tt.extCommN)
			sort.SliceStable(tt.toAdd, func(i, j int) bool {
				if strings.Compare(tt.toAdd[i], tt.toAdd[j]) == -1 {
					return true
				}
				return false
			})
			sort.SliceStable(tt.toDel, func(i, j int) bool {
				if strings.Compare(tt.toDel[i], tt.toDel[j]) == -1 {
					return true
				}
				return false
			})
			sort.SliceStable(gotToAdd, func(i, j int) bool {
				if strings.Compare(gotToAdd[i], gotToAdd[j]) == -1 {
					return true
				}
				return false
			})
			sort.SliceStable(gotToDel, func(i, j int) bool {
				if strings.Compare(gotToDel[i], gotToDel[j]) == -1 {
					return true
				}
				return false
			})
			if !reflect.DeepEqual(tt.toAdd, gotToAdd) {
				t.Errorf("Expected to Add slice %+v does not match with actual one: %+v", tt.toAdd, gotToAdd)
			}
			if !reflect.DeepEqual(tt.toDel, gotToDel) {
				t.Errorf("Expected to Del slice %+v does not match with actual one: %+v", tt.toDel, gotToDel)
			}
		})
	}
}
