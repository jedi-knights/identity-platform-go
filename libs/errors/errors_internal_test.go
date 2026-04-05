package errors

import (
	"reflect"
	"testing"
)

func TestIsNilableKind(t *testing.T) {
	tests := []struct {
		kind reflect.Kind
		want bool
	}{
		{reflect.Chan, true},
		{reflect.Func, true},
		{reflect.Map, true},
		{reflect.Pointer, true},
		{reflect.Slice, true},
		{reflect.UnsafePointer, true},
		{reflect.Struct, false},
		{reflect.String, false},
		{reflect.Int, false},
		{reflect.Bool, false},
		{reflect.Float64, false},
		{reflect.Array, false},
		{reflect.Uint64, false},
		{reflect.Invalid, false},
		{reflect.Interface, false},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			if got := isNilableKind(tt.kind); got != tt.want {
				t.Errorf("isNilableKind(%v) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
