package testutil_test

import (
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/testutil"
)

// spyT records whether Fatal or Error was called.
type spyT struct {
	testing.TB
	fataled bool
	errored bool
}

func (s *spyT) Fatalf(format string, args ...any) {
	s.fataled = true
	_ = format
	_ = args
}

func (s *spyT) Errorf(format string, args ...any) {
	s.errored = true
	_ = format
	_ = args
}

func (s *spyT) Helper() {}

func TestRequireNoError_NoError(t *testing.T) {
	spy := &spyT{}
	testutil.RequireNoError(spy, nil)
	if spy.fataled {
		t.Error("expected no Fatal when err is nil")
	}
}

func TestRequireNoError_WithError(t *testing.T) {
	spy := &spyT{}
	testutil.RequireNoError(spy, errors.New("something broke"))
	if !spy.fataled {
		t.Error("expected Fatal when err is non-nil")
	}
}

func TestAssertEqual_Equal(t *testing.T) {
	spy := &spyT{}
	testutil.AssertEqual(spy, 42, 42)
	if spy.errored {
		t.Error("expected no Errorf when values are equal")
	}
}

func TestAssertEqual_NotEqual(t *testing.T) {
	spy := &spyT{}
	testutil.AssertEqual(spy, 42, 99)
	if !spy.errored {
		t.Error("expected Errorf when values differ")
	}
}

func TestAssertEqual_NilVsEmptySlice(t *testing.T) {
	// Document known behaviour: nil slice != empty slice with reflect.DeepEqual.
	spy := &spyT{}
	testutil.AssertEqual(spy, []string{}, []string(nil))
	if !spy.errored {
		t.Error("expected Errorf: nil slice and empty slice are not deeply equal")
	}
}
