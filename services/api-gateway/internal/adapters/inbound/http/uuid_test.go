//go:build unit

package http

import "testing"

func TestIsValidUUID_AcceptsWellFormedV4(t *testing.T) {
	// Arrange
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"00000000-0000-4000-8000-000000000000",
		"ffffffff-ffff-4fff-bfff-ffffffffffff",
	}

	// Act + Assert
	for _, uuid := range valid {
		if !isValidUUID(uuid) {
			t.Errorf("isValidUUID(%q) = false, want true", uuid)
		}
	}
}

func TestIsValidUUID_RejectsWrongLength(t *testing.T) {
	// Arrange
	invalid := []string{
		"",
		"550e8400-e29b-41d4-a716-44665544000",  // 35 chars
		"550e8400-e29b-41d4-a716-4466554400000", // 37 chars
	}

	// Act + Assert
	for _, s := range invalid {
		if isValidUUID(s) {
			t.Errorf("isValidUUID(%q) = true, want false (wrong length)", s)
		}
	}
}

func TestIsValidUUID_RejectsMissingHyphens(t *testing.T) {
	// Arrange — hyphens removed or in wrong positions
	invalid := []string{
		"550e8400xe29b-41d4-a716-446655440000",
		"550e8400-e29bx41d4-a716-446655440000",
		"550e8400-e29b-41d4xa716-446655440000",
		"550e8400-e29b-41d4-a716x446655440000",
	}

	// Act + Assert
	for _, s := range invalid {
		if isValidUUID(s) {
			t.Errorf("isValidUUID(%q) = true, want false (missing hyphen)", s)
		}
	}
}

func TestIsValidUUID_RejectsNonHexChars(t *testing.T) {
	// Arrange — 'g' is not a hex digit
	s := "550e8400-e29b-41d4-a716-44665544g000"

	// Act + Assert
	if isValidUUID(s) {
		t.Errorf("isValidUUID(%q) = true, want false (non-hex char)", s)
	}
}

func TestIsValidUUID_RejectsUppercaseHex(t *testing.T) {
	// Arrange — the original regex only accepts lowercase; isValidUUID must match.
	s := "550E8400-E29B-41D4-A716-446655440000"

	// Act + Assert
	if isValidUUID(s) {
		t.Errorf("isValidUUID(%q) = true, want false (uppercase not accepted)", s)
	}
}

func TestIsValidUUID_RejectsWrongVersion(t *testing.T) {
	// Arrange — version nibble (position 14) is '5', not '4'
	s := "550e8400-e29b-51d4-a716-446655440000"

	// Act + Assert
	if isValidUUID(s) {
		t.Errorf("isValidUUID(%q) = true, want false (wrong version nibble)", s)
	}
}

func TestIsValidUUID_RejectsWrongVariant(t *testing.T) {
	// Arrange — variant nibble (position 19) is 'c', not [89ab]
	s := "550e8400-e29b-41d4-c716-446655440000"

	// Act + Assert
	if isValidUUID(s) {
		t.Errorf("isValidUUID(%q) = true, want false (wrong variant nibble)", s)
	}
}
