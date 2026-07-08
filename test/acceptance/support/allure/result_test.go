package allure

import "testing"

func TestWorstStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []string
		want     string
	}{
		{name: "empty", statuses: nil, want: StatusUnknown},
		{name: "all passed", statuses: []string{StatusPassed, StatusPassed}, want: StatusPassed},
		{name: "passed and skipped", statuses: []string{StatusPassed, StatusSkipped}, want: StatusSkipped},
		{name: "passed and broken", statuses: []string{StatusPassed, StatusBroken}, want: StatusBroken},
		{name: "broken and skipped", statuses: []string{StatusBroken, StatusSkipped}, want: StatusBroken},
		{name: "failed wins over everything", statuses: []string{StatusPassed, StatusFailed, StatusBroken, StatusSkipped}, want: StatusFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange — statuses is set up in the table above.

			// Act
			got := worstStatus(tt.statuses)

			// Assert
			if got != tt.want {
				t.Errorf("worstStatus(%v) = %q, want %q", tt.statuses, got, tt.want)
			}
		})
	}
}

func TestEpochMillis(t *testing.T) {
	// Arrange
	t1 := parseTestTime(t, "2026-01-01T00:00:00Z")
	t2 := parseTestTime(t, "2026-01-01T00:00:01Z")

	// Act
	got1 := epochMillis(t1)
	got2 := epochMillis(t2)

	// Assert
	if got2-got1 != 1000 {
		t.Errorf("epochMillis difference = %d ms, want 1000ms for a 1s gap", got2-got1)
	}
}
