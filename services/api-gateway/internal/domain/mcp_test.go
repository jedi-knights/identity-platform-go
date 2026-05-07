package domain

import "testing"

func TestTierOrder(t *testing.T) {
	tests := []struct {
		tier UserTier
		want int
	}{
		{TierFree, 0},
		{TierSubscriber, 1},
		{TierPremium, 2},
		{TierInternal, 3},
		{UserTier("unknown"), -1},
	}
	for _, tc := range tests {
		got := TierOrder(tc.tier)
		if got != tc.want {
			t.Errorf("TierOrder(%q) = %d, want %d", tc.tier, got, tc.want)
		}
	}
}

func TestTierOrderComparison(t *testing.T) {
	if TierOrder(TierSubscriber) <= TierOrder(TierFree) {
		t.Error("subscriber should rank above free")
	}
	if TierOrder(TierPremium) <= TierOrder(TierSubscriber) {
		t.Error("premium should rank above subscriber")
	}
	if TierOrder(TierInternal) <= TierOrder(TierPremium) {
		t.Error("internal should rank above premium")
	}
}
