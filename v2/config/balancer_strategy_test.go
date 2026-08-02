package config

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/group/balancer"
)

// The balancer rejects an unrecognised strategy with "unknown load balance
// strategy", and it does so at service start rather than config build — so the
// symptom was a tunnel that refused to come up, with nothing pointing at the
// option that caused it, and only once a profile carried more than one outbound.
//
// The empty string was the realistic input: HiddifyOptions loaded from a file
// unmarshal into a zero struct rather than over DefaultHiddifyOptions(), so any
// options JSON omitting "balancer-strategy" produced one.
func TestNormalizeBalancerStrategy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// The regression this exists for.
			name:  "empty falls back to round-robin",
			input: "",
			want:  balancer.StrategyRoundRobin,
		},
		{
			name:  "unknown value falls back to round-robin",
			input: "not-a-strategy",
			want:  balancer.StrategyRoundRobin,
		},
		{
			// Case matters: the balancer switches on the exact literal, so a
			// near-miss must fall back rather than be passed through.
			name:  "wrong case falls back to round-robin",
			input: "Round-Robin",
			want:  balancer.StrategyRoundRobin,
		},
		{name: "round-robin passes through", input: balancer.StrategyRoundRobin, want: balancer.StrategyRoundRobin},
		{name: "consistent-hashing passes through", input: balancer.StrategyConsistentHashing, want: balancer.StrategyConsistentHashing},
		{name: "sticky-sessions passes through", input: balancer.StrategyStickySessions, want: balancer.StrategyStickySessions},
		{name: "lowest-delay passes through", input: balancer.StrategyLowestDelay, want: balancer.StrategyLowestDelay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBalancerStrategy(tt.input); got != tt.want {
				t.Errorf("normalizeBalancerStrategy(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Every value normalizeBalancerStrategy can return must be one the balancer will
// actually accept. This guards the pairing: if upstream renames or drops a
// strategy constant, this fails rather than shipping a config the core rejects at
// start-up.
func TestNormalizeBalancerStrategyReturnsAcceptedValue(t *testing.T) {
	accepted := map[string]bool{
		balancer.StrategyRoundRobin:        true,
		balancer.StrategyConsistentHashing: true,
		balancer.StrategyStickySessions:    true,
		balancer.StrategyLowestDelay:       true,
	}

	for _, input := range []string{"", "garbage", "Round-Robin", balancer.StrategyRoundRobin, balancer.StrategyStickySessions} {
		if got := normalizeBalancerStrategy(input); !accepted[got] {
			t.Errorf("normalizeBalancerStrategy(%q) returned %q, which the balancer would reject", input, got)
		}
	}
}

// DefaultHiddifyOptions is the base that gRPC settings are unmarshalled over, so a
// client that omits the key inherits this. It must already be valid.
func TestDefaultHiddifyOptionsHasUsableBalancerStrategy(t *testing.T) {
	got := DefaultHiddifyOptions().BalancerStrategy

	if got == "" {
		t.Fatal("DefaultHiddifyOptions().BalancerStrategy is empty; the balancer rejects that with " +
			"\"unknown load balance strategy\" and the core fails to start once a profile has >1 outbound")
	}
	if got != balancer.StrategyRoundRobin {
		t.Errorf("BalancerStrategy = %q, want %q", got, balancer.StrategyRoundRobin)
	}
	if normalizeBalancerStrategy(got) != got {
		t.Errorf("default %q does not survive normalization", got)
	}
}
