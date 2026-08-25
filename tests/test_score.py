"""Scoring framework: block-rate, over-privilege, false-deny, decomposition,
and the port-granularity behaviour that is load-bearing for the thesis."""
from npready import decompose_false_deny, score

# a tiny ground truth
L = [("api", "db", 5432), ("api", "cache", 6379), ("web", "api", 8080)]
A = [("web", "db", 5432), ("cache", "api", 8080)]     # attacks; disjoint from L


def test_perfect_policy():
    """admitting exactly L blocks all attacks and denies nothing legit."""
    r = score(L, L, A)
    assert r["block_rate"] == 1.0
    assert r["over_privilege"] == 0.0
    assert r["false_deny"] == 0.0


def test_observed_only_policy_false_denies_unseen_edges():
    """a policy that only admits what it observed denies the rest of L."""
    observed = [("api", "db", 5432)]                  # saw one of three legit edges
    r = score(observed, L, A)
    assert r["over_privilege"] == 0.0                 # never admits an attack
    assert abs(r["false_deny"] - 2 / 3) < 1e-4        # denies the two unseen legit edges


def test_over_privilege_when_attack_admitted():
    admit = L + [("web", "db", 5432)]                 # admits one attack edge
    r = score(admit, L, A)
    assert r["over_privilege"] == 0.5                 # 1 of 2 attacks admitted
    assert r["block_rate"] == 0.5


def test_port_blind_wildcard_hides_over_privilege():
    """a port-blind admit (port=None) on web->db admits the :5432 attack too.

    This is the mechanism by which identity-only tools hide over-privilege, and the
    scorer must make it explicit rather than miss it."""
    admit = [("web", "db", None)]                      # any port web->db
    r = score(admit, L, A)
    assert "web->db:5432" in r["admitted_attacks"]     # the attack is admitted


def test_decomposition_splits_coverage_and_tool_penalty():
    """false-deny splits into never-observed (coverage) + observed-but-denied (tool)."""
    L2 = [("a", "b", 1), ("a", "c", 2), ("a", "d", 3)]
    observed = [("a", "b", 1), ("a", "c", 2)]          # d was never observed
    admit = [("a", "b", 1)]                             # c was observed but not encoded
    dec = decompose_false_deny(admit, L2, observed)
    assert abs(dec["false_deny"] - 2 / 3) < 1e-4
    assert abs(dec["coverage_component"] - 1 / 3) < 1e-4   # d: never observed
    assert abs(dec["tool_penalty"] - 1 / 3) < 1e-4        # c: seen, not encoded
    assert "a->d:3" in dec["never_observed"]
    assert "a->c:2" in dec["observed_but_denied"]
