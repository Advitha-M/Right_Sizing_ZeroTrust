"""
constants.py — single source of truth for all shared vocabulary.
Revision 6 — see agent_implementation_brief_v6.docx for the full
reconciliation record. Every value here reflects author-directed
corrections; where this file conflicts with the Rev5 spec docs or the
"comprehensive" agent brief, THIS FILE (and v6) wins.

Imported by: driver.py, config.py, analyze.py, compositional.py, samplers.py
Never import from each other to get these values — always import from here.
"""

# ── Layer universe ────────────────────────────────────────────────────────────
# CORRECTED (v6 Section 1): L1 and L2 are NOT a non-separable baseline bundle.
# L2 (cluster access control) is the true, sole base layer — always active,
# implemented as audit-logging baked into the kube-apiserver static manifest
# at cluster bootstrap. L1 (cloud & infrastructure) is a standalone,
# independently toggleable layer — implemented as a composite control:
# image-pull verification + etcd encryption at rest (registry-level and
# etcd-level, deliberately NOT overlapping with L3b's admission-time checks).

BASE_LAYER         = "L2"
PERMUTABLE_LAYERS  = ["L1", "L3a", "L3b", "L4", "L5", "L6", "L7"]
CANONICAL_ORDER    = [BASE_LAYER] + PERMUTABLE_LAYERS
# Back-compat alias — some analysis scripts historically imported BASELINE_LAYERS.
# Kept as a single-element list, NOT ["L1","L2"]. Do not silently re-expand this.
BASELINE_LAYERS    = [BASE_LAYER]

LAYER_LABELS = {
    "L1":  "Cloud & infra (image-pull verification + etcd encryption at rest)",
    "L2":  "Cluster access control (audit logging) — base layer",
    "L3a": "RBAC",
    "L3b": "OPA/Kyverno admission",
    "L4":  "Tenant isolation",
    "L5":  "NetworkPolicy",
    "L6":  "Istio mTLS",
    "L7":  "Vault dynamic secrets",
}

# L1 scope note (v6): the full real-world L1 definition (VPC segmentation,
# cloud IAM, OS hardening, image signing, etcd encryption) is RETAINED for
# paper narrative even where it overlaps with other layers (e.g. image
# verification also appears at L3b's admission stage — different enforcement
# point: L1 = registry/pull-time, L3b = admission-time). VPC segmentation and
# cloud IAM are NOT independently measurable on a local KIND substrate (no
# cloud provider, single Docker host) — documented as a substrate limitation,
# not a scope decision.
L1_SCOPE_NOTE = (
    "L1 measured proxy = image-pull verification + etcd encryption at rest. "
    "VPC segmentation and cloud IAM are conceptually part of L1 but have no "
    "implementable proxy under KIND (no cloud provider, single Docker host) "
    "— substrate limitation, stated explicitly in methods/limitations, not "
    "silently dropped from scope."
)

# L4 scope note (v6): tenant pools (tenant-finserv/tenant-saas/tenant-lowpriv/
# tenant-partner) are individually node-pinned and isolated from EACH OTHER.
# The system pool (Cilium, Falco, Istio control plane, Vault, etc.) is SHARED
# across all tenants and is not itself partitioned. The Tier-1 "system pool
# isolation" invariant check verifies the system pool is separate FROM
# tenants, not that it is partitioned per-tenant — these are different
# guarantees and must not be conflated in the write-up.
L4_SCOPE_NOTE = (
    "L4 tenant isolation applies to user-facing tenant pools only "
    "(tenant-finserv/tenant-saas/tenant-lowpriv/tenant-partner), which are "
    "individually node-pinned. The system pool (Cilium/Falco/Istio/Vault) is "
    "SHARED across all tenants and is not itself isolated per-tenant. Scope "
    "limitation for the paper's methods/limitations section."
)

# ── Condition definitions ─────────────────────────────────────────────────────
# CORRECTED (v6 Section 2): primary build is C0-C7 (8 conditions), every
# condition adds exactly ONE layer, no bundled multi-layer steps anywhere.
# Canonical order: L2(base) -> L1 -> L3a -> L3b -> L4 -> L5 -> L6 -> L7.

CONFIGS = {
    "C0": [],                                              # base L2 only
    "C1": ["L1"],
    "C2": ["L1", "L3a"],
    "C3": ["L1", "L3a", "L3b"],
    "C4": ["L1", "L3a", "L3b", "L4"],
    "C5": ["L1", "L3a", "L3b", "L4", "L5"],
    "C6": ["L1", "L3a", "L3b", "L4", "L5", "L6"],
    "C7": ["L1", "L3a", "L3b", "L4", "L5", "L6", "L7"],
}
CONDITION_ORDER = ["C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7"]

CONDITION_LABELS = {
    "C0": "C0\n(base: L2)", "C1": "C1\n+L1",  "C2": "C2\n+L3a",
    "C3": "C3\n+L3b",       "C4": "C4\n+L4",  "C5": "C5\n+L5",
    "C6": "C6\n+L6",        "C7": "C7\n+L7",
}

# ── Attack class definitions ──────────────────────────────────────────────────
# CORRECTED (v6 Section 7): the non-sequential script-to-class mapping table
# is SCRAPPED. attackN.sh = AN, identity mapping, no lookup table needed.
# Scripts have been physically renamed to match. SCRIPT_TO_DOC kept only as
# a thin identity-derived shim for code that still imports it.

ATTACK_ORDER_SCRIPTS = ["attack1","attack2","attack3","attack4","attack5","attack6","attack7"]
ATTACK_ORDER_DOCS    = ["A1","A2","A3","A4","A5","A6","A7"]

SCRIPT_TO_DOC = {f"attack{i+1}": doc for i, doc in enumerate(ATTACK_ORDER_DOCS)}
DOC_TO_SCRIPT = {v: k for k, v in SCRIPT_TO_DOC.items()}

ATTACK_CLASSES = {
    "attack1": {"doc_id": "A1", "label": "Isolation bypass",
                "primary_defender": ["L3a", "L4", "L5"]},
    "attack2": {"doc_id": "A2", "label": "Identity & auth",
                "primary_defender": ["L3a", "L2", "L6"]},
    "attack3": {"doc_id": "A3", "label": "IAM abuse",
                "primary_defender": ["L3a"]},
    "attack4": {"doc_id": "A4", "label": "Unauthorized API access",
                "primary_defender": ["L3a", "L2"]},
    "attack5": {"doc_id": "A5", "label": "Lateral movement",
                "primary_defender": ["L3a", "L4", "L5"]},
    "attack6": {"doc_id": "A6", "label": "Supply chain compromise",
                "primary_defender": ["L3b"]},
    "attack7": {"doc_id": "A7", "label": "Data exfiltration",
                "primary_defender": ["L5", "L7"]},
}

# ── Technique sets ─────────────────────────────────────────────────────────────
# CORRECTED (v6 + technique_sample_space.docx, Section 13, |T|=15 total).
# Every set below is verified against the actual attackN.sh TECHNIQUES=()
# arrays as of this revision. Do not add, remove, or re-derive techniques
# without updating BOTH this dict and the corresponding script.
# |T| sizes: A1=3, A2=3, A3=2, A4=1, A5=3, A6=1, A7=2  (sum=15)
# Risk tiers: High=3 (A1,A2,A5) Medium=2 (A3,A7) Low=1 (A4,A6)

TECHNIQUE_SETS = {
    "A1": ["t1-crb-cross-namespace", "t2-pvc-mismatch", "t3-direct-pod-api"],
    "A2": ["t1-sa-token-theft", "t2-token-replay-expired", "t3-cert-identity-spoof"],
    "A3": ["t1-scoped-binding-escalation", "t2-wildcard-clusterrole"],
    "A4": ["t1-tool-enumeration"],
    "A5": ["t1-sa-token-reuse", "t2-network-pivot", "t3-secret-projection-leak"],
    "A6": ["t1-pipeline-injection"],
    "A7": ["t1-direct-egress", "t2-vault-sa-token-exfil"],
}

# ── Attacker namespace per attack class (v6 Section 13) ──────────────────────
# A3: tenant-partner — insider/overpermissioned-operator profile (explicit
#     exception to the tenant-lowpriv default).
# A4: tenant-partner — Section 13 states tenant-partner is the "primary
#     substrate for A4 trials requiring a principal with legitimate but
#     overpermissioned access." This is a SECOND exception to the
#     tenant-lowpriv default; A4 was incorrectly mapped to tenant-lowpriv in
#     earlier revisions of this file. Corrected here.
# A6: tenant-lowpriv — attacker origin AND target namespace are the same
#     (tenant-lowpriv); the attack does not cross a namespace boundary,
#     unlike A1/A2/A5. See A6 scope constraint, Section 13.
# A7: CORRECTED (this revision) — tenant-finserv, NOT tenant-lowpriv.
#     Both A7 techniques (t1-direct-egress, t2-vault-sa-token-exfil) are
#     anchored in the finserv pod per the brief's technique descriptions
#     (mock-PII/transaction-data egress; SPIFFE-identified workload
#     requesting its own Vault secret) — there is no documented identity
#     or secret-holding role for tenant-saas in A7. Like A6, origin ==
#     target and A7 does not cross a namespace boundary; unlike A6,
#     the shared namespace is tenant-finserv, not tenant-lowpriv. Models
#     an insider/already-present principal, not an external intruder —
#     same modeling shift as A3/A4, but via shared-namespace rather than
#     cross-namespace scoped access. See A7 scope constraint (origin),
#     Section 13. NOTE: attack7.sh / pod-provisioning logic must be
#     checked to confirm the attacker pod is actually placed in
#     tenant-finserv (with SPIFFE identity there) rather than assuming
#     an outside-intruder start — this constant change alone does not
#     guarantee that.
ATTACKER_NS_MAP = {
    "A1": "tenant-lowpriv",
    "A2": "tenant-lowpriv",
    "A3": "tenant-partner",   # insider/overpermissioned-operator profile
    "A4": "tenant-partner",   # overpermissioned-but-legitimate principal
    "A5": "tenant-lowpriv",
    "A6": "tenant-lowpriv",   # origin == target; no namespace crossing
    "A7": "tenant-finserv",   # origin == target; insider/already-present principal
}

# ── Technique minimum-condition map ──────────────────────────────────────────
# Technique whose BLOCKED/SKIP outcome is structurally expected below the
# listed condition — not a layer-enforcement signal. analyze.py must exclude
# these (condition, technique) cells from McNemar/Cohen's h computation.
# CORRECTED: C6 -> C7 (Vault/L7 is now the C7 step, not C6, under the
# corrected 8-condition primary build). Token also corrected to match the
# rewritten attack7.sh technique (SA-token Vault k8s-auth, not static token).
TECHNIQUE_MIN_CONDITION = {
    ("A7", "t2-vault-sa-token-exfil"): "C7",   # Vault pod/role not populated before C7
}

# ── Shapley correction ────────────────────────────────────────────────────────
# CORRECTED (v6 Section 4): (L1,L7) is INCLUDED — L1 is physically
# toggleable and its position varies across this pair's samples like any
# other permutable layer. This directly overrides the prior exclusion
# ("(L1,L7) excluded: L1 is fixed substrate, phi(L1) unmeasurable").

CONSTRAINED_PAIRS_ASR = [("L3a", "L3b"), ("L5", "L6"), ("L1", "L7")]

# Per-pair Monte Carlo sample size (v6 Section 4.2 — NOT uniform M=30).
# (L3a,L3b) is ASR-constrained only -> M'=15.
# (L5,L6) and (L1,L7) are ASR-constrained AND DL candidates -> M=30.
PAIR_MC_SAMPLES = {
    ("L3a", "L3b"): 15,
    ("L5",  "L6"):  30,
    ("L1",  "L7"):  30,
}

# DL candidate pairs (architecturally determined, Rev5 §7.1) — unchanged by v6.
DL_CANDIDATE_PAIRS = [("L5", "L6"), ("L1", "L7"), ("L2", "L3a")]

# Dedicated separation-sample size for the DL-only pair (L2,L3a) — v6 confirms
# L2's position is fixed (hard precedence: L2 always precedes L3a), only
# L3a's position varies.
L2_L3A_SEPARATION_SAMPLES = 15

# DL robustness sample size — applies to ALL THREE DL candidate pairs after
# each individually passes its superadditivity test (v6 Section 4.2).
DL_ROBUSTNESS_SAMPLES = 15

# phi_DL_pair (v6 Section 5): pair-level ONLY, never split per layer.
# Computed directly from the M''=15 robustness-run output via Shapley-style
# averaging over the pair's sampled orderings — self-contained, no
# dependency on DL_solo_best or any other precomputed value. DL_solo_best
# is used ONLY as a separate downstream validation check (phi_DL_pair must
# beat MIN(delta_dl_solo(La), delta_dl_solo(Lb))), never as a formula input.
PHI_DL_PAIR_NOTE = (
    "phi_DL_pair computed directly from M''=15 Shapley averaging over "
    "sampled orderings. DL_solo_best = MIN(delta_dl_solo per layer) is "
    "validation-only, applied AFTER phi_DL_pair is computed, never as an "
    "input to it. Never decomposed into per-layer phi_DL values."
)

# ── Significance thresholds ───────────────────────────────────────────────────

ALPHA              = 0.05
N_ATTACK_CLASSES   = 7
BONFERRONI_ALPHA   = ALPHA / N_ATTACK_CLASSES   # ~= 0.00714
COHENS_H_MIN       = 0.20

# ── Recommendation engine precedence (VALID_SUBSET — not enforced in MC) ─────
# L2 is always present (base layer), so (L2,L3a) is always satisfied
# structurally. (L2,L6) retained from Rev5 for paper correctness.
# OPEN QUESTION (not settled in v6): does L7 (or any other layer) require a
# precedence entry now that L1 is independently toggleable rather than
# baseline-bundled? Left unchanged pending explicit confirmation — flag to
# author before treating PRECEDENCE as final for Deliverable B.
PRECEDENCE = [("L3a", "L3b"), ("L2", "L3a"), ("L2", "L6")]

def is_valid_subset(subset: list) -> bool:
    s = set(subset)
    for prereq, dependent in PRECEDENCE:
        if dependent in s and prereq not in s:
            return False
    return True

# ── Tenant model ──────────────────────────────────────────────────────────────

TENANTS = {
    "tenant-lowpriv": {"role": "attacker",             "node_label": "tenant-lowpriv"},
    "tenant-finserv": {"role": "isolated-victim",       "node_label": "tenant-finserv", "mock_data": "PII"},
    "tenant-partner": {"role": "overpermissioned-partner", "node_label": "tenant-partner", "mock_data": "API"},
    "tenant-saas":    {"role": "saas-partner",          "node_label": "tenant-saas",    "mock_data": "transactions"},
}
VICTIM_NS  = "tenant-finserv"
PARTNER_NS = "tenant-partner"
