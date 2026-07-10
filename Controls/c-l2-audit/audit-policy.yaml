# Controls/c-l2-audit/audit-policy.yaml
# -----------------------------------------------------------------------------
# Same policy content as Infra/files(1)/audit-policy.yaml (the KIND-cluster L2
# proxy), relocated here so this control folder is self-contained for the k3s
# (L2,L3a) separation sampler. On KIND, this policy is mounted at bootstrap and
# NEVER toggled (L2 is the fixed base layer there — see Driver/constants.py
# BASE_LAYER). On k3s, apply.sh/remove.sh below make this genuinely
# toggleable, which is the whole point of running this one sampler on k3s
# instead of KIND: a single-node k3s apiserver can be restarted in seconds via
# systemctl, so L2 can actually be turned on/off mid-run rather than being
# baked in once at cluster bootstrap.
# -----------------------------------------------------------------------------
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  # Secrets/configmaps: Metadata only (avoid logging secret values themselves)
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  # RBAC objects: full request/response — needed to audit L3a (RBAC) changes
  # and any privilege-escalation attempt (A2, A3).
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  # Pods, exec/attach, and service account tokens: full request/response —
  # this is the "rejected API request" shared detection event that the
  # (L2, L3a) DL candidate pair (Driver/constants.DL_CANDIDATE_PAIRS) relies
  # on, and covers A1-t3 (direct pod-to-pod API), A2 (token theft/replay),
  # A4 (unauthorized API access).
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "pods/exec", "pods/attach", "serviceaccounts", "serviceaccounts/token"]
  # Everything else: Metadata catch-all, so "full audit logging" holds for
  # the whole apiserver surface, not just the resources called out above.
  - level: Metadata
