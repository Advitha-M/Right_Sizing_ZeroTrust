#!/usr/bin/env bash
# =============================================================================
# azure/provision_shapley_autostart.sh — closes the gap left by putting
# rszt-shapley on Spot: nothing that runs ON the VM (systemd's
# Restart=on-failure, the cron watchdog) can recover from Azure evicting
# the whole VM out from under itself, because both mechanisms need the VM
# to already be running to do anything. This needs something that lives
# OUTSIDE the VM and gets triggered by Azure itself the moment eviction
# happens.
#
# Sets up, all within THIS account (account B — same account as
# rszt-shapley, no cross-account permissions needed):
#   1. An Automation Account with a system-assigned managed identity
#   2. A role assignment giving that identity "Virtual Machine Contributor"
#      scoped to rszt-shapley (start/restart only — nothing broader)
#   3. A PowerShell runbook that starts rszt-shapley, published + a
#      webhook created for it
#   4. An Action Group wired to that runbook via the webhook
#   5. An Activity Log Alert scoped to rszt-shapley, firing on
#      Microsoft.Compute/virtualMachines/deallocate/action with a
#      Succeeded status — this fires for a Spot eviction (Azure-initiated
#      deallocate) as well as any other deallocate, which is fine here:
#      the runbook's `az vm start` on an already-running VM is a safe
#      no-op, so an occasional manual/benign deallocate just gets a free
#      restart rather than requiring the alert to somehow distinguish
#      cause.
#
# Run this AFTER provision_shapley.sh, in the SAME account (`az login` to
# account B first, same as that script).
#
# Usage:
#   ./provision_shapley_autostart.sh [--subscription <id>]
#
# CAVEAT: exact `az` flags for automation-account/runbook/webhook/
# action-group/activity-log-alert resources have moved between CLI
# versions in the past (see azure/README-autostart.md, generated at the
# end of this script, for what to check if any step below errors on your
# installed `az` version). This was written and reasoned through against
# current documented syntax but NOT executed against a live subscription
# — treat the first run as a smoke test, same as this repo's existing
# k3s multi-instance bootstrap caveat in run_shapley.sh.
# =============================================================================
set -euo pipefail

SUBSCRIPTION="${1:-}"
[ -n "$SUBSCRIPTION" ] && az account set --subscription "$SUBSCRIPTION"

RG="rszt-shapley-rg"
LOCATION="${AZURE_LOCATION:-eastus}"
VM_NAME="rszt-shapley"
AUTOMATION_ACCOUNT="rszt-shapley-autostart-aa"
RUNBOOK_NAME="Start-RsztShapleyVM"
WEBHOOK_NAME="rszt-shapley-restart-hook"
ACTION_GROUP="rszt-shapley-restart-ag"
ALERT_NAME="rszt-shapley-eviction-restart"

echo "== account check =="
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table

SUB_ID=$(az account show --query id -o tsv)
VM_ID=$(az vm show -g "$RG" -n "$VM_NAME" --query id -o tsv) || {
  echo "FATAL: could not find VM $VM_NAME in resource group $RG — run" \
       "provision_shapley.sh first." >&2
  exit 1
}

echo "== automation account (system-assigned identity) =="
az automation account create \
  -g "$RG" -n "$AUTOMATION_ACCOUNT" -l "$LOCATION" \
  --assign-identity '[system]' >/dev/null

AA_PRINCIPAL=$(az automation account show -g "$RG" -n "$AUTOMATION_ACCOUNT" \
  --query identity.principalId -o tsv)
AA_ID=$(az automation account show -g "$RG" -n "$AUTOMATION_ACCOUNT" --query id -o tsv)

echo "== granting the automation account's identity VM Contributor on $VM_NAME only =="
# Scoped to the VM itself, not the resource group — this identity should
# only ever be able to start/restart this one Spot VM, nothing else.
az role assignment create \
  --assignee "$AA_PRINCIPAL" \
  --role "Virtual Machine Contributor" \
  --scope "$VM_ID" >/dev/null

echo "== importing the restart runbook =="
RUNBOOK_FILE="$(mktemp /tmp/rszt-shapley-restart-XXXX.ps1)"
cat > "$RUNBOOK_FILE" <<PS1
# Start-RsztShapleyVM.ps1 — runs inside Azure Automation on the
# automation account's own system-assigned managed identity (granted
# Virtual Machine Contributor scoped to rszt-shapley only). Triggered by
# the Activity Log Alert on this VM's deallocate/action operation, i.e.
# whenever the VM stops for ANY reason including Spot eviction.
# Starting an already-running VM is a harmless no-op, so this does not
# need to distinguish "evicted" from any other deallocate.
Connect-AzAccount -Identity | Out-Null
Start-AzVM -ResourceGroupName "$RG" -Name "$VM_NAME" -NoWait
Write-Output "Start-AzVM issued for $VM_NAME in $RG"
PS1

az automation runbook create \
  -g "$RG" --automation-account-name "$AUTOMATION_ACCOUNT" \
  -n "$RUNBOOK_NAME" --type PowerShell >/dev/null

az automation runbook replace-content \
  -g "$RG" --automation-account-name "$AUTOMATION_ACCOUNT" \
  -n "$RUNBOOK_NAME" --content "@${RUNBOOK_FILE}" >/dev/null

az automation runbook publish \
  -g "$RG" --automation-account-name "$AUTOMATION_ACCOUNT" \
  -n "$RUNBOOK_NAME" >/dev/null

rm -f "$RUNBOOK_FILE"

echo "== creating a webhook for the runbook (expires in 5 years — recreate before then) =="
WEBHOOK_URI=$(az automation webhook create \
  -g "$RG" --automation-account-name "$AUTOMATION_ACCOUNT" \
  -n "$WEBHOOK_NAME" --runbook-name "$RUNBOOK_NAME" \
  --expiry-time "$(date -u -d '+5 years' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query value -o tsv)
# NOTE: the webhook URI is only ever returned at creation time — az/Azure
# does not let you retrieve it again later. It's used once, immediately
# below, to wire up the action group; nothing else in this repo needs it
# again after this script finishes.

echo "== action group wired to the runbook via its webhook =="
az monitor action-group create \
  -g "$RG" -n "$ACTION_GROUP" --short-name "rsztshap" \
  --action automationrunbook restart-runbook \
    "$AA_ID" "$RUNBOOK_NAME" "$WEBHOOK_URI" false \
    >/dev/null

echo "== activity log alert: fires on rszt-shapley deallocate (eviction or otherwise) =="
az monitor activity-log alert create \
  -g "$RG" -n "$ALERT_NAME" \
  --scope "$VM_ID" \
  --condition category=Administrative \
              operationName=Microsoft.Compute/virtualMachines/deallocate/action \
              status=Succeeded \
              resourceId="$VM_ID" \
  --action-group "$ACTION_GROUP" \
  --description "Auto-restarts rszt-shapley after any deallocate, including Spot eviction" \
  >/dev/null

cat > "$(dirname "$0")/README-autostart.md" <<'MD'
# rszt-shapley autostart — what this set up and how to verify it

provision_shapley_autostart.sh created, in account B:
  - Automation account `rszt-shapley-autostart-aa` (system-assigned identity,
    scoped to "Virtual Machine Contributor" on rszt-shapley ONLY)
  - Runbook `Start-RsztShapleyVM` (PowerShell, calls Start-AzVM on the
    automation account's own identity)
  - A webhook on that runbook (5-year expiry — put a reminder to recreate
    it before it lapses; an expired webhook fails silently from the
    alert's point of view, i.e. this is the one part of this setup that
    can quietly stop working without an error appearing anywhere obvious)
  - Action group `rszt-shapley-restart-ag`
  - Activity Log Alert `rszt-shapley-eviction-restart`, scoped to the VM,
    firing on a successful `deallocate` operation of any origin

## To verify this actually works before trusting it for a multi-day run

    az vm deallocate -g rszt-shapley-rg -n rszt-shapley --no-wait

Then watch (this can take several minutes — Activity Log alerts are not
instant):

    az vm get-instance-view -g rszt-shapley-rg -n rszt-shapley \
      --query instanceView.statuses -o table

Expect to see it go Deallocated -> Starting -> Running on its own, with no
`az vm start` from you. If it doesn't, check:
  - Portal > rszt-shapley-autostart-aa > Runbooks > Start-RsztShapleyVM >
    Jobs, to see whether the alert fired the runbook at all
  - The Activity Log Alert's own "fired" history in the portal
  - That the webhook hasn't expired (5 years from creation)

## What this does NOT cover

Capacity-based eviction can happen again immediately if Standard_D48s_v5
Spot capacity in your region/zone is simply unavailable at restart time —
Start-AzVM will then itself fail, the runbook job will show that failure,
and nothing will retry it automatically. That's a genuine capacity
constraint no amount of automation removes; if it becomes a recurring
problem, either raise AZURE_SPOT_MAX_PRICE (accepting price risk instead
of dropping capacity risk), switch to a different VM size/region with more
Spot headroom, or fall back to a Regular (on-demand) VM for this account,
same as rszt-canonical.
MD

echo
echo "rszt-shapley autostart automation provisioned."
echo "See $(dirname "$0")/README-autostart.md for how to verify it before"
echo "trusting it for an unattended multi-day run."
