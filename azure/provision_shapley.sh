#!/usr/bin/env bash
# =============================================================================
# azure/provision_shapley.sh — stands up rszt-shapley under Azure ACCOUNT B.
#
# Run this AFTER `az login` (or `az login --tenant <account-B-tenant-id>`) to
# the account that will host the Shapley-correction VM. Fully independent of
# provision_canonical.sh — separate resource group/vnet/identity in a
# separate account. Designed to run CONCURRENTLY with the canonical VM: no
# runtime coordination between the two, no shared disk, no shared results.db
# — each account's VM writes its own DB, merged offline afterward.
#
# FIX: this previously called plain `az vm create` with no --priority/
# --eviction-policy — i.e. rszt-shapley was provisioned as a Regular
# (on-demand) VM, identical to rszt-canonical, even though the study design
# calls for the Shapley-correction VM specifically to run on Spot capacity.
# Now provisioned as a genuine Spot VM:
#   --priority Spot                 opts into Spot pricing/capacity
#   --eviction-policy Deallocate    REQUIRED, not the default: on eviction
#                                    the OS disk is preserved and the VM
#                                    goes to "Stopped (Deallocated)" rather
#                                    than being destroyed. This is what
#                                    lets driver.py's resume logic
#                                    (detect_applied_layers() + per-trial
#                                    resume) actually mean anything after
#                                    an eviction — the alternative,
#                                    --eviction-policy Delete, would wipe
#                                    the disk (and every KIND cluster /
#                                    results.db on it) on every eviction.
#   --max-price                     -1 (default here) means "pay up to the
#                                    regular on-demand price, never evict
#                                    for price" — only capacity-based
#                                    eviction remains possible. Override
#                                    via AZURE_SPOT_MAX_PRICE if you'd
#                                    rather cap spend and accept more
#                                    price-based eviction risk.
#
# Eviction itself is still possible (Azure gives ~30s Scheduled-Events
# notice, not enough to matter for a shell-script-driven study) — see
# provision_shapley_autostart.sh, which this script's output points you
# to, for the automation that restarts rszt-shapley automatically after an
# eviction. Without that companion script, an evicted Spot VM stays
# deallocated indefinitely: systemd's Restart=on-failure and the cron
# watchdog can only restart a *process* on an already-running VM, neither
# can start a VM the cloud itself stopped.
#
# Usage:
#   az login                                  # account B
#   ./provision_shapley.sh [--subscription <id>]
# =============================================================================
set -euo pipefail

SUBSCRIPTION="${1:-}"
[ -n "$SUBSCRIPTION" ] && az account set --subscription "$SUBSCRIPTION"

RG="rszt-shapley-rg"
LOCATION="${AZURE_LOCATION:-eastus}"
VNET="rszt-shapley-vnet"
SUBNET="rszt-shapley-subnet"
NSG="rszt-shapley-nsg"
ADMIN_USER="${AZURE_ADMIN_USER:-ztadmin}"
SSH_KEY="${AZURE_SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}"
SPOT_MAX_PRICE="${AZURE_SPOT_MAX_PRICE:--1}"   # -1 = cap at on-demand price

echo "== account check =="
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table

echo "== resource group =="
az group create -n "$RG" -l "$LOCATION" >/dev/null

echo "== network =="
az network vnet create -g "$RG" -n "$VNET" --address-prefix 10.43.0.0/16 \
  --subnet-name "$SUBNET" --subnet-prefix 10.43.1.0/24 >/dev/null
az network nsg create -g "$RG" -n "$NSG" >/dev/null
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-ssh \
  --priority 1000 --access Allow --protocol Tcp --destination-port-ranges 22 >/dev/null

echo "== rszt-shapley (Spot VM, max-price=${SPOT_MAX_PRICE} — each worker runs a" \
     "KIND cluster AND a k3s instance, sized up) =="
az vm create \
  -g "$RG" -n rszt-shapley \
  --image Ubuntu2204 \
  --size Standard_D48s_v5 \
  --priority Spot \
  --eviction-policy Deallocate \
  --max-price "$SPOT_MAX_PRICE" \
  --vnet-name "$VNET" --subnet "$SUBNET" --nsg "$NSG" \
  --admin-username "$ADMIN_USER" --ssh-key-values "$SSH_KEY" \
  --os-disk-size-gb 384 \
  --assign-identity '[system]' \
  --custom-data azure/cloud-init-common.yaml \
  --tags role=shapley study=right-sizing-zero-trust priority=spot >/dev/null

SHAP_PRINCIPAL=$(az vm identity show -g "$RG" -n rszt-shapley --query principalId -o tsv)
SHAP_ID=$(az vm show -g "$RG" -n rszt-shapley --query id -o tsv)
az role assignment create --assignee "$SHAP_PRINCIPAL" --role "Virtual Machine Contributor" \
  --scope "$SHAP_ID" >/dev/null

SHAP_IP=$(az vm show -d -g "$RG" -n rszt-shapley --query publicIps -o tsv)
echo
echo "rszt-shapley provisioned in this account as a Spot VM. Public IP: $SHAP_IP"
echo "SSH in and run azure/run_shapley.sh whenever you want it to start —"
echo "it can run at the same time as rszt-canonical in the other account."
echo "Keep $SHAP_IP handy — merge_results.py pulls results.db from here"
echo "separately from the canonical account."
echo
echo "IMPORTANT — this is a Spot VM and CAN be evicted mid-run. Now run:"
echo "    ./azure/provision_shapley_autostart.sh"
echo "in this same account so an eviction restarts rszt-shapley automatically"
echo "(otherwise it stays deallocated indefinitely — no in-VM mechanism, not"
echo "systemd's Restart=on-failure, not the cron watchdog, can start a VM"
echo "back up once Azure itself has stopped it)."
