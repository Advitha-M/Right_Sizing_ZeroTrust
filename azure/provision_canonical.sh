#!/usr/bin/env bash
# =============================================================================
# azure/provision_canonical.sh — stands up rszt-canonical under Azure ACCOUNT A.
#
# Run this AFTER `az login` (or `az login --tenant <account-A-tenant-id>`) to
# the account that will host the canonical build. Independent of
# provision_shapley.sh — no shared resource group, vnet, or identity, since
# the two VMs now live in separate Azure accounts and run concurrently with
# no runtime dependency on each other (results are merged offline afterward,
# see merge_results.py).
#
# Usage:
#   az login                                   # account A
#   ./provision_canonical.sh [--subscription <id>]
# =============================================================================
set -euo pipefail

SUBSCRIPTION="${1:-}"
[ -n "$SUBSCRIPTION" ] && az account set --subscription "$SUBSCRIPTION"

RG="rszt-canonical-rg"
LOCATION="${AZURE_LOCATION:-eastus}"
VNET="rszt-canonical-vnet"
SUBNET="rszt-canonical-subnet"
NSG="rszt-canonical-nsg"
ADMIN_USER="${AZURE_ADMIN_USER:-ztadmin}"
SSH_KEY="${AZURE_SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}"

echo "== account check =="
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table

echo "== resource group =="
az group create -n "$RG" -l "$LOCATION" >/dev/null

echo "== network =="
az network vnet create -g "$RG" -n "$VNET" --address-prefix 10.42.0.0/16 \
  --subnet-name "$SUBNET" --subnet-prefix 10.42.1.0/24 >/dev/null
az network nsg create -g "$RG" -n "$NSG" >/dev/null
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-ssh \
  --priority 1000 --access Allow --protocol Tcp --destination-port-ranges 22 >/dev/null

echo "== rszt-canonical (sized for NUM_WORKERS parallel KIND clusters, 5 nodes each) =="
az vm create \
  -g "$RG" -n rszt-canonical \
  --image Ubuntu2204 \
  --size Standard_D32s_v5 \
  --vnet-name "$VNET" --subnet "$SUBNET" --nsg "$NSG" \
  --admin-username "$ADMIN_USER" --ssh-key-values "$SSH_KEY" \
  --os-disk-size-gb 256 \
  --assign-identity '[system]' \
  --custom-data azure/cloud-init-common.yaml \
  --tags role=canonical study=right-sizing-zero-trust >/dev/null

CANON_PRINCIPAL=$(az vm identity show -g "$RG" -n rszt-canonical --query principalId -o tsv)
CANON_ID=$(az vm show -g "$RG" -n rszt-canonical --query id -o tsv)
az role assignment create --assignee "$CANON_PRINCIPAL" --role "Virtual Machine Contributor" \
  --scope "$CANON_ID" >/dev/null

CANON_IP=$(az vm show -d -g "$RG" -n rszt-canonical --query publicIps -o tsv)
echo
echo "rszt-canonical provisioned in this account. Public IP: $CANON_IP"
echo "SSH in and run azure/run_canonical.sh whenever you want it to start."
echo "Keep $CANON_IP (and this account's subscription id) handy — merge_results.py"
echo "pulls results.db from here separately from the shapley account."
