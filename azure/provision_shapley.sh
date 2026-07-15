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

echo "== rszt-shapley (each worker runs a KIND cluster AND a k3s instance, sized up) =="
az vm create \
  -g "$RG" -n rszt-shapley \
  --image Ubuntu2204 \
  --size Standard_D48s_v5 \
  --vnet-name "$VNET" --subnet "$SUBNET" --nsg "$NSG" \
  --admin-username "$ADMIN_USER" --ssh-key-values "$SSH_KEY" \
  --os-disk-size-gb 384 \
  --assign-identity '[system]' \
  --custom-data azure/cloud-init-common.yaml \
  --tags role=shapley study=right-sizing-zero-trust >/dev/null

SHAP_PRINCIPAL=$(az vm identity show -g "$RG" -n rszt-shapley --query principalId -o tsv)
SHAP_ID=$(az vm show -g "$RG" -n rszt-shapley --query id -o tsv)
az role assignment create --assignee "$SHAP_PRINCIPAL" --role "Virtual Machine Contributor" \
  --scope "$SHAP_ID" >/dev/null

SHAP_IP=$(az vm show -d -g "$RG" -n rszt-shapley --query publicIps -o tsv)
echo
echo "rszt-shapley provisioned in this account. Public IP: $SHAP_IP"
echo "SSH in and run azure/run_shapley.sh whenever you want it to start —"
echo "it can run at the same time as rszt-canonical in the other account."
echo "Keep $SHAP_IP handy — merge_results.py pulls results.db from here"
echo "separately from the canonical account."
