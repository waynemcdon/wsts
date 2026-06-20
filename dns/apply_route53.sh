#!/usr/bin/env bash
# ── Apply WSTS DNS records to Route 53 + enable DNSSEC ───────────────────────
# Creates the wsts.spatcyber.com A record, null-MX/SPF for the non-email
# subdomain, DMARC sp=reject hardening, and CAA records; then walks through
# enabling DNSSEC signing on the hosted zone.
#
# Prereqs:  awscli v2 configured with Route53 permissions.
# Usage:    ./apply_route53.sh <SERVER_IP>
set -euo pipefail

DOMAIN="spatcyber.com"
RECORDS_JSON="$(dirname "$0")/route53_wsts_records.json"

SERVER_IP="${1:-}"
if [[ -z "$SERVER_IP" ]]; then
  echo "Usage: $0 <SERVER_IP>"
  echo "  e.g. $0 13.216.144.59"
  exit 1
fi

# ── 1. Resolve the hosted zone ID ───────────────────────────────────────────
echo "[1/4] Looking up hosted zone for ${DOMAIN}..."
ZONE_ID=$(aws route53 list-hosted-zones-by-name \
  --dns-name "${DOMAIN}." \
  --query "HostedZones[?Name=='${DOMAIN}.'].Id | [0]" \
  --output text | sed 's#/hostedzone/##')

if [[ -z "$ZONE_ID" || "$ZONE_ID" == "None" ]]; then
  echo "ERROR: Could not find hosted zone for ${DOMAIN}." >&2
  exit 1
fi
echo "       Zone ID: ${ZONE_ID}"

# ── 2. Inject the server IP into a temp copy of the change batch ─────────────
echo "[2/4] Preparing change batch (server IP: ${SERVER_IP})..."
TMP_JSON="$(mktemp)"
sed "s/REPLACE_WITH_SERVER_IP/${SERVER_IP}/g" "$RECORDS_JSON" > "$TMP_JSON"

# ── 3. Submit the record changes ────────────────────────────────────────────
echo "[3/4] Submitting record changes..."
CHANGE_ID=$(aws route53 change-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --change-batch "file://${TMP_JSON}" \
  --query "ChangeInfo.Id" --output text)
rm -f "$TMP_JSON"
echo "       Change submitted: ${CHANGE_ID}"
echo "       Waiting for INSYNC..."
aws route53 wait resource-record-sets-changed --id "$CHANGE_ID"
echo "       Records are live."

# ── 4. DNSSEC guidance (manual confirmation recommended) ────────────────────
cat <<EOF

[4/4] DNSSEC — enable signing on the hosted zone:

  # a) Create a KSK backed by a KMS key (asymmetric, ECC_NIST_P256, us-east-1):
  aws route53 create-key-signing-key \\
      --hosted-zone-id ${ZONE_ID} \\
      --key-management-service-arn <KMS_KEY_ARN> \\
      --name wsts_ksk --status ACTIVE

  # b) Enable DNSSEC signing:
  aws route53 enable-hosted-zone-dnssec --hosted-zone-id ${ZONE_ID}

  # c) Retrieve the DS record and add it at your registrar:
  aws route53 get-dnssec --hosted-zone-id ${ZONE_ID} \\
      --query "KeySigningKeys[0].DSRecord" --output text

Done. Verify with:
  dig +dnssec wsts.${DOMAIN} A @8.8.8.8
  nslookup -type=CAA ${DOMAIN} 8.8.8.8
EOF
