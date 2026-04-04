#!/usr/bin/env bash
# ============================================================================
# Generate self-signed TLS certificates for Craton HSM cluster testing.
#
# Creates a test CA, per-node server certificates, and an admin client cert.
# These are for TESTING ONLY -- do not use in production.
#
# Usage: ./gen-test-certs.sh [output_dir]
#        Default output: deploy/test-certs/
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/test-certs}"
DAYS=365
NODES=3

echo "=== Craton HSM Test Certificate Generator ==="
echo "Output: ${OUT_DIR}"
echo ""

mkdir -p "${OUT_DIR}"

# ── 1. Test CA ──────────────────────────────────────────────────────────────
echo "[1/3] Generating test CA (EC P-256)..."

openssl ecparam -genkey -name prime256v1 -noout -out "${OUT_DIR}/test-ca.key" 2>/dev/null
chmod 600 "${OUT_DIR}/test-ca.key"

openssl req -new -x509 -key "${OUT_DIR}/test-ca.key" \
    -out "${OUT_DIR}/test-ca.crt" \
    -days ${DAYS} \
    -subj "/CN=Craton HSM Test CA/O=Craton Test/C=US" \
    2>/dev/null

echo "  CA key:  ${OUT_DIR}/test-ca.key"
echo "  CA cert: ${OUT_DIR}/test-ca.crt"

# ── 2. Per-node server certificates ────────────────────────────────────────
echo ""
echo "[2/3] Generating server certificates for ${NODES} nodes..."

for i in $(seq 1 ${NODES}); do
    NODE_NAME="node${i}"
    echo "  Node ${i}:"

    # Generate key
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "${OUT_DIR}/${NODE_NAME}-server.key" 2>/dev/null
    chmod 600 "${OUT_DIR}/${NODE_NAME}-server.key"

    # Create SAN config
    cat > "${OUT_DIR}/${NODE_NAME}.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = hsm-${NODE_NAME}
O = Craton HSM Test
C = US

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = hsm-${NODE_NAME}
DNS.3 = hsm-node-${i}
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Generate CSR
    openssl req -new -key "${OUT_DIR}/${NODE_NAME}-server.key" \
        -out "${OUT_DIR}/${NODE_NAME}-server.csr" \
        -config "${OUT_DIR}/${NODE_NAME}.cnf" \
        2>/dev/null

    # Sign with CA
    openssl x509 -req -in "${OUT_DIR}/${NODE_NAME}-server.csr" \
        -CA "${OUT_DIR}/test-ca.crt" -CAkey "${OUT_DIR}/test-ca.key" \
        -CAcreateserial -out "${OUT_DIR}/${NODE_NAME}-server.crt" \
        -days ${DAYS} \
        -extensions v3_req -extfile "${OUT_DIR}/${NODE_NAME}.cnf" \
        2>/dev/null

    # Clean up CSR and temp config
    rm -f "${OUT_DIR}/${NODE_NAME}-server.csr" "${OUT_DIR}/${NODE_NAME}.cnf"

    echo "    Key:  ${OUT_DIR}/${NODE_NAME}-server.key"
    echo "    Cert: ${OUT_DIR}/${NODE_NAME}-server.crt"
done

# ── 3. Admin client certificate (for mTLS) ─────────────────────────────────
echo ""
echo "[3/3] Generating admin client certificate..."

openssl ecparam -genkey -name prime256v1 -noout \
    -out "${OUT_DIR}/admin-client.key" 2>/dev/null
chmod 600 "${OUT_DIR}/admin-client.key"

cat > "${OUT_DIR}/admin-client.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = HSM Admin
O = Craton HSM Test
C = US

[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "${OUT_DIR}/admin-client.key" \
    -out "${OUT_DIR}/admin-client.csr" \
    -config "${OUT_DIR}/admin-client.cnf" \
    2>/dev/null

openssl x509 -req -in "${OUT_DIR}/admin-client.csr" \
    -CA "${OUT_DIR}/test-ca.crt" -CAkey "${OUT_DIR}/test-ca.key" \
    -CAcreateserial -out "${OUT_DIR}/admin-client.crt" \
    -days ${DAYS} \
    -extensions v3_req -extfile "${OUT_DIR}/admin-client.cnf" \
    2>/dev/null

rm -f "${OUT_DIR}/admin-client.csr" "${OUT_DIR}/admin-client.cnf" "${OUT_DIR}/test-ca.srl"
chmod 644 "${OUT_DIR}"/*.crt

echo "  Key:  ${OUT_DIR}/admin-client.key"
echo "  Cert: ${OUT_DIR}/admin-client.crt"

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=== Certificate generation complete ==="
echo ""
echo "Files generated:"
ls -la "${OUT_DIR}"/*.{key,crt} 2>/dev/null | awk '{print "  " $NF " (" $5 " bytes)"}'
echo ""
echo "WARNING: These certificates are for TESTING ONLY."
echo "         Do NOT use in production deployments."
