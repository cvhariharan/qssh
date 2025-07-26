#!/bin/bash

# Generate test certificates for mTLS testing
# This script creates:
# - CA certificate and key (ca.crt, ca.key)
# - Server certificate and key (server.crt, server.key)
# - Client certificate and key (client.crt, client.key)

set -e

# Create CA private key
openssl genrsa -out ca.key 4096

# Create CA certificate
openssl req -new -x509 -key ca.key -sha256 -subj "/C=US/ST=Test/L=Test/O=TestCA/CN=Test CA" -days 3650 -out ca.crt

# Create server private key
openssl genrsa -out server.key 4096

# Create server certificate request
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Test/L=Test/O=TestServer/CN=localhost"

# Create server certificate extensions file
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext

# Create client private key
openssl genrsa -out client.key 4096

# Create client certificate request
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=Test/L=Test/O=TestClient/CN=testclient"

# Create client certificate extensions file
cat > client.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile client.ext

# Clean up temporary files
rm server.csr client.csr server.ext client.ext ca.srl

echo "Test certificates generated successfully:"
echo "  CA: ca.crt, ca.key"
echo "  Server: server.crt, server.key"
echo "  Client: client.crt, client.key"