#!/bin/sh
# Test-only SPIFFE fixtures for creche-sink: a trust bundle and SVIDs, all P-256.
# CA keys are thrown away once used. Only the sink's leaf key is kept, and it
# signs nothing but test data. Run from this directory to regenerate.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ext() { printf '%s\n' "$@" > "$tmp/ext"; }
# cert NAME KEY ISSUER_CERT ISSUER_KEY NOT_BEFORE NOT_AFTER EXT_LINES...
cert() {
	name=$1 k=$2 icert=$3 ikey=$4 nb=$5 na=$6
	shift 6
	ext "$@"
	openssl req -new -key "$k" -subj "/O=creche test/CN=$name" -out "$tmp/$name.csr" 2>/dev/null
	openssl x509 -req -in "$tmp/$name.csr" -CA "$icert" -CAkey "$ikey" -set_serial "0x$(openssl rand -hex 8)" \
		-not_before "$nb" -not_after "$na" -extfile "$tmp/ext" -sha256 -outform DER -out "$name.der" 2>/dev/null
}
CA_EXT="basicConstraints=critical,CA:true"
LEAF_EXT="basicConstraints=critical,CA:false"
NB=20260101000000Z NA=21260101000000Z

# Trust bundle: a self-signed root.
key "$tmp/root.key"
openssl req -x509 -new -key "$tmp/root.key" -subj "/O=creche test/CN=root" -sha256 \
	-not_before $NB -not_after $NA -addext "$CA_EXT" -out bundle.pem 2>/dev/null
openssl x509 -in bundle.pem -outform DER -out "$tmp/root.der"
openssl x509 -in bundle.pem -out "$tmp/root.pem"

# The sink's SVID, from the root, and its key.
key "$tmp/sink.key"
openssl pkcs8 -topk8 -nocrypt -in "$tmp/sink.key" -outform DER -out sink.key.der
cert sink "$tmp/sink.key" "$tmp/root.pem" "$tmp/root.key" $NB $NA "$LEAF_EXT" "subjectAltName=URI:spiffe://creche.test/sink"

# An SVID through an intermediate CA.
key "$tmp/inter.key"
cert inter "$tmp/inter.key" "$tmp/root.pem" "$tmp/root.key" $NB $NA "$CA_EXT"
openssl x509 -inform DER -in inter.der -out "$tmp/inter.pem"
cert via-inter "$tmp/sink.key" "$tmp/inter.pem" "$tmp/inter.key" $NB $NA "$LEAF_EXT" "subjectAltName=URI:spiffe://creche.test/sink"

# SVIDs that must not be trusted.
cert expired "$tmp/sink.key" "$tmp/root.pem" "$tmp/root.key" 20200101000000Z 20210101000000Z "$LEAF_EXT" "subjectAltName=URI:spiffe://creche.test/sink"
cert no-spiffe-id "$tmp/sink.key" "$tmp/root.pem" "$tmp/root.key" $NB $NA "$LEAF_EXT" "subjectAltName=DNS:sink.creche.test"
cert leaf-is-ca "$tmp/sink.key" "$tmp/root.pem" "$tmp/root.key" $NB $NA "$CA_EXT" "subjectAltName=URI:spiffe://creche.test/sink"
key "$tmp/other.key"
openssl req -x509 -new -key "$tmp/other.key" -subj "/O=creche test/CN=root" -sha256 \
	-not_before $NB -not_after $NA -addext "$CA_EXT" -out "$tmp/other.pem" 2>/dev/null
cert foreign "$tmp/sink.key" "$tmp/other.pem" "$tmp/other.key" $NB $NA "$LEAF_EXT" "subjectAltName=URI:spiffe://creche.test/sink"
# An intermediate that is not a CA, issuing an SVID.
key "$tmp/notca.key"
cert not-ca "$tmp/notca.key" "$tmp/root.pem" "$tmp/root.key" $NB $NA "$LEAF_EXT"
openssl x509 -inform DER -in not-ca.der -out "$tmp/notca.pem"
cert via-not-ca "$tmp/sink.key" "$tmp/notca.pem" "$tmp/notca.key" $NB $NA "$LEAF_EXT" "subjectAltName=URI:spiffe://creche.test/sink"
