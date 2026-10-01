#!/usr/bin/env python3
"""APK Signature Scheme v2 — signer and verifier, no Android SDK required.

Why this exists: this project ships a WebView APK that must be re-signed after every
asset repack, but the machine used to build it only has a JDK (no `apksigner`). The
scheme is small and fully specified, so it is implemented here and cross-checked against
an APK that really is v2-signed (`verify` reproduces the digests a real signer wrote,
which proves the chunking / prefix / section logic is right).

The digest algorithm, mirroring com.android.apksig.internal.apk.ApkSigningBlockUtils:
    * three segments: ZIP entries, ZIP central directory, ZIP EOCD
    * WITH THE EOCD'S CENTRAL-DIRECTORY-OFFSET FIELD REWRITTEN to the offset at which the
      APK Signing Block starts (that is what makes the digest reproducible from the final
      file, where the real field points past the block)
    * each segment split into 1 MiB chunks; chunk digest = H(0xa5 || u32le(len) || chunk)
    * segment digest = H(0x5a || u32le(total chunk count) || concat(chunk digests))
    * empty segments contribute no chunks

Design notes:
  * v2 only. `minSdkVersion` is 24, and API 24 is exactly where v2 support starts, so a
    v2-only signature is understood by every device the package can be installed on.
    (v1/JAR signing is deliberately NOT added: `jarsigner` rewrites the archive, and
    Android 11+ requires `resources.arsc` to stay uncompressed — a repack risk for no gain.)
  * Every byte of the ZIP entry data is left untouched. Only a signing block is inserted
    immediately before the central directory, and the EOCD central-directory offset is
    patched. Entry CRCs therefore still match the unsigned input.
  * Key handling uses the `cryptography` package when present (PKCS#12 or PEM), and falls
    back to the `openssl` CLI. Verification is pure Python, so it works with neither.

Usage:
    python tools/apk_v2_sign.py keygen --out signing/local.p12 --password <pw>
    python tools/apk_v2_sign.py sign <in.apk> <out.apk> --p12 signing/local.p12 --p12-pass <pw>
    python tools/apk_v2_sign.py sign <in.apk> <out.apk> --key k.pem --cert c.pem
    python tools/apk_v2_sign.py verify <apk> [<apk> ...]
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import shutil
import struct
import subprocess

V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
VERITY_PADDING_BLOCK_ID = 0x42726577
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
EOCD_MAGIC = b"PK\x05\x06"
EOCD_CD_OFFSET_FIELD = 16          # byte offset of the central-directory offset inside the EOCD
CHUNK = 1 << 20                    # CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES
ALGOS = {0x0101: "sha256", 0x0102: "sha512", 0x0103: "sha256", 0x0104: "sha512"}
SIGN_ALGO_ID = 0x0101              # RSASSA-PKCS1-v1_5 with SHA-256
SIGN_ALGO = "sha256"


def lp(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def lp_seq(elements) -> bytes:
    """A length-prefixed sequence: uint32 total, then every element length-prefixed.

    This is apksig's encodeAsSequenceOfLengthPrefixedElements: each element gets its own
    uint32 length, and the concatenation is wrapped in one more uint32 length. (The extra
    per-element length is what makes the digests and signatures lists self-delimiting.)
    """
    return lp(b"".join(lp(e) for e in elements))


# ── ZIP landmark discovery ────────────────────────────────────────────────────────────

def find_eocd(data: bytes):
    """Return (eocd_offset, cd_size, cd_offset, comment_len)."""
    start = max(0, len(data) - (65535 + 22))
    idx = data.rfind(EOCD_MAGIC, start)
    if idx < 0:
        raise ValueError("no End Of Central Directory record found — is this a ZIP/APK?")
    _sig, _d1, _d2, _n1, _n2, cd_size, cd_off, comment_len = struct.unpack_from("<IHHHHIIH", data, idx)
    if idx + 22 + comment_len != len(data):
        raise ValueError(f"EOCD comment length does not reach EOF ({idx + 22 + comment_len} != {len(data)})")
    if cd_off + cd_size > len(data):
        raise ValueError("EOCD central directory runs past EOF")
    return idx, cd_size, cd_off, comment_len


def locate_signing_block(data: bytes, cd_offset: int):
    """Return (block_start, block_end) of the APK Signing Block, or None."""
    if cd_offset < 24 or data[cd_offset - 16:cd_offset] != APK_SIG_BLOCK_MAGIC:
        return None
    size_at_tail = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    start = cd_offset - 8 - size_at_tail
    if start < 0:
        raise ValueError("APK Signing Block size overflows the file")
    if struct.unpack_from("<Q", data, start)[0] != size_at_tail:
        raise ValueError("APK Signing Block size fields disagree")
    return start, cd_offset


def iter_block_pairs(data: bytes, start: int, end: int):
    p = start + 8
    limit = end - 24
    while p < limit:
        length = struct.unpack_from("<Q", data, p)[0]
        if length < 4 or p + 8 + length > limit:
            raise ValueError(f"malformed ID-value pair at {p}")
        pid = struct.unpack_from("<I", data, p + 8)[0]
        yield pid, data[p + 12:p + 8 + length]
        p += 8 + length
    if p != limit:
        raise ValueError("ID-value pairs do not fill the signing block exactly")


def segments(data: bytes):
    """Return (eocd_off, cd_size, cd_off, block_start, entries, central_dir, eocd)."""
    eocd_off, cd_size, cd_off, _comment = find_eocd(data)
    located = locate_signing_block(data, cd_off)
    block_start = located[0] if located else cd_off
    return (eocd_off, cd_size, cd_off, block_start,
            data[:block_start], data[cd_off:cd_off + cd_size], data[eocd_off:])


def eocd_for_digesting(eocd: bytes, block_start: int) -> bytes:
    """A copy of the EOCD whose central-directory offset points at the signing block."""
    out = bytearray(eocd)
    struct.pack_into("<I", out, EOCD_CD_OFFSET_FIELD, block_start)
    return bytes(out)


# ── v2 block structure ────────────────────────────────────────────────────────────────

class Reader:
    def __init__(self, buf: bytes):
        self.buf, self.p = buf, 0

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.buf, self.p)[0]
        self.p += 4
        return v

    def lp(self) -> bytes:
        n = self.u32()
        v = self.buf[self.p:self.p + n]
        if len(v) != n:
            raise ValueError("length-prefixed field runs past the buffer")
        self.p += n
        return v

    def lp_seq(self):
        """A length-prefixed sequence: uint32 total, then length-prefixed elements."""
        n = self.u32()
        end = self.p + n
        out = []
        while self.p < end:
            out.append(self.lp())
        if self.p != end:
            raise ValueError("length-prefixed sequence is not self-consistent")
        return out

    def at_end(self) -> bool:
        return self.p == len(self.buf)


def _alg_and_lp(element: bytes):
    """Split a `uint32 algorithm id || length-prefixed value` element pair."""
    alg = struct.unpack_from("<I", element, 0)[0]
    return alg, Reader(element[4:]).lp()


def parse_v2_block(block: bytes):
    """Yield one dict per signer: {digests, certs, signatures, public_key}.

    `signed data` is (V2SchemeSigner.generateSignerBlock):
        length-prefixed sequence of length-prefixed digests
        length-prefixed sequence of certificates
        length-prefixed additional attributes   (empty blob when v3 signing is off)
        length-prefixed empty byte array        <- present even for v2-only signatures
    """
    r = Reader(block)
    signers = []
    for raw_signer in r.lp_seq():
        s = Reader(raw_signer)
        signed_data = s.lp()
        signatures = s.lp_seq()
        public_key = s.lp()
        if not s.at_end():
            raise ValueError("trailing bytes inside a v2 signer")
        d = Reader(signed_data)
        digests = d.lp_seq()
        certs = d.lp_seq()
        attrs = d.lp()
        reserved = d.lp()
        if reserved:
            raise ValueError("the reserved trailing element of v2 signed data is not empty")
        if not d.at_end():
            raise ValueError(f"trailing bytes inside v2 signed data ({len(signed_data) - d.p} left)")
        signers.append({
            "signed_data": signed_data,
            "digests": [_alg_and_lp(x) for x in digests],
            "certs": certs,
            "signatures": [_alg_and_lp(x) for x in signatures],
            "attributes": attrs,
            "public_key": public_key,
        })
    if not r.at_end():
        raise ValueError("trailing bytes after the v2 signer sequence")
    return signers


# ── content digest ────────────────────────────────────────────────────────────────────

def content_digest(entries: bytes, central_dir: bytes, eocd: bytes, algo: str) -> bytes:
    """Digest the three segments exactly as ApkSigningBlockUtils.computeOneMbChunkContentDigests does."""
    h = getattr(hashlib, algo)
    chunks = []
    for blob in (entries, central_dir, eocd):
        pos = 0
        while pos < len(blob):                       # empty segments contribute no chunks
            n = min(CHUNK, len(blob) - pos)
            chunks.append(h(b"\xa5" + struct.pack("<I", n) + blob[pos:pos + n]).digest())
            pos += n
    return h(b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()


def digest_algorithm_for(signature_algorithm_id: int):
    return ALGOS.get(signature_algorithm_id)


# ── key material ──────────────────────────────────────────────────────────────────────
# Two interchangeable back ends: the `cryptography` package (preferred: reads PKCS#12 or
# PEM, no external process) and the `openssl` CLI (fallback). Both expose the three things
# a v2 signer needs: the certificate DER, the SubjectPublicKeyInfo DER, and a raw signature.

class CryptoKeyMaterial:
    """Backed by the `cryptography` package."""

    def __init__(self, private_key, certificate, label: str):
        self.key = private_key
        self.cert = certificate
        self.label = label

    @classmethod
    def from_p12(cls, path: str, password: str | None):
        from cryptography.hazmat.primitives.serialization import pkcs12
        blob = open(path, "rb").read()
        key, cert, extra = pkcs12.load_key_and_certificates(
            blob, password.encode() if password else None)
        if key is None or cert is None:
            raise SystemExit(f"{path}: no private key / certificate found")
        if extra:
            print(f"  note: {len(extra)} extra certificate(s) in the chain are not used")
        return cls(key, cert, path)

    @classmethod
    def from_pem(cls, key_path: str, cert_path: str, password: str | None):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(open(key_path, "rb").read(),
                                   password.encode() if password else None)
        cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
        return cls(key, cert, key_path)

    def cert_der(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding
        return self.cert.public_bytes(Encoding.DER)

    def public_key_der(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def signature_length(self, algo: str) -> int:
        return (self.key.key_size + 7) // 8

    def sign(self, message: bytes, algo: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        table = {"sha256": hashes.SHA256, "sha512": hashes.SHA512}
        return self.key.sign(message, padding.PKCS1v15(), table[algo]())

    def describe(self) -> str:
        return (f"{self.label}: {type(self.key).__name__} {getattr(self.key, 'key_size', '?')}-bit, "
                f"cert subject {self.cert.subject.rfc4514_string()}, "
                f"serial {self.cert.serial_number:x}")


class OpenSslKeyMaterial:
    """Backed by the openssl CLI (PEM key + PEM certificate)."""

    def __init__(self, exe: str | None, key_path: str, cert_path: str):
        self.exe = exe or shutil.which("openssl")
        if not self.exe:
            raise SystemExit("neither the `cryptography` package nor openssl is available")
        self.key_path, self.cert_path = key_path, cert_path
        self.label = key_path

    def run(self, *args, stdin: bytes | None = None) -> bytes:
        proc = subprocess.run([self.exe, *args], input=stdin, capture_output=True)
        if proc.returncode != 0:
            raise SystemExit(f"openssl {' '.join(args)} failed:\n{proc.stderr.decode('utf-8', 'replace')}")
        return proc.stdout

    def cert_der(self) -> bytes:
        return self.run("x509", "-in", self.cert_path, "-outform", "DER")

    def public_key_der(self) -> bytes:
        pem = self.run("x509", "-in", self.cert_path, "-pubkey", "-noout")
        return self.run("pkey", "-pubin", "-outform", "DER", stdin=pem)

    def sign(self, message: bytes, algo: str) -> bytes:
        return self.run("dgst", f"-{algo}", "-sign", self.key_path, stdin=message)

    def signature_length(self, algo: str) -> int:
        return len(self.sign(b"probe", algo))       # RSA PKCS#1 v1.5 length == modulus length

    def describe(self) -> str:
        return f"{self.label} (openssl)"


def load_key_material(a) -> object:
    """Pick a back end from the CLI options, preferring `cryptography` when installed."""
    try:
        import cryptography  # noqa: F401
        have_crypto = True
    except ImportError:
        have_crypto = False

    if a.p12:
        if not have_crypto:
            raise SystemExit("--p12 needs the `cryptography` package (pip install cryptography)")
        return CryptoKeyMaterial.from_p12(a.p12, a.p12_pass)
    if not (a.key and a.cert):
        raise SystemExit("sign needs --p12, or --key together with --cert")
    if have_crypto:
        return CryptoKeyMaterial.from_pem(a.key, a.cert, a.key_pass)
    return OpenSslKeyMaterial(a.openssl, a.key, a.cert)


def keygen(out_path: str, password: str, days: int, common_name: str) -> None:
    """Create a self-signed RSA-2048 PKCS#12 for local, sideloaded builds."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise SystemExit("keygen needs the `cryptography` package (pip install cryptography)")

    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "I.L.Y")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    blob = pkcs12.serialize_key_and_certificates(
        common_name.encode(), key, cert, None,
        serialization.BestAvailableEncryption(password.encode()))
    with open(out_path, "wb") as fh:
        fh.write(blob)
    print(f"wrote {out_path}")
    print(f"  RSA-2048, valid {days} days, subject {name.rfc4514_string()}")
    print(f"  serial {cert.serial_number:x}, SHA-256 fingerprint "
          f"{cert.fingerprint(hashes.SHA256()).hex()}")
    print("  KEEP THIS FILE: every future build must be signed with it to be upgradeable.")


# ── RSA verification (pure Python: no scratch files, no external process) ─────────────

def _der(buf: bytes, pos: int):
    """Minimal DER TLV reader -> (tag, value, next_pos)."""
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, buf[pos:pos + length], pos + length


def rsa_public_key(spki: bytes):
    """Extract (modulus, exponent) from an X.509 SubjectPublicKeyInfo."""
    _tag, seq, _ = _der(spki, 0)                 # SEQUENCE
    _tag, _alg, p = _der(seq, 0)                 # AlgorithmIdentifier
    _tag, bits, _ = _der(seq, p)                 # BIT STRING
    if not bits or bits[0] != 0:
        raise ValueError("unexpected BIT STRING padding in SubjectPublicKeyInfo")
    _tag, rsaseq, _ = _der(bits[1:], 0)          # RSAPublicKey SEQUENCE
    _tag, n_bytes, p2 = _der(rsaseq, 0)          # modulus INTEGER
    _tag, e_bytes, _ = _der(rsaseq, p2)          # publicExponent INTEGER
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


# DigestInfo prefixes (RFC 8017), i.e. the ASN.1 wrapper around a bare hash.
DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def pkcs1_v15_verify(spki: bytes, message: bytes, signature: bytes, algo: str) -> bool:
    n, e = rsa_public_key(spki)
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    t = DIGEST_INFO_PREFIX[algo] + getattr(hashlib, algo)(message).digest()
    if len(t) > k - 11:
        return False
    return em == b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t


# ── verify ────────────────────────────────────────────────────────────────────────────

def verify(apk: str) -> bool:
    data = open(apk, "rb").read()
    eocd_off, cd_size, cd_off, block_start, entries, central_dir, eocd = segments(data)
    print(f"  {apk}")
    print(f"    entries: {len(entries)} bytes   central dir: {cd_off}..{cd_off + cd_size}   EOCD at {eocd_off}")
    if block_start == cd_off:
        print("    NO APK Signing Block -> unsigned or v1-only")
        return False
    print(f"    signing block: {block_start}..{cd_off} ({cd_off - block_start} bytes)")

    signers = None
    labels = {V2_BLOCK_ID: "v2", V3_BLOCK_ID: "v3", VERITY_PADDING_BLOCK_ID: "verity padding"}
    for pid, value in iter_block_pairs(data, block_start, cd_off):
        print(f"    block {hex(pid)} ({labels.get(pid, 'unknown')}), {len(value)} bytes")
        if pid == V2_BLOCK_ID:
            signers = parse_v2_block(value)
    if not signers:
        print("    v2 block absent")
        return False

    view = eocd_for_digesting(eocd, block_start)
    ok = True
    for i, signer in enumerate(signers):
        print(f"    signer {i}: {len(signer['digests'])} digest(s), {len(signer['signatures'])} signature(s), "
              f"{len(signer['certs'])} cert(s), pubkey {len(signer['public_key'])} bytes")
        for alg, stored in signer["digests"]:
            name = digest_algorithm_for(alg)
            if not name:
                print(f"      digest alg {hex(alg)}: not evaluated")
                continue
            got = content_digest(entries, central_dir, view, name)
            match = got == stored
            ok = ok and match
            print(f"      content digest {name} (alg {hex(alg)}): {'MATCH' if match else 'MISMATCH'}")
            if not match:
                print(f"        stored  {stored.hex()}\n        actual  {got.hex()}")
        if signer["certs"] or signer["public_key"]:
            for alg, sig in signer["signatures"]:
                name = digest_algorithm_for(alg)
                if name is None:
                    print(f"      signature alg {hex(alg)}: unknown algorithm")
                    continue
                if alg in (0x0103, 0x0104):
                    print(f"      signature alg {hex(alg)}: RSASSA-PSS, not evaluated here")
                    continue
                try:
                    good = pkcs1_v15_verify(signer["public_key"], signer["signed_data"], sig, name)
                except Exception as err:                     # noqa: BLE001 - report, do not crash
                    print(f"      signature alg {hex(alg)}: could not verify ({err})")
                    ok = False
                    continue
                ok = ok and good
                print(f"      signature alg {hex(alg)} over signed data: {'VALID' if good else 'INVALID'}")
    print(f"    => {'SIGNED, v2 integrity OK' if ok else 'SIGNATURE PROBLEM'}")
    return ok


# ── sign ─────────────────────────────────────────────────────────────────────────────

def build_block(v2_block: bytes) -> bytes:
    pair = struct.pack("<Q", 4 + len(v2_block)) + struct.pack("<I", V2_BLOCK_ID) + v2_block
    size = len(pair) + 8 + 16
    return struct.pack("<Q", size) + pair + struct.pack("<Q", size) + APK_SIG_BLOCK_MAGIC


def build_signed_data(digest_entries, cert_der: bytes) -> bytes:
    """`signed data`, i.e. exactly what the RSA signature is computed over.

    Layout mirrors V2SchemeSigner.generateSignerBlock, including the trailing empty byte
    array that is emitted even when no additional attributes are present.
    """
    return (lp_seq(digest_entries)      # each entry: uint32 signature algorithm id || lp(digest)
            + lp_seq([cert_der])        # X.509 certificates, DER
            + lp(b"")                   # additional attributes (none: v2-only signature)
            + lp(b""))                  # reserved trailing element


def build_v2_block(digest_entries, cert_der: bytes, spki: bytes, signature: bytes) -> bytes:
    signed_data = build_signed_data(digest_entries, cert_der)
    signature_entry = struct.pack("<I", SIGN_ALGO_ID) + lp(signature)
    signer = lp(signed_data) + lp_seq([signature_entry]) + lp(spki)
    return lp_seq([signer])


def sign(in_apk: str, out_apk: str, material) -> None:
    data = open(in_apk, "rb").read()
    eocd_off, cd_size, cd_off, comment_len = find_eocd(data)
    if locate_signing_block(data, cd_off):
        raise SystemExit("input already has an APK Signing Block; sign the unsigned repack instead")
    if comment_len:
        raise SystemExit("EOCD has a comment; not handled")
    print(f"  signing key -> {material.describe()}")

    cert_der = material.cert_der()
    spki = material.public_key_der()
    sig_len = material.signature_length(SIGN_ALGO)

    # The block width must be known before the digests exist: the EOCD's real central-directory
    # offset has to point past the block. Both the RSA signature and the content digest have
    # fixed sizes, so placeholders of the right width give the final block size exactly.
    placeholder = [struct.pack("<I", SIGN_ALGO_ID) + lp(b"\x00" * hashlib.new(SIGN_ALGO).digest_size)]
    block_size = len(build_block(build_v2_block(placeholder, cert_der, spki, b"\x00" * sig_len)))

    block_start = cd_off                       # where the signing block (and thus the digesting
    new_cd_off = cd_off + block_size           # view) starts, vs. where the CD really lands
    real_eocd = bytearray(data[eocd_off:])
    struct.pack_into("<I", real_eocd, EOCD_CD_OFFSET_FIELD, new_cd_off)
    entries = data[:block_start]
    central_dir = data[cd_off:cd_off + cd_size]

    view = eocd_for_digesting(bytes(real_eocd), block_start)
    digest_entries = [
        struct.pack("<I", SIGN_ALGO_ID) + lp(content_digest(entries, central_dir, view, SIGN_ALGO))
    ]

    signed_data = build_signed_data(digest_entries, cert_der)
    signature = material.sign(signed_data, SIGN_ALGO)
    if len(signature) != sig_len:
        raise SystemExit(f"unexpected signature length {len(signature)} (expected {sig_len})")

    block = build_block(build_v2_block(digest_entries, cert_der, spki, signature))
    if len(block) != block_size:
        raise SystemExit(f"signing block size is not stable ({len(block)} != {block_size})")

    out = entries + block + central_dir + bytes(real_eocd)
    with open(out_apk, "wb") as fh:
        fh.write(out)
    print(f"wrote {out_apk}")
    print(f"  {len(out)} bytes, signing block {len(block)} bytes, "
          f"central directory {cd_off} -> {new_cd_off}, RSA signature {sig_len} bytes")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["sign", "verify", "keygen"])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--key", help="PEM private key")
    ap.add_argument("--cert", help="PEM certificate")
    ap.add_argument("--key-pass", default=None, help="passphrase for --key")
    ap.add_argument("--p12", help="PKCS#12 keystore (needs the `cryptography` package)")
    ap.add_argument("--p12-pass", default=None, help="passphrase for --p12")
    ap.add_argument("--openssl", default=None, help="openssl executable for the PEM back end")
    ap.add_argument("--out", help="keygen: output .p12 path")
    ap.add_argument("--password", default=None, help="keygen: passphrase for the new .p12")
    ap.add_argument("--days", type=int, default=10950, help="keygen: validity in days")
    ap.add_argument("--cn", default="I.L.Y local test", help="keygen: certificate common name")
    a = ap.parse_args()

    if a.mode == "verify":
        if not a.paths:
            raise SystemExit("verify needs at least one APK path")
        return 0 if all(verify(p) for p in a.paths) else 1

    if a.mode == "keygen":
        out = a.out or (a.paths[0] if a.paths else None)
        if not out:
            raise SystemExit("keygen needs --out <file.p12>")
        password = a.password or getpass.getpass("new keystore passphrase: ")
        keygen(out, password, a.days, a.cn)
        return 0

    if len(a.paths) != 2:
        raise SystemExit("sign needs <in.apk> <out.apk>")
    sign(a.paths[0], a.paths[1], load_key_material(a))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
