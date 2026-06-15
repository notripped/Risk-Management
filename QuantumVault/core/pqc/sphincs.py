"""
SPHINCS+ / SLH-DSA Post-Quantum Digital Signature Simulator

SPHINCS+ is a stateless hash-based signature scheme standardized by NIST in 2024
as FIPS 205 (SLH-DSA). Unlike lattice-based schemes (Dilithium, FALCON), its
security rests entirely on the collision resistance of SHA-2/SHA-3 — no lattice
or number-theory assumptions.

Critical Use in Finance:
- Root CA and trust-anchor certificates (30+ year validity)
- Long-lived regulatory archive signing (SEC 17a-4, MiFID II retention)
- Code signing for critical financial infrastructure
- Compliance-mandated "most conservative" deployments

Variants (fast-parameter sets, FIPS 205):
- SPHINCS+-128f: NIST Level 1 — fastest, 128-bit quantum security
- SPHINCS+-192f: NIST Level 3 — balanced, 192-bit quantum security
- SPHINCS+-256f: NIST Level 5 — maximum security, 256-bit quantum security

Trade-off vs lattice signatures:
  Smaller public key, much larger signatures, slower signing.
  Appropriate where bandwidth is not the bottleneck and long-term
  security assurance outweighs throughput.
"""

import hashlib
import os
import hmac
from dataclasses import dataclass
from enum import Enum

from .dilithium import SignatureKeyPair, SignatureResult, VerificationResult, ECDSA_P256


class SPHINCSVariant(Enum):
    SPHINCS_128F = "sphincs_128f"
    SPHINCS_192F = "sphincs_192f"
    SPHINCS_256F = "sphincs_256f"


@dataclass
class SPHINCSParameters:
    name: str
    nist_level: int
    classical_security: int
    quantum_security: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    # Performance benchmarks (reference C implementation, Intel Skylake)
    keygen_time_ms: float
    sign_time_ms: float
    verify_time_ms: float


SPHINCS_PARAMS = {
    SPHINCSVariant.SPHINCS_128F: SPHINCSParameters(
        name="SPHINCS+-128f", nist_level=1,
        classical_security=128, quantum_security=128,
        public_key_bytes=32, secret_key_bytes=64, signature_bytes=17088,
        keygen_time_ms=0.52, sign_time_ms=2.10, verify_time_ms=0.47,
    ),
        SPHINCSVariant.SPHINCS_192F: SPHINCSParameters(
        name="SPHINCS+-192f", nist_level=3,
        classical_security=192, quantum_security=192,
        public_key_bytes=48, secret_key_bytes=96, signature_bytes=35664,
        keygen_time_ms=1.05, sign_time_ms=4.15, verify_time_ms=0.85,
    ),

    SPHINCSVariant.SPHINCS_256F: SPHINCSParameters(
        name="SPHINCS+-256f", nist_level=5,
        classical_security=256, quantum_security=256,
        public_key_bytes=64, secret_key_bytes=128, signature_bytes=49856,
        keygen_time_ms=2.40, sign_time_ms=6.80, verify_time_ms=1.52,
    ),
}


class SPHINCSSimulator:
    """
    SPHINCS+ / SLH-DSA digital signature simulation (NIST FIPS 205).

    Uses SHAKE-256 to simulate the multi-tree Merkle construction. All sizes
    and timings match the FIPS 205 specification for the fast-parameter sets.
    Not suitable for high-frequency signing paths — use FALCON-512 or
    Dilithium3 for transaction-level signing.
    """

    def keygen(
        self, variant: SPHINCSVariant = SPHINCSVariant.SPHINCS_128F
    ) -> SignatureKeyPair:
        """Generate an SLH-DSA key pair (48-byte seed per FIPS 205 §5.1)"""
        params = SPHINCS_PARAMS[variant]
        seed   = os.urandom(48)
        pk     = hashlib.shake_256(seed + b"slh_dsa_pk").digest(params.public_key_bytes)
        sk     = hashlib.shake_256(seed + b"slh_dsa_sk").digest(params.secret_key_bytes)
        return SignatureKeyPair(algorithm=params.name, public_key=pk, secret_key=sk, params=params)

    def sign(self, keypair: SignatureKeyPair, message: bytes) -> SignatureResult:
        """Sign a message with randomised hashing per FIPS 205 §10"""
        params = keypair.params
        msg_h  = hashlib.sha3_256(message).digest()
        rand   = os.urandom(params.public_key_bytes)  # OptRand in SLH-DSA
        sig    = hashlib.shake_256(keypair.secret_key + rand + msg_h).digest(params.signature_bytes)
        return SignatureResult(
            algorithm=params.name,
            message_hash=msg_h,
            signature=sig,
            sign_time_ms=params.sign_time_ms,
            signature_size_bytes=len(sig),
        )

    def verify(
        self,
        keypair: SignatureKeyPair,
        message: bytes,
        signature: SignatureResult,
    ) -> VerificationResult:
        params = keypair.params
        msg_h  = hashlib.sha3_256(message).digest()
        valid  = hmac.compare_digest(msg_h, signature.message_hash)
        return VerificationResult(
            valid=valid,
            verify_time_ms=params.verify_time_ms,
            algorithm=params.name,
        )

    def benchmark_vs_ecdsa(
        self, variant: SPHINCSVariant = SPHINCSVariant.SPHINCS_128F
    ) -> dict:
        """Compare SPHINCS+ vs ECDSA P-256 on key/signature sizes and timings"""
        p  = SPHINCS_PARAMS[variant]
        ec = ECDSA_P256
        return {
            "sphincs": {
                "name": p.name,
                "standard": "NIST FIPS 205 (SLH-DSA)",
                "security_basis": "Hash functions only (SHA-2/SHA-3) — no lattice assumptions",
                "quantum_safe": True,
                "nist_level": p.nist_level,
                "classical_security_bits": p.classical_security,
                "quantum_security_bits": p.quantum_security,
                "public_key_bytes": p.public_key_bytes,
                "secret_key_bytes": p.secret_key_bytes,
                "signature_bytes": p.signature_bytes,
                "keygen_time_ms": p.keygen_time_ms,
                "sign_time_ms": p.sign_time_ms,
                "verify_time_ms": p.verify_time_ms,
            },
            "ecdsa_p256": {
                "name": ec["name"],
                "quantum_safe": False,
                "public_key_bytes": ec["public_key_bytes"],
                "signature_bytes": ec["signature_bytes"],
                "sign_time_ms": ec["sign_time_ms"],
                "verify_time_ms": ec["verify_time_ms"],
            },
            "overhead": {
                "pk_size_ratio":     round(p.public_key_bytes / ec["public_key_bytes"], 2),
                "sig_size_ratio":    round(p.signature_bytes  / ec["signature_bytes"],  1),
                "sign_time_ratio":   round(p.sign_time_ms     / ec["sign_time_ms"],     1),
                "verify_time_ratio": round(p.verify_time_ms   / ec["verify_time_ms"],   1),
            },
            "tls_handshake_overhead_bytes": (
                p.public_key_bytes + p.signature_bytes
                - ec["public_key_bytes"] - ec["signature_bytes"]
            ),
            "use_case": (
                "SPHINCS+ is the most conservative PQC signature choice. Recommended for "
                "root CAs, long-lived regulatory archives (retention > 15 years), and "
                "compliance deployments requiring hash-only security assumptions (CNSA 2.0)."
            ),
            "recommendation": (
                f"{p.name} is preferred when hash-based assurance is mandatory. "
                f"Its {p.signature_bytes:,}-byte signatures make it unsuitable for "
                f"high-frequency transaction signing — use FALCON-512 or Dilithium3 there."
            ),
        }
