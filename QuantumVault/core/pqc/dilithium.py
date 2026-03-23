"""
CRYSTALS-Dilithium Post-Quantum Digital Signature Simulator

CRYSTALS-Dilithium is a digital signature scheme standardized by NIST in 2024
(FIPS 204). Based on Module Lattice problems (MLWE + MSIS), quantum-safe.

Critical Use in Finance:
- Signing financial transactions (trades, settlements, SWIFT messages)
- Code signing for trading systems and financial software
- Certificate authorities and PKI infrastructure
- Regulatory audit trail authentication

Variants:
- Dilithium2:  NIST Level 2
- Dilithium3:  NIST Level 3 — RECOMMENDED for financial transaction signing
- Dilithium5:  NIST Level 5 — for long-term regulatory records

Also covers FALCON (fast lattice signatures, FFT-based) and SPHINCS+ (hash-based).
"""

import numpy as np
import hashlib
import os
import time
import hmac
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class DilithiumVariant(Enum):
    DILITHIUM2 = "dilithium2"
    DILITHIUM3 = "dilithium3"
    DILITHIUM5 = "dilithium5"


class FALCONVariant(Enum):
    FALCON_512  = "falcon512"
    FALCON_1024 = "falcon1024"


@dataclass
class DilithiumParameters:
    name: str
    nist_level: int
    classical_security: int
    quantum_security: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    # Performance (Intel Skylake reference)
    keygen_time_ms: float
    sign_time_ms: float
    verify_time_ms: float


@dataclass
class FALCONParameters:
    name: str
    nist_level: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    keygen_time_ms: float
    sign_time_ms: float
    verify_time_ms: float


DILITHIUM_PARAMS = {
    DilithiumVariant.DILITHIUM2: DilithiumParameters(
        name="Dilithium2", nist_level=2,
        classical_security=128, quantum_security=128,
        public_key_bytes=1312, secret_key_bytes=2528, signature_bytes=2420,
        keygen_time_ms=0.055, sign_time_ms=0.115, verify_time_ms=0.046,
    ),
    DilithiumVariant.DILITHIUM3: DilithiumParameters(
        name="Dilithium3", nist_level=3,
        classical_security=192, quantum_security=178,
        public_key_bytes=1952, secret_key_bytes=4000, signature_bytes=3293,
        keygen_time_ms=0.085, sign_time_ms=0.170, verify_time_ms=0.068,
    ),
    DilithiumVariant.DILITHIUM5: DilithiumParameters(
        name="Dilithium5", nist_level=5,
        classical_security=256, quantum_security=254,
        public_key_bytes=2592, secret_key_bytes=4864, signature_bytes=4595,
        keygen_time_ms=0.120, sign_time_ms=0.260, verify_time_ms=0.090,
    ),
}

FALCON_PARAMS = {
    FALCONVariant.FALCON_512: FALCONParameters(
        name="FALCON-512", nist_level=1,
        public_key_bytes=897, secret_key_bytes=1281, signature_bytes=690,
        keygen_time_ms=12.5, sign_time_ms=0.170, verify_time_ms=0.055,
    ),
    FALCONVariant.FALCON_1024: FALCONParameters(
        name="FALCON-1024", nist_level=5,
        public_key_bytes=1793, secret_key_bytes=2305, signature_bytes=1330,
        keygen_time_ms=25.0, sign_time_ms=0.340, verify_time_ms=0.110,
    ),
}

# ECDSA comparison reference
ECDSA_P256 = {
    "name": "ECDSA P-256",
    "quantum_safe": False,
    "public_key_bytes": 64,
    "signature_bytes": 64,
    "keygen_time_ms": 0.040,
    "sign_time_ms": 0.030,
    "verify_time_ms": 0.080,
}


@dataclass
class SignatureKeyPair:
    algorithm: str
    public_key: bytes
    secret_key: bytes
    params: object


@dataclass
class SignatureResult:
    algorithm: str
    message_hash: bytes
    signature: bytes
    sign_time_ms: float
    signature_size_bytes: int


@dataclass
class VerificationResult:
    valid: bool
    verify_time_ms: float
    algorithm: str


class DilithiumSimulator:
    """CRYSTALS-Dilithium digital signature simulation"""

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.default_rng(seed)

    def keygen(self, variant: DilithiumVariant = DilithiumVariant.DILITHIUM3) -> SignatureKeyPair:
        params = DILITHIUM_PARAMS[variant]
        seed   = os.urandom(32)
        pk     = hashlib.shake_256(seed + b"dilithium_pk").digest(params.public_key_bytes)
        sk     = hashlib.shake_256(seed + b"dilithium_sk").digest(params.secret_key_bytes)
        return SignatureKeyPair(algorithm=params.name, public_key=pk, secret_key=sk, params=params)

    def sign(self, keypair: SignatureKeyPair, message: bytes) -> SignatureResult:
        params  = keypair.params
        msg_h   = hashlib.sha3_256(message).digest()
        nonce   = os.urandom(32)
        sig     = hashlib.shake_256(keypair.secret_key + msg_h + nonce).digest(params.signature_bytes)
        return SignatureResult(
            algorithm=params.name,
            message_hash=msg_h,
            signature=sig,
            sign_time_ms=params.sign_time_ms,
            signature_size_bytes=len(sig),
        )

    def verify(
        self, keypair: SignatureKeyPair, message: bytes, signature: SignatureResult
    ) -> VerificationResult:
        params = keypair.params
        # Simulate verification (deterministic check)
        msg_h  = hashlib.sha3_256(message).digest()
        valid  = hmac.compare_digest(msg_h, signature.message_hash)
        return VerificationResult(
            valid=valid,
            verify_time_ms=params.verify_time_ms,
            algorithm=params.name,
        )

    def benchmark_vs_ecdsa(
        self, variant: DilithiumVariant = DilithiumVariant.DILITHIUM3
    ) -> dict:
        p = DILITHIUM_PARAMS[variant]
        ec = ECDSA_P256
        return {
            "dilithium": {
                "name": p.name,
                "quantum_safe": True,
                "nist_level": p.nist_level,
                "public_key_bytes": p.public_key_bytes,
                "signature_bytes":  p.signature_bytes,
                "sign_time_ms":     p.sign_time_ms,
                "verify_time_ms":   p.verify_time_ms,
            },
            "ecdsa_p256": {
                "name": ec["name"],
                "quantum_safe": False,
                "public_key_bytes": ec["public_key_bytes"],
                "signature_bytes":  ec["signature_bytes"],
                "sign_time_ms":     ec["sign_time_ms"],
                "verify_time_ms":   ec["verify_time_ms"],
            },
            "overhead": {
                "pk_size_ratio":  round(p.public_key_bytes / ec["public_key_bytes"], 1),
                "sig_size_ratio": round(p.signature_bytes  / ec["signature_bytes"],  1),
                "sign_time_ratio": round(p.sign_time_ms   / ec["sign_time_ms"],    1),
                "verify_time_ratio": round(p.verify_time_ms / ec["verify_time_ms"], 1),
            },
            "tls_handshake_overhead_bytes": p.public_key_bytes + p.signature_bytes - ec["public_key_bytes"] - ec["signature_bytes"],
            "recommendation": (
                f"{p.name} is the recommended quantum-safe replacement for ECDSA P-256 "
                f"in financial transaction signing. {p.sign_time_ms:.3f}ms signing time "
                f"is negligible for financial applications."
            )
        }


class FALCONSimulator:
    """
    FALCON Digital Signature Simulator.
    FALCON produces smaller signatures than Dilithium — preferred for
    bandwidth-constrained environments (HFT, high-frequency messaging).
    """

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.default_rng(seed)

    def keygen(self, variant: FALCONVariant = FALCONVariant.FALCON_512) -> SignatureKeyPair:
        params = FALCON_PARAMS[variant]
        seed   = os.urandom(32)
        pk     = hashlib.shake_256(seed + b"falcon_pk").digest(params.public_key_bytes)
        sk     = hashlib.shake_256(seed + b"falcon_sk").digest(params.secret_key_bytes)
        return SignatureKeyPair(algorithm=params.name, public_key=pk, secret_key=sk, params=params)

    def sign(self, keypair: SignatureKeyPair, message: bytes) -> SignatureResult:
        params  = keypair.params
        msg_h   = hashlib.sha3_256(message).digest()
        nonce   = os.urandom(32)
        sig     = hashlib.shake_256(keypair.secret_key + msg_h + nonce).digest(params.signature_bytes)
        return SignatureResult(
            algorithm=params.name, message_hash=msg_h, signature=sig,
            sign_time_ms=params.sign_time_ms, signature_size_bytes=len(sig),
        )

    def signature_size_comparison(self) -> list:
        """Compare signature sizes across all PQC and classical schemes"""
        schemes = [
            {"name": "ECDSA P-256", "sig_bytes": 64,   "quantum_safe": False, "nist_level": "N/A"},
            {"name": "RSA-2048",    "sig_bytes": 256,   "quantum_safe": False, "nist_level": "N/A"},
            {"name": "FALCON-512",  "sig_bytes": 690,   "quantum_safe": True,  "nist_level": 1},
            {"name": "FALCON-1024", "sig_bytes": 1330,  "quantum_safe": True,  "nist_level": 5},
            {"name": "Dilithium2",  "sig_bytes": 2420,  "quantum_safe": True,  "nist_level": 2},
            {"name": "Dilithium3",  "sig_bytes": 3293,  "quantum_safe": True,  "nist_level": 3},
            {"name": "Dilithium5",  "sig_bytes": 4595,  "quantum_safe": True,  "nist_level": 5},
            {"name": "SPHINCS+-128f","sig_bytes": 17088, "quantum_safe": True, "nist_level": 1},
            {"name": "SPHINCS+-256f","sig_bytes": 49856, "quantum_safe": True, "nist_level": 5},
        ]
        return sorted(schemes, key=lambda x: x["sig_bytes"])
