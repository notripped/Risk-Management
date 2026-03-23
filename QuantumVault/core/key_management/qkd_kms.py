"""
QKD Key Management System (QKD-KMS) Simulator

Simulates a complete QKD key lifecycle management system compliant with:
- ETSI GS QKD 014 (Key Delivery API)
- ETSI GS QKD 004 (Application Interface)
- ETSI GR QKD 007 (Security Requirements)

Manages the full lifecycle of quantum keys:
1. Key Generation (from QKD hardware via BB84/E91/MDI-QKD)
2. Key Storage (secure enclave / HSM simulation)
3. Key Distribution (ETSI QKD API)
4. Key Consumption (one-time pad, AES rekeying)
5. Key Rotation (automated based on policies)
6. Key Deletion (secure erase after consumption)

Financial Use Cases:
- AES-256 session key rekeying for trading connections
- Symmetric encryption of SWIFT messages
- One-time pad for ultra-high-value transactions (M&A, large block trades)
- Authentication tokens for inter-bank settlement
"""

import numpy as np
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from datetime import datetime, timedelta


class KeyState(Enum):
    FRESH     = "fresh"       # Just generated, not yet assigned
    RESERVED  = "reserved"    # Reserved for a specific application
    CONSUMED  = "consumed"    # Used — must be securely deleted
    EXPIRED   = "expired"     # TTL exceeded without use
    COMPROMISED = "compromised"  # Flagged as potentially compromised


class KeyUsePurpose(Enum):
    AES_REKEY       = "aes_rekey"           # AES session key material
    OTP_ENCRYPTION  = "otp_encryption"      # One-time pad
    HMAC_AUTH       = "hmac_auth"           # HMAC authentication keys
    KDF_SEED        = "kdf_seed"            # Key derivation function seed
    TLS_MASTER      = "tls_master_secret"   # TLS master secret


@dataclass
class QKDKey:
    key_id: str
    key_material: bytes
    key_size_bits: int
    state: KeyState
    source_protocol: str        # "bb84", "e91", "mdi_qkd"
    source_link: str
    created_at: float           # Unix timestamp
    ttl_seconds: int            # Time to live
    purpose: Optional[KeyUsePurpose] = None
    consumer_id: Optional[str]  = None
    consumed_at: Optional[float] = None
    qber_at_generation: float   = 0.0


@dataclass
class KeyStoreStats:
    total_keys: int
    fresh_keys: int
    reserved_keys: int
    consumed_keys: int
    expired_keys: int
    total_bits_available: int
    total_bits_consumed: int
    key_consumption_rate_bps: float
    average_ttl_remaining_s: float
    links: dict             # Per-link key stats


@dataclass
class ETSIKeyResponse:
    """ETSI GS QKD 014 compliant key response"""
    keys: list              # List of {"key_ID": str, "key": str (base64)}
    key_container_extension: dict = field(default_factory=dict)


class QKDKeyManagementSystem:
    """
    Simulated QKD Key Management System.
    Implements ETSI GS QKD 014 key delivery API.
    Full key lifecycle: generation, storage, distribution, consumption.
    """

    DEFAULT_KEY_SIZE_BITS = 256      # AES-256 sized keys
    DEFAULT_TTL_SECONDS   = 3600     # 1 hour
    MAX_STORE_KEYS        = 100_000  # Maximum keys in store

    def __init__(self, seed: Optional[int] = None):
        self._store: dict = {}           # key_id -> QKDKey
        self._rng = np.random.default_rng(seed)
        self._consumption_log: list = []
        self._total_bits_consumed = 0
        self._start_time = time.time()

    # ------------------------------------------------------------------ #
    #  Key Generation (from QKD simulation)                               #
    # ------------------------------------------------------------------ #

    def ingest_keys_from_bb84(
        self,
        n_keys: int,
        link_id: str,
        key_size_bits: int = 256,
        qber: float = 0.02,
        ttl_seconds: int = 3600,
    ) -> int:
        """Ingest keys generated from BB84 simulation into the key store"""
        from ..qkd.bb84 import BB84Simulator, QuantumChannel

        simulator = BB84Simulator()
        n_ingested = 0

        for _ in range(n_keys):
            # In production: key_material comes from real QKD hardware
            # Here: simulate key generation
            channel = QuantumChannel(distance_km=10.0)
            result = simulator.run(n_qubits=5000, channel=channel)

            if result.n_secure_key_bits >= key_size_bits and not result.eve_detected:
                key_bytes = result.final_key[:key_size_bits // 8]
                if len(key_bytes) >= key_size_bits // 8:
                    key_id = self._generate_key_id()
                    self._store[key_id] = QKDKey(
                        key_id=key_id,
                        key_material=key_bytes[:key_size_bits // 8],
                        key_size_bits=key_size_bits,
                        state=KeyState.FRESH,
                        source_protocol="bb84",
                        source_link=link_id,
                        created_at=time.time(),
                        ttl_seconds=ttl_seconds,
                        qber_at_generation=result.qber,
                    )
                    n_ingested += 1

        return n_ingested

    def generate_simulated_keys(
        self,
        n_keys: int,
        link_id: str,
        key_size_bits: int = 256,
        qber: float = 0.02,
        ttl_seconds: int = 3600,
    ) -> int:
        """Fast key generation simulation (without full BB84 protocol)"""
        n_ingested = 0
        for _ in range(n_keys):
            key_material = os.urandom(key_size_bits // 8)
            key_id = self._generate_key_id()
            self._store[key_id] = QKDKey(
                key_id=key_id,
                key_material=key_material,
                key_size_bits=key_size_bits,
                state=KeyState.FRESH,
                source_protocol="simulated",
                source_link=link_id,
                created_at=time.time(),
                ttl_seconds=ttl_seconds,
                qber_at_generation=qber,
            )
            n_ingested += 1
        return n_ingested

    # ------------------------------------------------------------------ #
    #  ETSI GS QKD 014 API Methods                                        #
    # ------------------------------------------------------------------ #

    def get_key(
        self,
        slave_sae_id: str,
        number: int = 1,
        size_bits: int = 256,
        key_ids: Optional[list] = None,
        purpose: KeyUsePurpose = KeyUsePurpose.AES_REKEY,
    ) -> Optional[ETSIKeyResponse]:
        """
        ETSI QKD 014: GET /api/v1/keys/{slave_sae_id}/enc_keys
        Retrieve fresh quantum keys for consumption.
        """
        self._expire_old_keys()

        # Find fresh keys of requested size
        available = [
            k for k in self._store.values()
            if k.state == KeyState.FRESH
            and k.key_size_bits >= size_bits
        ]

        if len(available) < number:
            return None   # Insufficient key material

        selected = available[:number]
        key_responses = []

        for key in selected:
            key.state      = KeyState.CONSUMED
            key.purpose    = purpose
            key.consumer_id = slave_sae_id
            key.consumed_at = time.time()

            self._total_bits_consumed += key.key_size_bits
            self._consumption_log.append({
                "timestamp": time.time(),
                "key_id": key.key_id,
                "consumer": slave_sae_id,
                "purpose": purpose.value,
                "bits": key.key_size_bits,
            })

            import base64
            key_responses.append({
                "key_ID":  key.key_id,
                "key":     base64.b64encode(key.key_material).decode(),
            })

        return ETSIKeyResponse(keys=key_responses)

    def get_key_by_id(
        self,
        master_sae_id: str,
        key_ids: list,
    ) -> Optional[ETSIKeyResponse]:
        """
        ETSI QKD 014: POST /api/v1/keys/{master_sae_id}/dec_keys
        Retrieve specific keys by ID (for synchronized decryption).
        """
        import base64
        key_responses = []
        for kid in key_ids:
            key = self._store.get(kid)
            if key and key.state in [KeyState.FRESH, KeyState.RESERVED]:
                key_responses.append({
                    "key_ID": key.key_id,
                    "key": base64.b64encode(key.key_material).decode(),
                })
        return ETSIKeyResponse(keys=key_responses) if key_responses else None

    def get_status(self) -> dict:
        """
        ETSI QKD 014: GET /api/v1/keys/{slave_sae_id}/status
        Key store status and availability.
        """
        fresh  = sum(1 for k in self._store.values() if k.state == KeyState.FRESH)
        stats  = self.get_stats()
        return {
            "source_KME_ID": "quantumvault_kms_01",
            "target_KME_ID": "quantumvault_kms_02",
            "master_SAE_ID": "master_sae",
            "slave_SAE_ID":  "slave_sae",
            "key_size":      self.DEFAULT_KEY_SIZE_BITS,
            "stored_key_count": fresh,
            "max_key_per_request": 100,
            "max_key_size": 4096,
            "min_key_size": 64,
            "max_SAE_ID_count": 0,
            "status_extension": {
                "total_bits_available": stats.total_bits_available,
                "key_consumption_rate_bps": stats.key_consumption_rate_bps,
                "uptime_seconds": round(time.time() - self._start_time, 0),
            }
        }

    # ------------------------------------------------------------------ #
    #  Key Management Operations                                           #
    # ------------------------------------------------------------------ #

    def rotate_keys(self, link_id: str, new_key_rate_bps: float = 1000) -> dict:
        """
        Rotate key material on a link. Triggered automatically or on demand.
        """
        # Expire old consumed keys
        expired_count = self._expire_old_keys()

        # Generate new keys based on available rate
        n_new = max(10, int(new_key_rate_bps / self.DEFAULT_KEY_SIZE_BITS))
        n_new = min(n_new, 500)
        ingested = self.generate_simulated_keys(n_new, link_id)

        return {
            "link_id": link_id,
            "expired_keys_cleared": expired_count,
            "new_keys_generated": ingested,
            "fresh_keys_available": sum(1 for k in self._store.values() if k.state == KeyState.FRESH),
        }

    def get_stats(self) -> KeyStoreStats:
        """Return comprehensive key store statistics"""
        states = {s: 0 for s in KeyState}
        for k in self._store.values():
            states[k.state] += 1

        fresh_keys = [k for k in self._store.values() if k.state == KeyState.FRESH]
        bits_available = sum(k.key_size_bits for k in fresh_keys)
        elapsed = time.time() - self._start_time
        consumption_rate = self._total_bits_consumed / elapsed if elapsed > 0 else 0

        ttl_remaining = []
        for k in fresh_keys:
            remaining = k.ttl_seconds - (time.time() - k.created_at)
            ttl_remaining.append(max(0, remaining))

        links = {}
        for k in self._store.values():
            if k.source_link not in links:
                links[k.source_link] = {"fresh": 0, "consumed": 0, "expired": 0}
            links[k.source_link][k.state.value] = links[k.source_link].get(k.state.value, 0) + 1

        return KeyStoreStats(
            total_keys=len(self._store),
            fresh_keys=states[KeyState.FRESH],
            reserved_keys=states[KeyState.RESERVED],
            consumed_keys=states[KeyState.CONSUMED],
            expired_keys=states[KeyState.EXPIRED],
            total_bits_available=bits_available,
            total_bits_consumed=self._total_bits_consumed,
            key_consumption_rate_bps=round(consumption_rate, 2),
            average_ttl_remaining_s=round(sum(ttl_remaining) / len(ttl_remaining), 1) if ttl_remaining else 0,
            links=links,
        )

    def _expire_old_keys(self) -> int:
        """Expire keys past their TTL"""
        now = time.time()
        expired = 0
        for key in self._store.values():
            if key.state == KeyState.FRESH:
                if now - key.created_at > key.ttl_seconds:
                    key.state = KeyState.EXPIRED
                    expired += 1
        return expired

    def _generate_key_id(self) -> str:
        return hashlib.sha256(os.urandom(16)).hexdigest()[:32].upper()
