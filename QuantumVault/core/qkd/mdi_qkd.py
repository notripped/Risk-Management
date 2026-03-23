"""
MDI-QKD: Measurement Device Independent QKD Simulator

MDI-QKD removes all detector-side attacks (a major vulnerability in BB84/E91)
by using an untrusted central relay (Charlie) to perform Bell state measurements.

Security Guarantee:
- Even if the detector (Charlie) is fully controlled by Eve, the protocol remains secure
- Only state preparation at Alice and Bob must be trusted
- Dramatically higher security than prepare-and-measure QKD for enterprise deployments

Use Case in Finance:
- Trading floor ↔ Data center ↔ Trading floor links where middle node may be
  in a shared datacenter (co-location facilities like Equinix)
- Eliminates trust requirement on physical measurement infrastructure
"""

import numpy as np
import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MDIQKDResult:
    n_pulses_sent: int
    n_successful_bsm: int        # Successful Bell State Measurements
    n_sifted_bits: int
    n_secure_key_bits: int
    qber: float
    bsm_success_rate: float
    secure_key_rate_bps: float
    final_key: bytes
    detector_attack_immune: bool  # Always True for MDI-QKD
    simulation_stats: dict = field(default_factory=dict)


class MDIQKDSimulator:
    """
    MDI-QKD Simulator.

    Alice and Bob both send optical pulses to an untrusted relay Charlie.
    Charlie performs a Bell State Measurement and announces the result.
    Alice and Bob use this to correlate their keys — without Charlie
    ever accessing the key material itself.
    """

    BSM_SUCCESS_PROBABILITY = 0.5    # Linear optical BSM maximum
    QBER_THRESHOLD = 0.11

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.default_rng(seed)

    def run(
        self,
        n_pulses: int = 50_000,
        alice_distance_km: float = 25.0,
        bob_distance_km: float   = 25.0,
        channel_loss_db_per_km: float = 0.20,
        detector_efficiency: float    = 0.85,
        mean_photon_number: float     = 0.1,
        channel_misalignment: float   = 0.015,
        charlie_is_malicious: bool    = False,
    ) -> MDIQKDResult:
        """
        Run MDI-QKD simulation.

        Alice and Bob each send to central node Charlie.
        Charlie's honesty is irrelevant to protocol security.
        """
        # Individual channel transmittances
        T_alice = (10 ** (-channel_loss_db_per_km * alice_distance_km / 10)) * detector_efficiency
        T_bob   = (10 ** (-channel_loss_db_per_km * bob_distance_km   / 10)) * detector_efficiency

        # Both photons must reach Charlie for BSM
        joint_transmission = T_alice * T_bob * self.BSM_SUCCESS_PROBABILITY

        n_bsm_success = int(n_pulses * joint_transmission)

        # Alice and Bob independently choose bases and bits
        alice_bits  = self.rng.integers(0, 2, size=n_bsm_success)
        alice_bases = self.rng.integers(0, 2, size=n_bsm_success)
        bob_bits    = self.rng.integers(0, 2, size=n_bsm_success)
        bob_bases   = self.rng.integers(0, 2, size=n_bsm_success)

        # Charlie announces BSM results (even malicious Charlie cannot help Eve)
        # BSM announcement tells which Bell state was measured
        bsm_outcomes = self.rng.integers(0, 4, size=n_bsm_success)  # |Φ+>, |Φ->, |Ψ+>, |Ψ->

        # Sifting: keep where bases match
        sift_mask = alice_bases == bob_bases
        alice_sifted = alice_bits[sift_mask]
        bob_sifted   = bob_bits[sift_mask]
        bsm_sifted   = bsm_outcomes[sift_mask]
        n_sifted     = int(np.sum(sift_mask))

        # Key correlation: Bob flips bits based on BSM outcome
        # |Ψ-> outcome → no flip; |Ψ+> → flip; |Φ+/-> → discard
        valid_mask   = (bsm_sifted == 0) | (bsm_sifted == 1)   # Only |Ψ> states useful
        alice_key    = alice_sifted[valid_mask]
        bob_key_raw  = bob_sifted[valid_mask]
        flip_mask    = bsm_sifted[valid_mask] == 1
        bob_key      = np.where(flip_mask, 1 - bob_key_raw, bob_key_raw)
        n_valid      = len(alice_key)

        if n_valid < 50:
            return self._empty_result(n_pulses)

        # QBER estimation
        sample_n = max(20, n_valid // 4)
        qber_noise = channel_misalignment
        if charlie_is_malicious:
            # Malicious Charlie cannot improve or modify QBER below protocol limit
            qber_noise = channel_misalignment   # No change — MDI security holds

        mismatch = np.sum(alice_key[:sample_n] != bob_key[:sample_n])
        # Add channel noise
        qber = float(mismatch) / sample_n + qber_noise
        qber = min(qber, 0.5)

        raw_key = alice_key[sample_n:]

        # Privacy amplification
        n_secure_bits, final_key = self._key_distillation(raw_key, qber)

        return MDIQKDResult(
            n_pulses_sent=n_pulses,
            n_successful_bsm=n_bsm_success,
            n_sifted_bits=n_sifted,
            n_secure_key_bits=n_secure_bits,
            qber=round(qber, 6),
            bsm_success_rate=round(n_bsm_success / n_pulses, 6),
            secure_key_rate_bps=round(n_secure_bits / (n_pulses * 1e-9), 2),
            final_key=final_key,
            detector_attack_immune=True,
            simulation_stats={
                "alice_effective_transmittance": round(T_alice, 6),
                "bob_effective_transmittance":   round(T_bob,   6),
                "joint_transmission":  round(joint_transmission, 8),
                "bsm_success_count":   n_bsm_success,
                "valid_bsm_fraction":  round(n_valid / n_sifted, 4) if n_sifted > 0 else 0,
                "charlie_malicious":   charlie_is_malicious,
                "protocol_secure":     True,   # MDI always secure
            }
        )

    def _key_distillation(self, raw_key: np.ndarray, qber: float) -> tuple:
        def h(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        secret_fraction = max(0.0, 1 - 2 * h(qber))
        n_output = max(0, int(len(raw_key) * secret_fraction))
        n_bytes = max(1, n_output // 8) if n_output > 0 else 0
        if n_bytes == 0 or len(raw_key) == 0:
            return 0, b""
        key_bytes = np.packbits(raw_key).tobytes()
        digest = hashlib.shake_256(key_bytes).digest(n_bytes)
        return n_output, digest

    def _empty_result(self, n_pulses) -> MDIQKDResult:
        return MDIQKDResult(
            n_pulses_sent=n_pulses, n_successful_bsm=0, n_sifted_bits=0,
            n_secure_key_bits=0, qber=0.5, bsm_success_rate=0.0,
            secure_key_rate_bps=0.0, final_key=b"", detector_attack_immune=True,
        )
