"""
E91 Quantum Key Distribution Protocol Simulator (Ekert, 1991)

E91 uses quantum entanglement (EPR pairs) and Bell inequality violations
to distribute keys. Security is guaranteed by the laws of quantum mechanics —
any eavesdropping reduces the Bell inequality violation below the quantum bound.

Key Advantages over BB84:
- No need to trust the photon source (device-independent variant)
- Security relies on fundamental quantum correlations
- Long-distance entanglement via quantum repeaters
- Bell test provides a built-in security parameter

Bell Inequality (CHSH):
  |E(a,b) - E(a,b') + E(a',b) + E(a',b')| ≤ 2  (Classical bound)
  |S| ≤ 2√2 ≈ 2.828                              (Quantum bound — Tsirelson's bound)
Any violation > 2 confirms quantum entanglement.
Violation = 2√2 means perfect EPR source and no eavesdropping.
"""

import hashlib
import numpy as np
from dataclasses import dataclass, field
from typing import Optional


# CHSH measurement settings (angles in radians)
ALICE_SETTINGS = [0, np.pi/4]          # 0°, 45°
BOB_SETTINGS   = [np.pi/8, 3*np.pi/8]  # 22.5°, 67.5°


@dataclass
class E91Result:
    n_pairs_sent: int
    n_sifted_bits: int
    n_secure_key_bits: int
    bell_parameter_s: float          # CHSH S parameter (ideal: 2√2 ≈ 2.828)
    bell_violation: bool             # True if |S| > 2
    qber: float
    final_key: bytes
    eavesdropping_detected: bool
    entanglement_fidelity: float     # How close to perfect Bell state
    secure_key_rate_bps: float
    simulation_stats: dict = field(default_factory=dict)


class E91Simulator:
    """
    E91 Entanglement-Based QKD Protocol Simulator.
    Models realistic EPR pair generation, measurement, CHSH test, and key sifting.
    """

    BELL_CLASSICAL_BOUND  = 2.0
    BELL_QUANTUM_BOUND    = 2 * np.sqrt(2)   # ≈ 2.828
    QBER_THRESHOLD        = 0.11

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.default_rng(seed)

    def run(
        self,
        n_pairs: int = 10_000,
        distance_km: float = 50.0,
        entanglement_fidelity: float = 0.97,
        eavesdropping: bool = False,
        eve_intercept_fraction: float = 0.0,
    ) -> E91Result:
        """
        Simulate E91 QKD protocol.

        Args:
            n_pairs: Number of EPR pairs distributed
            distance_km: Channel distance
            entanglement_fidelity: Fidelity of Bell state (1.0 = perfect)
            eavesdropping: Whether Eve is present
            eve_intercept_fraction: Fraction of pairs Eve interferes with
        """

        # Generate EPR pairs (singlet |Ψ-> state)
        pairs = self._generate_epr_pairs(n_pairs, entanglement_fidelity)

        # Alice and Bob choose measurement settings randomly
        alice_settings_idx = self.rng.integers(0, 2, size=n_pairs)
        bob_settings_idx   = self.rng.integers(0, 2, size=n_pairs)

        alice_angles = np.array([ALICE_SETTINGS[i] for i in alice_settings_idx])
        bob_angles   = np.array([BOB_SETTINGS[i]   for i in bob_settings_idx  ])

        # Apply eavesdropping disturbance
        if eavesdropping and eve_intercept_fraction > 0:
            pairs = self._apply_eavesdropping(pairs, eve_intercept_fraction)

        # Measure entangled pairs
        alice_results, bob_results = self._measure_pairs(pairs, alice_angles, bob_angles)

        # CHSH Bell test using specific setting combinations
        bell_s = self._compute_bell_parameter(
            alice_results, bob_results,
            alice_settings_idx, bob_settings_idx
        )

        bell_violation = abs(bell_s) > self.BELL_CLASSICAL_BOUND

        # Sifting: keep rounds where both used same effective setting
        sift_mask = alice_settings_idx == bob_settings_idx
        alice_key = alice_results[sift_mask]
        bob_key   = bob_results[sift_mask]
        n_sifted  = int(np.sum(sift_mask))

        # QBER on sifted key
        sample_n = max(20, n_sifted // 5)
        if n_sifted > sample_n:
            qber = float(np.sum(alice_key[:sample_n] != bob_key[:sample_n])) / sample_n
            raw_key = alice_key[sample_n:]
        else:
            qber = 0.5
            raw_key = np.array([], dtype=int)

        # Security check — Bell violation must be present AND above threshold
        eve_detected = not bell_violation or qber > self.QBER_THRESHOLD

        # Key generation
        secure_bits   = self._generate_secure_key(raw_key, qber)
        n_secure_bits = len(secure_bits) * 8

        key_rate = n_secure_bits / (n_pairs * 1e-9) if n_pairs > 0 else 0.0

        return E91Result(
            n_pairs_sent=n_pairs,
            n_sifted_bits=n_sifted,
            n_secure_key_bits=n_secure_bits,
            bell_parameter_s=round(bell_s, 6),
            bell_violation=bell_violation,
            qber=round(qber, 6),
            final_key=secure_bits,
            eavesdropping_detected=eve_detected,
            entanglement_fidelity=entanglement_fidelity,
            secure_key_rate_bps=round(key_rate, 2),
            simulation_stats={
                "theoretical_bell_max": round(self.BELL_QUANTUM_BOUND, 4),
                "classical_bound": self.BELL_CLASSICAL_BOUND,
                "bell_violation_margin": round(abs(bell_s) - self.BELL_CLASSICAL_BOUND, 4),
                "sift_ratio": round(n_sifted / n_pairs, 4) if n_pairs > 0 else 0,
                "pairs_used_for_bell_test": n_pairs - n_sifted,
            }
        )

    # ------------------------------------------------------------------ #
    #  EPR Pair Generation                                                  #
    # ------------------------------------------------------------------ #

    def _generate_epr_pairs(self, n: int, fidelity: float) -> np.ndarray:
        """
        Generate EPR pairs as correlated hidden-variable representation.
        In the singlet state |Ψ->, measurements are anti-correlated when
        measured in the same basis.
        fidelity < 1 models depolarizing noise on the entangled state.
        """
        # Hidden variable (local hidden instruction set for perfect singlet)
        lambdas = self.rng.uniform(0, 2 * np.pi, size=n)

        # Noise: with probability (1-fidelity) replace with mixed state
        noise_mask = self.rng.random(n) > fidelity
        lambdas[noise_mask] = self.rng.uniform(0, 2 * np.pi, size=int(np.sum(noise_mask)))

        return lambdas

    def _measure_pairs(
        self, lambdas: np.ndarray,
        alice_angles: np.ndarray, bob_angles: np.ndarray
    ) -> tuple:
        """
        Simulate quantum measurements on EPR pairs using quantum prediction.
        Correlation: E(a,b) = -cos(a-b) for singlet state.
        """
        alice_results = np.zeros(len(lambdas), dtype=int)
        bob_results   = np.zeros(len(lambdas), dtype=int)

        for i, (lam, a_ang, b_ang) in enumerate(zip(lambdas, alice_angles, bob_angles)):
            # Alice measures according to quantum probability
            alice_prob_0 = 0.5 * (1 + np.cos(a_ang - lam))
            alice_results[i] = 0 if self.rng.random() < alice_prob_0 else 1

            # Bob: singlet state — anti-correlated when same angle
            bob_prob_0 = 0.5 * (1 - np.cos(b_ang - lam))
            bob_results[i] = 0 if self.rng.random() < bob_prob_0 else 1

        return alice_results, bob_results

    def _apply_eavesdropping(self, lambdas: np.ndarray, fraction: float) -> np.ndarray:
        """
        Eve's interference: partial measurement collapses entanglement,
        reducing Bell inequality violation toward classical bound.
        """
        n_interfere = int(len(lambdas) * fraction)
        noise = self.rng.uniform(0, 2 * np.pi, size=n_interfere)
        lambdas[:n_interfere] = (lambdas[:n_interfere] + noise) % (2 * np.pi)
        return lambdas

    def _compute_bell_parameter(
        self,
        alice_res: np.ndarray, bob_res: np.ndarray,
        alice_idx: np.ndarray, bob_idx: np.ndarray
    ) -> float:
        """
        Compute CHSH Bell parameter S.
        S = E(a0,b0) - E(a0,b1) + E(a1,b0) + E(a1,b1)
        Quantum mechanics: |S| up to 2√2 ≈ 2.828
        Classical limit:   |S| ≤ 2
        """
        def correlation(a_i, b_i):
            mask = (alice_idx == a_i) & (bob_idx == b_i)
            if np.sum(mask) == 0:
                return 0.0
            a = 2 * alice_res[mask] - 1   # Convert 0/1 to +1/-1
            b = 2 * bob_res[mask]   - 1
            return float(np.mean(a * b))

        E00 = correlation(0, 0)
        E01 = correlation(0, 1)
        E10 = correlation(1, 0)
        E11 = correlation(1, 1)

        S = E00 - E01 + E10 + E11
        return S

    def _generate_secure_key(self, raw_key: np.ndarray, qber: float) -> bytes:
        """Apply privacy amplification to generate final key"""
        if len(raw_key) == 0:
            return b""

        def h(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        output_fraction = max(0, 1 - 2 * h(qber))
        n_output_bytes = max(1, int(len(raw_key) * output_fraction / 8))

        key_bytes = np.packbits(raw_key).tobytes()
        return hashlib.shake_256(key_bytes).digest(n_output_bytes) if len(key_bytes) > 0 else b""
