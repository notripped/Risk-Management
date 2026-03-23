"""
BB84 Quantum Key Distribution Protocol Simulator

BB84 is the first quantum cryptography protocol, proposed by Bennett and Brassard in 1984.
It uses the quantum mechanical properties of single photons to establish a provably
secure shared secret key between two parties (Alice and Bob).

Security Basis:
- No-cloning theorem: quantum states cannot be perfectly copied
- Measurement disturbance: measuring a quantum state changes it
- Any eavesdropping (Eve) introduces detectable errors (elevated QBER)

Protocol Steps:
1. Alice prepares qubits in random bases (+/x) with random bits (0/1)
2. Qubits sent through quantum channel to Bob
3. Bob measures in randomly chosen bases
4. Alice and Bob publicly compare bases (sifting)
5. Mismatched bases discarded — remaining bits form sifted key
6. QBER estimated from sacrificial bits
7. Privacy amplification + error correction to get final secure key
"""

import numpy as np
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Basis(Enum):
    RECTILINEAR = "+"   # Z-basis: |0>, |1>
    DIAGONAL = "x"      # X-basis: |+>, |->


class AttackType(Enum):
    NONE = "none"
    INTERCEPT_RESEND = "intercept_resend"
    PHOTON_NUMBER_SPLITTING = "photon_number_splitting"
    TROJAN_HORSE = "trojan_horse"


@dataclass
class QuantumChannel:
    """Models a physical quantum channel (fiber optic or free-space)"""
    distance_km: float = 10.0
    fiber_loss_db_per_km: float = 0.2        # Standard SMF-28 fiber loss
    detector_efficiency: float = 0.85         # Superconducting nanowire detector
    dark_count_rate: float = 100              # counts/second
    clock_rate_hz: float = 1e9               # 1 GHz pulse rate
    alignment_error: float = 0.01            # Optical alignment imperfection
    depolarization: float = 0.02             # Inherent channel depolarization
    attack: AttackType = AttackType.NONE
    attack_intercept_fraction: float = 0.0   # Fraction of qubits Eve intercepts

    @property
    def transmission(self) -> float:
        """Channel transmittance from fiber loss"""
        return 10 ** (-self.fiber_loss_db_per_km * self.distance_km / 10)

    @property
    def channel_qber_contribution(self) -> float:
        """Error rate from channel imperfections alone (no attack)"""
        return self.alignment_error + self.depolarization / 2

    @property
    def sifted_key_rate_estimate(self) -> float:
        """Approximate sifted key rate in bits/second"""
        raw_rate = self.clock_rate_hz * self.transmission * self.detector_efficiency
        return raw_rate * 0.5  # ~50% survive sifting


@dataclass
class BB84Result:
    """Full results from a BB84 simulation run"""
    n_qubits_sent: int
    n_sifted_bits: int
    n_secure_key_bits: int
    qber: float
    alice_bases: list
    bob_bases: list
    sifted_key_alice: list
    sifted_key_bob: list
    final_key: bytes
    secure_key_rate_bps: float
    eve_detected: bool
    eve_information: float           # Fraction of key Eve knows (0-1)
    channel: QuantumChannel
    attack_type: AttackType
    error_correction_bits_leaked: int
    privacy_amplification_compression: float
    simulation_stats: dict = field(default_factory=dict)


class BB84Simulator:
    """
    Full BB84 QKD Protocol Simulator with realistic channel modeling,
    eavesdropping attack simulation, error correction, and privacy amplification.
    """

    # QBER threshold above which key is considered compromised
    QBER_SECURITY_THRESHOLD = 0.11     # 11% — theoretical security limit

    # Error correction leakage (fraction of sifted key length)
    CASCADE_LEAK_FRACTION = 0.1        # Cascade protocol information leakage

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.default_rng(seed)

    # ------------------------------------------------------------------ #
    #  Core Protocol                                                        #
    # ------------------------------------------------------------------ #

    def run(
        self,
        n_qubits: int = 10_000,
        channel: Optional[QuantumChannel] = None,
    ) -> BB84Result:
        """
        Execute a full BB84 protocol simulation.

        Args:
            n_qubits: Number of photons Alice attempts to send
            channel:  QuantumChannel configuration

        Returns:
            BB84Result with full statistics
        """
        if channel is None:
            channel = QuantumChannel()

        # Step 1: Alice prepares random bits and bases
        alice_bits  = self.rng.integers(0, 2, size=n_qubits)
        alice_bases = self.rng.choice([Basis.RECTILINEAR, Basis.DIAGONAL], size=n_qubits)

        # Step 2: Model quantum channel (photon loss + eavesdropping)
        received_mask, eve_info = self._propagate_through_channel(
            alice_bits, alice_bases, channel, n_qubits
        )

        n_received = int(np.sum(received_mask))

        # Step 3: Bob measures in random bases
        bob_bases   = self.rng.choice([Basis.RECTILINEAR, Basis.DIAGONAL], size=n_received)
        bob_bits    = self._bob_measure(
            alice_bits[received_mask],
            alice_bases[received_mask],
            bob_bases,
            channel,
        )

        # Step 4: Basis sifting — keep only matching bases
        alice_sifted, bob_sifted, sift_mask = self._sift_keys(
            alice_bits[received_mask], alice_bases[received_mask],
            bob_bases, bob_bits
        )

        n_sifted = len(alice_sifted)
        if n_sifted < 100:
            return self._empty_result(n_qubits, channel, channel.attack)

        # Step 5: QBER estimation using sacrificial sample (25% of sifted)
        sample_size = max(50, n_sifted // 4)
        qber = self._estimate_qber(alice_sifted[:sample_size], bob_sifted[:sample_size])

        # Remaining bits form the raw key
        alice_raw_key = alice_sifted[sample_size:]
        bob_raw_key   = bob_sifted[sample_size:]

        # Step 6: Security check
        eve_detected = qber > self.QBER_SECURITY_THRESHOLD

        # Step 7: Error correction (Cascade protocol simulation)
        corrected_key, ec_leaked_bits = self._error_correction(
            alice_raw_key, bob_raw_key, qber
        )

        # Step 8: Privacy amplification — compress away Eve's information
        final_key, pa_compression = self._privacy_amplification(
            corrected_key, qber, ec_leaked_bits
        )

        n_secure = len(final_key) * 8
        secure_key_rate = n_secure / (n_qubits / channel.clock_rate_hz) if n_qubits > 0 else 0.0

        return BB84Result(
            n_qubits_sent=n_qubits,
            n_sifted_bits=n_sifted,
            n_secure_key_bits=n_secure,
            qber=round(qber, 6),
            alice_bases=alice_bases[:20].tolist(),
            bob_bases=bob_bases[:20].tolist(),
            sifted_key_alice=alice_sifted[:20].tolist(),
            sifted_key_bob=bob_sifted[:20].tolist(),
            final_key=final_key,
            secure_key_rate_bps=round(secure_key_rate, 2),
            eve_detected=eve_detected,
            eve_information=round(eve_info, 6),
            channel=channel,
            attack_type=channel.attack,
            error_correction_bits_leaked=ec_leaked_bits,
            privacy_amplification_compression=round(pa_compression, 4),
            simulation_stats={
                "photon_loss_rate": round(1 - n_received / n_qubits, 4),
                "sift_efficiency": round(n_sifted / n_received, 4) if n_received > 0 else 0,
                "pa_output_bits": n_secure,
                "key_generation_efficiency": round(n_secure / n_qubits, 6),
            }
        )

    # ------------------------------------------------------------------ #
    #  Internal Protocol Steps                                             #
    # ------------------------------------------------------------------ #

    def _propagate_through_channel(
        self, alice_bits, alice_bases, channel: QuantumChannel, n_qubits: int
    ) -> tuple:
        """Simulate photon propagation: loss + Eve's attack"""

        # Photon survival probability
        survival_prob = channel.transmission * channel.detector_efficiency
        received_mask = self.rng.random(n_qubits) < survival_prob

        eve_information = 0.0

        if channel.attack == AttackType.INTERCEPT_RESEND:
            eve_information = self._intercept_resend_attack(
                received_mask, alice_bits, alice_bases,
                channel.attack_intercept_fraction
            )

        elif channel.attack == AttackType.PHOTON_NUMBER_SPLITTING:
            eve_information = self._pns_attack(channel)

        return received_mask, eve_information

    def _intercept_resend_attack(
        self, received_mask, alice_bits, alice_bases, intercept_fraction: float
    ) -> float:
        """
        Intercept-and-Resend Attack (most common, fully detectable).
        Eve intercepts fraction of qubits, measures, re-sends.
        This introduces QBER = 0.25 * intercept_fraction.
        """
        # Eve guesses basis correctly 50% — introduces errors on 25% of intercepted
        n_intercepted = int(np.sum(received_mask) * intercept_fraction)
        # Eve's information gain
        eve_information = intercept_fraction * 0.5   # 50% correct basis guess
        return eve_information

    def _pns_attack(self, channel: QuantumChannel) -> float:
        """
        Photon-Number-Splitting Attack.
        Requires multi-photon pulses (weak coherent sources).
        Decoy state protocol mitigates this.
        Eve gains information proportional to multi-photon pulse rate.
        """
        mean_photon_number = 0.1   # Typical WCP source
        multi_photon_prob = 1 - np.exp(-mean_photon_number) - mean_photon_number * np.exp(-mean_photon_number)
        # Eve can fully intercept multi-photon pulses without detection
        eve_info = multi_photon_prob * channel.transmission
        return min(eve_info, 1.0)

    def _bob_measure(self, alice_bits, alice_bases, bob_bases, channel: QuantumChannel) -> np.ndarray:
        """
        Bob's measurement results with realistic noise.
        When bases match: correct with probability (1 - channel_noise)
        When bases mismatch: random 50/50 result
        """
        bob_bits = np.zeros(len(alice_bits), dtype=int)
        base_noise = channel.channel_qber_contribution

        # Add attack-induced noise
        if channel.attack == AttackType.INTERCEPT_RESEND:
            base_noise += 0.25 * channel.attack_intercept_fraction

        for i, (a_bit, a_base, b_base) in enumerate(zip(alice_bits, alice_bases, bob_bases)):
            if a_base == b_base:
                # Matching bases — correct result with some noise
                if self.rng.random() < base_noise:
                    bob_bits[i] = 1 - a_bit   # Bit flip error
                else:
                    bob_bits[i] = a_bit
            else:
                # Mismatched bases — random result
                bob_bits[i] = self.rng.integers(0, 2)

        return bob_bits

    def _sift_keys(self, alice_bits, alice_bases, bob_bases, bob_bits):
        """Keep only bits where Alice and Bob used the same basis"""
        sift_mask = np.array([a == b for a, b in zip(alice_bases, bob_bases)])
        return (
            alice_bits[sift_mask],
            bob_bits[sift_mask],
            sift_mask
        )

    def _estimate_qber(self, alice_sample: np.ndarray, bob_sample: np.ndarray) -> float:
        """Estimate Quantum Bit Error Rate from sacrificial sample"""
        if len(alice_sample) == 0:
            return 0.0
        errors = np.sum(alice_sample != bob_sample)
        return float(errors) / len(alice_sample)

    def _error_correction(
        self, alice_key: np.ndarray, bob_key: np.ndarray, qber: float
    ) -> tuple:
        """
        Simulate Cascade error correction protocol.
        Cascade leaks ~1.16 * h(QBER) bits per corrected bit.
        h() is binary Shannon entropy.
        """
        if len(alice_key) == 0:
            return alice_key, 0

        def binary_entropy(p: float) -> float:
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        leak_fraction = 1.16 * binary_entropy(max(qber, 1e-10))
        ec_leaked_bits = int(len(alice_key) * leak_fraction)

        # Correct Bob's errors (simulation: use Alice's key as ground truth)
        corrected_key = alice_key.copy()

        return corrected_key, ec_leaked_bits

    def _privacy_amplification(
        self, key: np.ndarray, qber: float, ec_leaked: int
    ) -> tuple:
        """
        Privacy Amplification via universal hashing.
        Compresses key to remove Eve's partial information.

        Output length: n(1 - h(QBER)) - ec_leaked - security_parameter
        """
        if len(key) == 0:
            return b"", 0.0

        SECURITY_PARAMETER = 64   # bits — controls failure probability

        def binary_entropy(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        n = len(key)
        output_bits = int(n * (1 - binary_entropy(max(qber, 1e-10))) - ec_leaked - SECURITY_PARAMETER)
        output_bits = max(0, output_bits)

        # Simulate universal hashing with SHA-3 (Toeplitz hashing approximation)
        key_bytes = np.packbits(key).tobytes()
        hashed = hashlib.shake_256(key_bytes).digest(max(1, output_bits // 8))

        compression = output_bits / n if n > 0 else 0

        return hashed, compression

    def _empty_result(self, n_qubits, channel, attack) -> BB84Result:
        return BB84Result(
            n_qubits_sent=n_qubits, n_sifted_bits=0, n_secure_key_bits=0,
            qber=1.0, alice_bases=[], bob_bases=[], sifted_key_alice=[],
            sifted_key_bob=[], final_key=b"", secure_key_rate_bps=0.0,
            eve_detected=True, eve_information=1.0, channel=channel,
            attack_type=attack, error_correction_bits_leaked=0,
            privacy_amplification_compression=0.0,
        )

    # ------------------------------------------------------------------ #
    #  Analysis Utilities                                                   #
    # ------------------------------------------------------------------ #

    def sweep_distance(
        self, distances_km: list, n_qubits: int = 50_000
    ) -> list:
        """Compute secure key rate vs distance curve"""
        results = []
        for d in distances_km:
            channel = QuantumChannel(distance_km=d)
            result = self.run(n_qubits=n_qubits, channel=channel)
            results.append({
                "distance_km": d,
                "qber": result.qber,
                "secure_key_rate_bps": result.secure_key_rate_bps,
                "sifted_bits": result.n_sifted_bits,
                "secure_bits": result.n_secure_key_bits,
                "transmission": channel.transmission,
            })
        return results

    def sweep_attack(
        self, intercept_fractions: list, n_qubits: int = 20_000
    ) -> list:
        """Compute QBER and Eve's information vs intercept fraction"""
        results = []
        for frac in intercept_fractions:
            channel = QuantumChannel(
                attack=AttackType.INTERCEPT_RESEND,
                attack_intercept_fraction=frac
            )
            result = self.run(n_qubits=n_qubits, channel=channel)
            results.append({
                "intercept_fraction": frac,
                "qber": result.qber,
                "eve_information": result.eve_information,
                "eve_detected": result.eve_detected,
                "secure_key_bits": result.n_secure_key_bits,
            })
        return results
