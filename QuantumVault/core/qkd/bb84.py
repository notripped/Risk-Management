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
class DecoyStateConfig:
    """Three-intensity decoy-state settings for a WCP BB84 source."""
    mu_signal: float = 0.5     # Signal pulses — high gain, vulnerable to PNS
    mu_decoy: float = 0.1      # Decoy pulses — lower multi-photon fraction
    # Vacuum intensity is always 0.0 (no photons sent, measures Y_0 directly)
    fraction_signal: float = 0.5    # Fraction of total pulses at signal intensity
    fraction_decoy: float = 0.25    # Fraction at decoy intensity
    # fraction_vacuum = 1 - fraction_signal - fraction_decoy = 0.25

    def __post_init__(self):
        if self.mu_signal <= self.mu_decoy:
            raise ValueError("mu_signal must be greater than mu_decoy")
        if self.fraction_signal + self.fraction_decoy >= 1.0:
            raise ValueError("fraction_signal + fraction_decoy must be < 1.0")

    @property
    def fraction_vacuum(self) -> float:
        return 1.0 - self.fraction_signal - self.fraction_decoy

    @property
    def multi_photon_prob_signal(self) -> float:
        """P(n≥2 | µ_signal) — fraction of signal pulses Eve can exploit via PNS"""
        return 1.0 - np.exp(-self.mu_signal) * (1.0 + self.mu_signal)

    @property
    def multi_photon_prob_decoy(self) -> float:
        """P(n≥2 | µ_decoy) — much smaller, making PNS inconsistency visible"""
        return 1.0 - np.exp(-self.mu_decoy) * (1.0 + self.mu_decoy)



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
    mean_photon_number: float = 0.5        # µ for WCP source (used when decoy-state is active)


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
    finite_key_correction_bits: int = 0

@dataclass
class DecoyStateResult:
    """Results from a three-intensity decoy-state BB84 simulation."""
    n_pulses_total: int
    n_signal_pulses: int
    n_decoy_pulses: int
    n_vacuum_pulses: int
    # Observed gains Q (fraction of pulses that produce a detection event)
    gain_signal: float
    gain_decoy: float
    gain_vacuum: float             # = Y_0 directly — dark count yield per pulse
    # Observed error rates per intensity
    qber_signal: float
    qber_decoy: float
    # LMC decoy-state bounds (Lo, Ma, Chen 2005)
    Q1_lower_bound: float          # τ_1^L — lower bound on single-photon gain contribution
    e1_upper_bound: float          # e_1^U — upper bound on single-photon QBER
    single_photon_fraction: float  # τ_1^L / Q_s
    # Key output
    n_secure_key_bits: int
    secure_key_rate_gllp: float        # GLLP rate with decoy-state bounds
    secure_key_rate_standard: float    # Standard BB84 without decoy (for comparison)
    key_rate_improvement_x: float      # Multiplicative improvement factor
    # PNS detection
    pns_attack_active: bool
    pns_detectable_via_decoy: bool
    pns_inconsistency: float       # 0 = consistent channel, >0.15 = likely PNS
    config: DecoyStateConfig
    channel: QuantumChannel
    simulation_stats: dict = field(default_factory=dict)
    finite_key_correction_bits: int = 0


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
        final_key, pa_compression, fk_correction = self._privacy_amplification(
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
            finite_key_correction_bits=fk_correction,
            simulation_stats={
                "photon_loss_rate": round(1 - n_received / n_qubits, 4),
                "sift_efficiency": round(n_sifted / n_received, 4) if n_received > 0 else 0,
                "pa_output_bits": n_secure,
                "finite_key_correction_bits": fk_correction,
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
        self, key: np.ndarray, qber: float, ec_leaked: int,
        epsilon: float = 1e-10,
    ) -> tuple:
        """
        Privacy Amplification via universal hashing.
        Compresses key to remove Eve's partial information.

        Output length (finite-key, Scarani-Renner 2008):
          n(1 - h(QBER)) - ec_leaked - Δ(n, ε)
        where Δ(n, ε) = 7√(n · log₂(2/ε)) replaces the asymptotic fixed term.
        """
        if len(key) == 0:
            return b"", 0.0, 0

        def binary_entropy(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        n = len(key)
        # Scarani-Renner finite-key correction (2008)
        delta = int(7 * np.sqrt(n * np.log2(2.0 / epsilon)))

        output_bits = int(n * (1 - binary_entropy(max(qber, 1e-10))) - ec_leaked - delta)
        output_bits = max(0, output_bits)

        # Simulate universal hashing with SHA-3 (Toeplitz hashing approximation)
        key_bytes = np.packbits(key).tobytes()
        hashed = hashlib.shake_256(key_bytes).digest(max(1, output_bits // 8))

        compression = output_bits / n if n > 0 else 0

        return hashed, compression, delta

    def _empty_result(self, n_qubits, channel, attack) -> BB84Result:
        return BB84Result(
            n_qubits_sent=n_qubits, n_sifted_bits=0, n_secure_key_bits=0,
            qber=1.0, alice_bases=[], bob_bases=[], sifted_key_alice=[],
            sifted_key_bob=[], final_key=b"", secure_key_rate_bps=0.0,
            eve_detected=True, eve_information=1.0, channel=channel,
            attack_type=attack, error_correction_bits_leaked=0,
            privacy_amplification_compression=0.0,
        )
    def _simulate_intensity_level(
        self,
        mu: float,
        n_pulses: int,
        eta: float,
        Y0: float,
        e_channel: float,
        pns_block_singles: bool = False,
    ) -> tuple:
        """
        Vectorised WCP pulse simulation for one intensity level.

        eta: transmission * detector_efficiency (single-photon detection prob)
        Y0:  dark count yield per pulse
        pns_block_singles: PNS attack — Eve blocks all n=1 pulses at signal intensity.
        """
        ns = self.rng.poisson(mu, size=n_pulses)

        # Y_n = 1 - (1-Y0)*(1-eta)^n  for n>=1,  Y_0 = Y0 for vacuum
        yn = np.where(ns == 0, Y0, 1.0 - (1.0 - Y0) * (1.0 - eta) ** ns)

        if pns_block_singles:
            # Eve blocks single-photon pulses entirely; multi-photon pass through
            yn = np.where(ns == 1, 0.0, yn)

        detected = self.rng.random(n_pulses) < yn
        # Dark count detections are random bits (e=0.5); photon detections have channel QBER
        e_per_pulse = np.where(ns == 0, 0.5, e_channel)
        errors = detected & (self.rng.random(n_pulses) < e_per_pulse)

        n_det = int(np.sum(detected))
        gain  = n_det / n_pulses
        qber  = float(np.sum(errors)) / n_det if n_det > 0 else 0.0
        return gain, qber, n_det


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
    def run_with_decoy_state(
        self,
        n_pulses: int = 50_000,
        channel: Optional[QuantumChannel] = None,
        config: Optional[DecoyStateConfig] = None,
    ) -> DecoyStateResult:
        """
        BB84 with three-intensity decoy-state protocol (GLLP security proof).

        Sends signal (µ), decoy (ν), and vacuum pulses in random order.
        Uses LMC lower bound on τ_1 to compute a tight secure key rate that
        remains valid even under a full Photon-Number-Splitting attack.
        """
        if channel is None:
            channel = QuantumChannel()
        if config is None:
            config = DecoyStateConfig()

        n_signal = int(n_pulses * config.fraction_signal)
        n_decoy  = int(n_pulses * config.fraction_decoy)
        n_vacuum = n_pulses - n_signal - n_decoy

        eta  = channel.transmission * channel.detector_efficiency
        Y0   = channel.dark_count_rate / channel.clock_rate_hz
        e_ch = channel.channel_qber_contribution

        pns_active = (channel.attack == AttackType.PHOTON_NUMBER_SPLITTING)

        gain_s, qber_s, n_det_s = self._simulate_intensity_level(
            config.mu_signal, n_signal, eta, Y0, e_ch,
            pns_block_singles=pns_active,   # PNS only effective at high-µ signal pulses
        )
        gain_d, qber_d, n_det_d = self._simulate_intensity_level(
            config.mu_decoy, n_decoy, eta, Y0, e_ch,
        )
        gain_v, _,      n_det_v = self._simulate_intensity_level(
            0.0, n_vacuum, eta, Y0, e_ch,
        )
        Y0_est = gain_v   # Vacuum measurement directly gives Y_0

        # ---- LMC decoy-state parameter estimation -------------------------
        # Lower bound on τ_1^L = µ_s · e^{-µ_s} · Y_1
        # (single-photon contribution to signal-pulse gain)
        mu_s, mu_d = config.mu_signal, config.mu_decoy
        denom = mu_s * mu_d - mu_d ** 2

        tau1_lower = 0.0
        if denom > 1e-12:
            bracket = (
                gain_d * np.exp(mu_d)
                - gain_s * np.exp(mu_s) * (mu_d / mu_s) ** 2
                - (1.0 - (mu_d / mu_s) ** 2) * Y0_est
            )
            tau1_lower = max(0.0, (mu_s ** 2 * np.exp(-mu_s)) / denom * bracket)

        # Lower bound on single-photon yield Y_1
        Y1_lower = tau1_lower / (mu_s * np.exp(-mu_s)) if mu_s > 1e-12 else 0.0

        # Upper bound on single-photon QBER e_1^U
        e1_upper = 0.5
        denom_e1 = mu_d * Y1_lower
        if denom_e1 > 1e-12:
            e1_upper = max(0.0, min(0.5,
                (qber_d * gain_d * np.exp(mu_d) - 0.5 * Y0_est) / denom_e1
            ))

        sp_fraction = tau1_lower / gain_s if gain_s > 1e-12 else 0.0

        # ---- GLLP secret key rate ----------------------------------------
        def h(p: float) -> float:
            if p <= 0.0 or p >= 1.0:
                return 0.0
            return -p * np.log2(p) - (1.0 - p) * np.log2(1.0 - p)

        CASCADE_F  = 1.16
        r_gllp     = max(0.0, tau1_lower * (1.0 - h(e1_upper)) - CASCADE_F * gain_s * h(qber_s))
        r_standard = max(0.0, gain_s * (1.0 - h(qber_s)) - CASCADE_F * gain_s * h(qber_s))

        t_elapsed       = n_pulses / channel.clock_rate_hz
        # Scarani-Renner finite-key correction applied to single-photon signal count
        EPSILON_DS      = 1e-10
        fk_correction_ds = int(7 * np.sqrt(n_signal * np.log2(2.0 / EPSILON_DS)))
        n_secure_gllp   = max(0, int(r_gllp * n_signal) - fk_correction_ds)
        rate_gllp       = n_secure_gllp / t_elapsed
        rate_standard   = int(r_standard * n_signal) / t_elapsed
        improvement     = rate_gllp / rate_standard if rate_standard > 0 else float("inf")

        # ---- PNS cross-intensity consistency check -----------------------
        # If Eve did PNS only on signal pulses, the gain at decoy won't match
        # what Y_1 estimated from signal+vacuum would predict.
        Y1_from_signal = (gain_s * np.exp(mu_s) - Y0_est) / mu_s if mu_s > 1e-12 else 0.0
        Q_d_predicted  = np.exp(-mu_d) * (Y0_est + mu_d * Y1_from_signal)
        inconsistency  = (
            abs(gain_d - Q_d_predicted) / Q_d_predicted
            if Q_d_predicted > 1e-12 else 0.0
        )
        pns_detectable = pns_active and (inconsistency > 0.15)

        return DecoyStateResult(
            n_pulses_total=n_pulses,
            n_signal_pulses=n_signal,
            n_decoy_pulses=n_decoy,
            n_vacuum_pulses=n_vacuum,
            gain_signal=round(gain_s, 8),
            gain_decoy=round(gain_d, 8),
            gain_vacuum=round(gain_v, 8),
            qber_signal=round(qber_s, 6),
            qber_decoy=round(qber_d, 6),
            Q1_lower_bound=round(tau1_lower, 8),
            e1_upper_bound=round(e1_upper, 6),
            single_photon_fraction=round(sp_fraction, 4),
            n_secure_key_bits=n_secure_gllp,
            secure_key_rate_gllp=round(rate_gllp, 2),
            secure_key_rate_standard=round(rate_standard, 2),
            key_rate_improvement_x=round(improvement, 2),
            pns_attack_active=pns_active,
            pns_detectable_via_decoy=pns_detectable,
            pns_inconsistency=round(min(inconsistency, 1.0), 4),
            config=config,
            channel=channel,
            finite_key_correction_bits=fk_correction_ds,
            simulation_stats={
                "Y0_dark_yield":             round(Y0_est, 8),
                "Y1_lower_bound":            round(Y1_lower, 6),
                "n_signal_detections":       n_det_s,
                "n_decoy_detections":        n_det_d,
                "n_vacuum_detections":       n_det_v,
                "multi_photon_prob_signal":  round(config.multi_photon_prob_signal, 6),
                "multi_photon_prob_decoy":   round(config.multi_photon_prob_decoy, 6),
                "finite_key_correction_bits": fk_correction_ds,
            },
        )

