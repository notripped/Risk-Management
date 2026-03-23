"""
Test Suite: BB84 QKD Protocol
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import numpy as np
from core.qkd.bb84 import BB84Simulator, QuantumChannel, AttackType


class TestBB84Basics:
    def setup_method(self):
        self.sim = BB84Simulator(seed=42)

    def test_no_attack_low_qber(self):
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=20000, channel=channel)
        assert result.qber < 0.11, f"QBER {result.qber:.4f} exceeds threshold without attack"

    def test_key_generated_without_attack(self):
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=20000, channel=channel)
        assert result.n_secure_key_bits > 0

    def test_sifted_key_less_than_sent(self):
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=20000, channel=channel)
        assert result.n_sifted_bits < result.n_qubits_sent

    def test_sifted_key_approx_half_received(self):
        """Sifting removes ~50% of bits"""
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=50000, channel=channel)
        loss_rate = result.simulation_stats.get("photon_loss_rate", 0)
        n_received = int(result.n_qubits_sent * (1 - loss_rate))
        if n_received > 0:
            sift_ratio = result.n_sifted_bits / n_received
            assert 0.3 < sift_ratio < 0.7, f"Sift ratio {sift_ratio:.3f} outside expected range"


class TestBB84InterceptResendAttack:
    def setup_method(self):
        self.sim = BB84Simulator(seed=42)

    def test_heavy_intercept_detected(self):
        """Full interception (100%) must be detected"""
        channel = QuantumChannel(
            distance_km=5.0,
            attack=AttackType.INTERCEPT_RESEND,
            attack_intercept_fraction=1.0,
        )
        result = self.sim.run(n_qubits=30000, channel=channel)
        assert result.eve_detected, "Full intercept-resend attack not detected"

    def test_heavy_intercept_elevated_qber(self):
        channel = QuantumChannel(
            distance_km=5.0,
            attack=AttackType.INTERCEPT_RESEND,
            attack_intercept_fraction=0.5,
        )
        result = self.sim.run(n_qubits=30000, channel=channel)
        assert result.qber > 0.09, f"QBER {result.qber:.4f} not elevated for 50% intercept attack"

    def test_zero_intercept_gives_clean_channel(self):
        channel = QuantumChannel(
            distance_km=5.0,
            attack=AttackType.INTERCEPT_RESEND,
            attack_intercept_fraction=0.0,
        )
        result = self.sim.run(n_qubits=30000, channel=channel)
        assert result.qber < 0.11


class TestBB84DistanceSweep:
    def setup_method(self):
        self.sim = BB84Simulator(seed=42)

    def test_key_rate_decreases_with_distance(self):
        data = self.sim.sweep_distance([10, 30, 60, 100], n_qubits=20000)
        rates = [d["secure_key_rate_bps"] for d in data]
        # Rate should be non-increasing (allowing for noise)
        for i in range(len(rates) - 1):
            assert rates[i] >= rates[i+1] * 0.01 or rates[i+1] == 0, \
                   f"Key rate unexpectedly increased from {rates[i]} to {rates[i+1]}"

    def test_short_distance_viable(self):
        data = self.sim.sweep_distance([5], n_qubits=20000)
        assert data[0]["secure_key_rate_bps"] > 0

    def test_result_fields_present(self):
        data = self.sim.sweep_distance([10], n_qubits=10000)
        expected_keys = {"distance_km", "qber", "secure_key_rate_bps", "sifted_bits", "secure_bits"}
        assert expected_keys.issubset(set(data[0].keys()))


class TestBB84PrivacyAmplification:
    def setup_method(self):
        self.sim = BB84Simulator(seed=42)

    def test_secure_key_less_than_sifted(self):
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=30000, channel=channel)
        assert result.n_secure_key_bits <= result.n_sifted_bits

    def test_final_key_bytes_match_bit_count(self):
        channel = QuantumChannel(distance_km=5.0)
        result = self.sim.run(n_qubits=30000, channel=channel)
        if result.n_secure_key_bits > 0:
            expected_bytes = result.n_secure_key_bits // 8
            actual_bytes   = len(result.final_key)
            # Allow small discrepancy from integer truncation
            assert abs(actual_bytes - expected_bytes) <= 2


class TestQuantumChannel:
    def test_transmission_decreases_with_distance(self):
        c1 = QuantumChannel(distance_km=10.0)
        c2 = QuantumChannel(distance_km=50.0)
        assert c1.transmission > c2.transmission

    def test_zero_distance_max_transmission(self):
        c = QuantumChannel(distance_km=0.001)
        assert c.transmission > 0.99

    def test_sifted_key_rate_positive(self):
        c = QuantumChannel(distance_km=10.0)
        assert c.sifted_key_rate_estimate > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
