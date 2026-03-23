"""
Test Suite: Post-Quantum Cryptography — Kyber, Dilithium, FALCON, Migration Engine
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.pqc.kyber     import KyberSimulator, KyberVariant, KYBER_PARAMS
from core.pqc.dilithium import DilithiumSimulator, FALCONSimulator, DilithiumVariant, FALCONVariant
from core.pqc.migration import (
    MigrationEngine, CryptoAsset, ClassicalAlgorithm,
    FinancialProtocol, MigrationUrgency
)


class TestKyber:
    def setup_method(self):
        self.sim = KyberSimulator()

    def test_keygen_produces_correct_sizes(self):
        for variant in KyberVariant:
            kp = self.sim.keygen(variant)
            params = KYBER_PARAMS[variant]
            assert len(kp.public_key) == params.public_key_bytes, f"Wrong public key size for {variant}"
            assert len(kp.secret_key) == params.secret_key_bytes, f"Wrong secret key size for {variant}"

    def test_encap_ciphertext_correct_size(self):
        kp = self.sim.keygen(KyberVariant.KYBER_768)
        enc = self.sim.encapsulate(kp)
        assert len(enc.ciphertext) == KYBER_PARAMS[KyberVariant.KYBER_768].ciphertext_bytes

    def test_encap_decap_shared_secret_match(self):
        kp  = self.sim.keygen(KyberVariant.KYBER_768)
        enc = self.sim.encapsulate(kp)
        dec = self.sim.decapsulate(kp, enc.ciphertext, enc.shared_secret)
        assert dec.secrets_match is True

    def test_shared_secret_is_32_bytes(self):
        kp  = self.sim.keygen(KyberVariant.KYBER_768)
        enc = self.sim.encapsulate(kp)
        assert len(enc.shared_secret) == 32

    def test_benchmark_fields(self):
        bench = self.sim.benchmark_vs_rsa(KyberVariant.KYBER_768)
        assert "key_sizes" in bench
        assert "performance_ms" in bench
        assert "security" in bench
        assert bench["quantum_safe"] is True
        assert bench["security"]["rsa2048_quantum_security_bits"] == 0

    def test_kyber_faster_keygen_than_rsa(self):
        bench = self.sim.benchmark_vs_rsa(KyberVariant.KYBER_768)
        assert bench["performance_ms"]["kyber_keygen"] < bench["performance_ms"]["rsa_keygen"]

    def test_all_variants_have_larger_keys_than_rsa(self):
        for variant in KyberVariant:
            bench = self.sim.benchmark_vs_rsa(variant)
            assert bench["key_sizes"]["pk_size_ratio"] > 1, f"{variant} public key should be larger than RSA-2048"

    def test_higher_variant_larger_keys(self):
        params_512  = KYBER_PARAMS[KyberVariant.KYBER_512]
        params_768  = KYBER_PARAMS[KyberVariant.KYBER_768]
        params_1024 = KYBER_PARAMS[KyberVariant.KYBER_1024]
        assert params_512.public_key_bytes < params_768.public_key_bytes < params_1024.public_key_bytes


class TestDilithium:
    def setup_method(self):
        self.sim = DilithiumSimulator()

    def test_keygen_correct_sizes(self):
        from core.pqc.dilithium import DILITHIUM_PARAMS
        for variant in DilithiumVariant:
            kp = self.sim.keygen(variant)
            params = DILITHIUM_PARAMS[variant]
            assert len(kp.public_key) == params.public_key_bytes
            assert len(kp.secret_key) == params.secret_key_bytes

    def test_sign_produces_correct_size(self):
        from core.pqc.dilithium import DILITHIUM_PARAMS
        kp  = self.sim.keygen(DilithiumVariant.DILITHIUM3)
        sig = self.sim.sign(kp, b"test financial transaction")
        params = DILITHIUM_PARAMS[DilithiumVariant.DILITHIUM3]
        assert sig.signature_size_bytes == params.signature_bytes

    def test_verify_valid_signature(self):
        msg = b"Trade order: BUY 10000 AAPL @ 175.00"
        kp  = self.sim.keygen(DilithiumVariant.DILITHIUM3)
        sig = self.sim.sign(kp, msg)
        ver = self.sim.verify(kp, msg, sig)
        assert ver.valid is True

    def test_verify_tampered_message_invalid(self):
        msg     = b"Trade order: BUY 10000 AAPL @ 175.00"
        tampered = b"Trade order: SELL 10000 AAPL @ 0.01"
        kp  = self.sim.keygen(DilithiumVariant.DILITHIUM3)
        sig = self.sim.sign(kp, msg)
        ver = self.sim.verify(kp, tampered, sig)
        assert ver.valid is False

    def test_benchmark_fields(self):
        bench = self.sim.benchmark_vs_ecdsa(DilithiumVariant.DILITHIUM3)
        assert bench["dilithium"]["quantum_safe"] is True
        assert bench["ecdsa_p256"]["quantum_safe"] is False
        assert "overhead" in bench
        assert bench["overhead"]["sig_size_ratio"] > 1


class TestFALCON:
    def setup_method(self):
        self.sim = FALCONSimulator()

    def test_signature_comparison_sorted(self):
        data = self.sim.signature_size_comparison()
        sizes = [d["sig_bytes"] for d in data]
        assert sizes == sorted(sizes)

    def test_falcon_smaller_than_dilithium(self):
        data = self.sim.signature_size_comparison()
        size_map = {d["name"]: d["sig_bytes"] for d in data}
        assert size_map["FALCON-512"] < size_map["Dilithium2"]

    def test_ecdsa_smallest(self):
        data = self.sim.signature_size_comparison()
        assert data[0]["name"] == "ECDSA P-256"

    def test_all_pqc_quantum_safe(self):
        data = self.sim.signature_size_comparison()
        for d in data:
            if d["name"] not in ["ECDSA P-256", "RSA-2048"]:
                assert d["quantum_safe"] is True, f"{d['name']} should be quantum safe"


class TestMigrationEngine:
    def setup_method(self):
        self.engine = MigrationEngine()

    def _make_asset(self, algo=ClassicalAlgorithm.RSA_2048, sensitivity="confidential",
                    retention=7, volume=100_000):
        return CryptoAsset(
            asset_id="test_01",
            name="Test Asset",
            algorithm=algo,
            protocol=FinancialProtocol.TLS_1_3,
            data_sensitivity=sensitivity,
            retention_years=retention,
            system="trading_engine",
            daily_transaction_volume=volume,
        )

    def test_rsa_2048_assessed_as_quantum_broken(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_2048)
        result = self.engine.assess_asset(asset)
        assert result.urgency != MigrationUrgency.NONE

    def test_aes_256_assessed_as_safe(self):
        asset  = self._make_asset(ClassicalAlgorithm.AES_256_GCM)
        result = self.engine.assess_asset(asset)
        assert result.urgency == MigrationUrgency.NONE

    def test_rsa_1024_critical_urgency(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_1024)
        result = self.engine.assess_asset(asset)
        assert result.urgency == MigrationUrgency.CRITICAL

    def test_kyber_recommended_for_rsa(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_2048)
        result = self.engine.assess_asset(asset)
        assert "Kyber" in result.recommended_kem

    def test_migration_steps_non_empty(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_2048)
        result = self.engine.assess_asset(asset)
        assert len(result.migration_steps) > 0

    def test_risk_score_bounded(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_1024, "secret", 20, 5_000_000)
        result = self.engine.assess_asset(asset)
        assert 0 <= result.risk_score <= 100

    def test_generate_plan_counts_correctly(self):
        assets = [
            self._make_asset(ClassicalAlgorithm.RSA_1024),
            self._make_asset(ClassicalAlgorithm.AES_256_GCM),
            self._make_asset(ClassicalAlgorithm.ECDH_P256),
        ]
        plan = self.engine.generate_plan("TestBank", assets)
        assert plan.total_assets == 3
        assert plan.critical_count + plan.high_count + plan.medium_count + plan.low_count + \
               sum(1 for a in plan.assessments if a.urgency == MigrationUrgency.NONE) == 3

    def test_secret_data_higher_risk_than_public(self):
        secret = self._make_asset(ClassicalAlgorithm.RSA_2048, "secret")
        public = self._make_asset(ClassicalAlgorithm.RSA_2048, "public")
        res_s  = self.engine.assess_asset(secret)
        res_p  = self.engine.assess_asset(public)
        assert res_s.risk_score >= res_p.risk_score

    def test_compliance_flags_rsa1024_non_compliant(self):
        asset  = self._make_asset(ClassicalAlgorithm.RSA_1024)
        result = self.engine.assess_asset(asset)
        assert any("NON-COMPLIANT" in f for f in result.compliance_flags)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
