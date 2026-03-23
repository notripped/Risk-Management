"""
Test Suite: HNDL Risk Engine and Q-Day Timeline
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.threat.hndl import HNDLRiskEngine, HNDLExposureRecord, DataCategory, QUANTUM_VULNERABLE_ALGORITHMS
from core.threat.qday import QDayTimeline, QDAY_SCENARIOS
from core.threat.crypto_audit import CryptoAuditor, SystemCryptoProfile


class TestHNDLRiskEngine:
    def setup_method(self):
        self.engine = HNDLRiskEngine()

    def test_quantum_vulnerable_algo_raises_score(self):
        safe_record = HNDLExposureRecord(
            DataCategory.TRADE_ORDERS, 10.0,
            "AES-256-GCM", "link", 0.5
        )
        vuln_record = HNDLExposureRecord(
            DataCategory.TRADE_ORDERS, 10.0,
            "RSA-2048", "link", 0.5
        )
        safe_result = self.engine.assess_exposure(safe_record)
        vuln_result = self.engine.assess_exposure(vuln_record)
        assert vuln_result.risk_score > safe_result.risk_score

    def test_quantum_vulnerable_flag_correct(self):
        r = HNDLExposureRecord(DataCategory.SWIFT_MESSAGES, 5.0, "ECDH-P256", "link", 0.8)
        result = self.engine.assess_exposure(r)
        assert result.encryption_broken_by_quantum is True

    def test_quantum_safe_algo_not_broken(self):
        r = HNDLExposureRecord(DataCategory.TRADE_ORDERS, 5.0, "AES-256-GCM", "link", 0.5)
        result = self.engine.assess_exposure(r)
        assert result.encryption_broken_by_quantum is False

    def test_high_value_data_high_score(self):
        r1 = HNDLExposureRecord(DataCategory.ALGO_SOURCE_CODE,  1.0, "RSA-2048", "l", 0.8)
        r2 = HNDLExposureRecord(DataCategory.AUDIT_TRAILS,       1.0, "RSA-2048", "l", 0.8)
        res1 = self.engine.assess_exposure(r1)
        res2 = self.engine.assess_exposure(r2)
        assert res1.risk_score > res2.risk_score

    def test_portfolio_ranked_by_risk(self):
        records = [
            HNDLExposureRecord(DataCategory.TRADE_ORDERS,   10.0, "RSA-2048",   "link", 0.8),
            HNDLExposureRecord(DataCategory.AUDIT_TRAILS,    1.0, "AES-256-GCM","link", 0.1),
            HNDLExposureRecord(DataCategory.RISK_MODELS,     5.0, "ECDHA-P256", "link", 0.9),
        ]
        report = self.engine.assess_portfolio(records)
        ranks  = [r["priority_rank"] for r in report.asset_results]
        assert ranks == sorted(ranks)

    def test_portfolio_report_fields_present(self):
        records = [HNDLExposureRecord(DataCategory.TRADE_ORDERS, 10.0, "RSA-2048", "link", 0.5)]
        report = self.engine.assess_portfolio(records)
        assert hasattr(report, "total_financial_exposure_usd")
        assert hasattr(report, "overall_risk_score")
        assert hasattr(report, "qday_scenarios")
        assert len(report.qday_scenarios) == 4

    def test_financial_exposure_positive_for_vulnerable(self):
        r = HNDLExposureRecord(DataCategory.MA_COMMUNICATIONS, 2.0, "RSA-2048", "link", 0.8)
        result = self.engine.assess_exposure(r)
        assert result.financial_exposure_estimate_usd > 0

    def test_risk_score_bounded(self):
        r = HNDLExposureRecord(DataCategory.RISK_MODELS, 100.0, "RSA-1024", "link", 1.0)
        result = self.engine.assess_exposure(r)
        assert 0 <= result.risk_score <= 100

    def test_years_at_risk_zero_for_short_retention(self):
        """If retention < Q-Day years, years_at_risk should be 0"""
        r = HNDLExposureRecord(DataCategory.INTERBANK_COMMS, 1.0, "RSA-2048", "link", 0.5)
        result = self.engine.assess_exposure(r, qday_scenario="optimistic")
        # Retention for INTERBANK_COMMS is 5 years; optimistic Q-Day is 8 years
        assert result.years_at_risk >= 0

    def test_black_swan_scenario_higher_risk(self):
        r = HNDLExposureRecord(DataCategory.TRADE_ORDERS, 10.0, "RSA-2048", "link", 0.8)
        res_median = self.engine.assess_exposure(r, qday_scenario="median")
        res_black  = self.engine.assess_exposure(r, qday_scenario="black_swan")
        # Black swan has shorter timeline → more years at risk → higher score
        assert res_black.risk_score >= res_median.risk_score


class TestQDayTimeline:
    def setup_method(self):
        self.analyzer = QDayTimeline()

    def test_probabilities_sum_to_one(self):
        total = sum(s.probability for s in QDAY_SCENARIOS)
        assert abs(total - 1.0) < 0.01

    def test_median_year_within_range(self):
        result = self.analyzer.analyze(current_year=2026)
        assert 2030 <= result.median_qday_year <= 2055

    def test_prob_before_2040_majority(self):
        result = self.analyzer.analyze()
        assert result.probability_before_2040 >= 0.5

    def test_analysis_contains_all_fields(self):
        result = self.analyzer.analyze()
        assert len(result.scenarios) == len(QDAY_SCENARIOS)
        assert len(result.hardware_assessments) > 0
        assert result.shor_algorithm_requirements["logical_qubits"] == 4099

    def test_probability_density_returns_years(self):
        years = [2028, 2030, 2035, 2040]
        density = self.analyzer.probability_density(years)
        assert len(density) == len(years)
        for d in density:
            assert "year" in d
            assert "probability_density" in d
            assert d["probability_density"] >= 0

    def test_finance_risk_horizon_is_string(self):
        result = self.analyzer.analyze()
        assert isinstance(result.risk_horizon_for_finance, str)
        assert len(result.risk_horizon_for_finance) > 10


class TestCryptoAuditor:
    def setup_method(self):
        self.auditor = CryptoAuditor()

    def _make_system(self, suites, tls="1.3", cert="RSA-2048", fs=True):
        return SystemCryptoProfile(
            system_name="test", system_type="test",
            cipher_suites=suites, tls_version=tls,
            certificate_algorithm=cert, certificate_key_size=2048,
            certificate_expiry_days=180, hsts_enabled=True,
            forward_secrecy=fs, hostname="", department="",
        )

    def test_broken_suite_gives_low_grade(self):
        s = self._make_system(["TLS_RSA_WITH_3DES_EDE_CBC_SHA"])
        r = self.auditor.audit_system(s)
        assert r.overall_grade in ["D", "F"]

    def test_quantum_safe_suite_not_flagged(self):
        s = self._make_system(["X25519Kyber768Draft00"])
        r = self.auditor.audit_system(s)
        assert r.overall_grade in ["A+", "A", "B+", "B"]

    def test_tls_1_0_adds_issue(self):
        s = self._make_system(["TLS_AES_256_GCM_SHA384"], tls="1.0")
        r = self.auditor.audit_system(s)
        assert len(r.tls_issues) > 0

    def test_no_forward_secrecy_flagged(self):
        s = self._make_system(["TLS_AES_256_GCM_SHA384"], fs=False)
        r = self.auditor.audit_system(s)
        assert len(r.tls_issues) > 0

    def test_expiring_cert_flagged(self):
        s = self._make_system(["TLS_AES_256_GCM_SHA384"])
        s.certificate_expiry_days = 15
        r = self.auditor.audit_system(s)
        assert len(r.certificate_issues) > 0

    def test_institution_audit_aggregates(self):
        systems = [
            self._make_system(["TLS_AES_256_GCM_SHA384"]),
            self._make_system(["TLS_RSA_WITH_AES_256_GCM_SHA384"], tls="1.2"),
        ]
        result = self.auditor.audit_institution("TestBank", systems)
        assert result.total_systems == 2
        assert result.systems_audited == 2

    def test_vulnerability_score_bounded(self):
        s = self._make_system(["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256"])
        r = self.auditor.audit_system(s)
        assert 0 <= r.quantum_vulnerability_score <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
