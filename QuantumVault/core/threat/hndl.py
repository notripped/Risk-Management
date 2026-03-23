"""
Harvest Now Decrypt Later (HNDL) Risk Engine

HNDL is the primary near-term quantum threat to financial institutions.
Adversaries (nation-states, APT groups) are currently:
1. Intercepting and storing encrypted financial communications
2. Archiving inter-bank TLS sessions, SWIFT messages, settlement records
3. Waiting until a Cryptographically Relevant Quantum Computer (CRQC) exists
4. Decrypting all historical data retroactively

This engine quantifies HNDL exposure across financial communication assets
and produces risk scores, exposure timelines, and prioritized remediation.

References:
- NSA CNSA 2.0 (2022) — explicit HNDL acknowledgment
- CISA/NSA/NIST Joint Advisory (2022)
- ENISA Quantum Threat Report (2023)
- UK NCSC Post-Quantum Cryptography Migration guidance (2023)
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class DataCategory(Enum):
    """Financial data categories with sensitivity and retention requirements"""
    TRADE_ORDERS        = "trade_orders"          # 7 years MiFID II retention
    SETTLEMENT_RECORDS  = "settlement_records"    # 10 years
    CLIENT_PII          = "client_pii"            # GDPR — indefinite
    RISK_MODELS         = "risk_models"            # Proprietary — indefinite
    SWIFT_MESSAGES      = "swift_messages"         # 10 years
    REGULATORY_REPORTS  = "regulatory_reports"    # 7 years
    MA_COMMUNICATIONS   = "ma_communications"      # Strategic — indefinite
    INTERBANK_COMMS     = "interbank_comms"        # 5 years
    ALGO_SOURCE_CODE    = "algo_source_code"       # Proprietary — indefinite
    CREDIT_DECISIONS    = "credit_decisions"       # Basel III — 7 years
    DERIVATIVE_CONTRACTS = "derivative_contracts"  # 7 years
    AUDIT_TRAILS        = "audit_trails"           # 10 years


# Data retention requirements (years)
RETENTION_REQUIREMENTS = {
    DataCategory.TRADE_ORDERS:        7,
    DataCategory.SETTLEMENT_RECORDS: 10,
    DataCategory.CLIENT_PII:          30,   # Conservative GDPR interpretation
    DataCategory.RISK_MODELS:         20,   # Competitive horizon
    DataCategory.SWIFT_MESSAGES:      10,
    DataCategory.REGULATORY_REPORTS:  7,
    DataCategory.MA_COMMUNICATIONS:   25,   # Long-term competitive risk
    DataCategory.INTERBANK_COMMS:      5,
    DataCategory.ALGO_SOURCE_CODE:    20,
    DataCategory.CREDIT_DECISIONS:    7,
    DataCategory.DERIVATIVE_CONTRACTS: 7,
    DataCategory.AUDIT_TRAILS:        10,
}

# Base data value scores (0-100, input to risk model)
DATA_VALUE_SCORES = {
    DataCategory.TRADE_ORDERS:         85,
    DataCategory.SETTLEMENT_RECORDS:   70,
    DataCategory.CLIENT_PII:           90,
    DataCategory.RISK_MODELS:         100,
    DataCategory.SWIFT_MESSAGES:       75,
    DataCategory.REGULATORY_REPORTS:   50,
    DataCategory.MA_COMMUNICATIONS:   100,
    DataCategory.INTERBANK_COMMS:      65,
    DataCategory.ALGO_SOURCE_CODE:    100,
    DataCategory.CREDIT_DECISIONS:     70,
    DataCategory.DERIVATIVE_CONTRACTS: 80,
    DataCategory.AUDIT_TRAILS:         55,
}


@dataclass
class HNDLExposureRecord:
    """Represents a specific data exposure point"""
    data_category: DataCategory
    volume_gb_per_day: float
    encryption_algorithm: str       # Current encryption
    channel: str                    # Network path
    adversary_access_likelihood: float  # 0-1, likelihood adversary can capture


@dataclass
class HNDLRiskResult:
    """HNDL risk assessment output"""
    data_category: DataCategory
    risk_score: float               # 0-100 composite risk
    hndl_exposure_score: float      # Pure HNDL exposure
    data_value_score: float         # Business value of the data
    retention_years: int
    qday_median_years: int
    years_at_risk: float            # Max(0, retention - qday)
    encryption_broken_by_quantum: bool
    adversary_capture_likelihood: str  # "low", "medium", "high", "nation-state"
    recommended_action: str
    estimated_annual_exposure_gb: float
    financial_exposure_estimate_usd: int
    priority_rank: int


@dataclass
class HNDLPortfolioReport:
    """Aggregate HNDL risk across entire institution"""
    total_daily_volume_gb: float
    total_annual_exposure_gb: float
    total_financial_exposure_usd: int
    critical_assets: int
    overall_risk_score: float
    asset_results: list
    top_3_risks: list
    immediate_actions: list
    qday_scenarios: dict


# Algorithms vulnerable to quantum (Shor's algorithm)
QUANTUM_VULNERABLE_ALGORITHMS = {
    "RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "ECDH-P256", "ECDH-P384", "X25519", "X448",
    "DH-2048", "DH-3072",
    "DSA-2048",
}

# Approximate value of compromised financial data per GB (regulatory, competitive)
DATA_VALUE_PER_GB_USD = {
    DataCategory.TRADE_ORDERS:         500_000,
    DataCategory.SETTLEMENT_RECORDS:   200_000,
    DataCategory.CLIENT_PII:           100_000,
    DataCategory.RISK_MODELS:       50_000_000,   # Competitive IP
    DataCategory.SWIFT_MESSAGES:       300_000,
    DataCategory.REGULATORY_REPORTS:    50_000,
    DataCategory.MA_COMMUNICATIONS:  10_000_000,
    DataCategory.INTERBANK_COMMS:      150_000,
    DataCategory.ALGO_SOURCE_CODE:  100_000_000,
    DataCategory.CREDIT_DECISIONS:     200_000,
    DataCategory.DERIVATIVE_CONTRACTS: 500_000,
    DataCategory.AUDIT_TRAILS:          30_000,
}


class HNDLRiskEngine:
    """
    Quantifies Harvest-Now-Decrypt-Later exposure for financial institutions.
    Produces risk scores, financial exposure estimates, and prioritized remediation.
    """

    # Q-Day probability distribution (years from 2026)
    QDAY_SCENARIOS = {
        "optimistic":   8,    # Best case: ~2034
        "median":      12,    # Central estimate: ~2038
        "pessimistic": 17,    # Conservative: ~2043
        "black_swan":   5,    # Surprise breakthrough: ~2031
    }

    ADVERSARY_LIKELIHOOD_MAP = {
        "nation_state":      0.85,
        "apt_group":         0.60,
        "criminal_org":      0.30,
        "opportunistic":     0.10,
        "internal":          0.15,
    }

    def assess_exposure(
        self,
        record: HNDLExposureRecord,
        adversary_type: str = "nation_state",
        qday_scenario: str = "median",
    ) -> HNDLRiskResult:
        """Assess HNDL risk for a single data exposure point"""

        retention = RETENTION_REQUIREMENTS.get(record.data_category, 10)
        value_score = DATA_VALUE_SCORES.get(record.data_category, 50)
        qday = self.QDAY_SCENARIOS.get(qday_scenario, 12)
        quantum_broken = record.encryption_algorithm in QUANTUM_VULNERABLE_ALGORITHMS

        # Years the data will remain at risk after Q-Day
        years_at_risk = max(0.0, retention - qday)

        # HNDL sub-score components
        capture_likelihood = self.ADVERSARY_LIKELIHOOD_MAP.get(adversary_type, 0.5) * record.adversary_access_likelihood
        quantum_vuln_score = 50 if quantum_broken else 0
        retention_score    = min(30, years_at_risk * 3)
        capture_score      = capture_likelihood * 20

        hndl_score = quantum_vuln_score + retention_score + capture_score

        # Composite risk = HNDL exposure × data value
        risk_score = (hndl_score * 0.6) + (value_score * 0.4)
        risk_score = min(risk_score, 100.0)

        annual_gb = record.volume_gb_per_day * 365
        value_per_gb = DATA_VALUE_PER_GB_USD.get(record.data_category, 100_000)
        financial_exposure = int(annual_gb * value_per_gb * capture_likelihood * (1 if quantum_broken else 0.1))

        # Adversary capability string
        if capture_likelihood > 0.7:
            adversary_str = "nation-state"
        elif capture_likelihood > 0.4:
            adversary_str = "high"
        elif capture_likelihood > 0.2:
            adversary_str = "medium"
        else:
            adversary_str = "low"

        # Recommended action
        if not quantum_broken:
            action = "No HNDL risk — algorithm is quantum-resistant"
        elif risk_score > 75:
            action = "IMMEDIATE: Migrate to PQC. Begin QKD deployment planning."
        elif risk_score > 50:
            action = "HIGH: Schedule PQC migration within 12 months. Hybrid mode first."
        elif risk_score > 30:
            action = "MEDIUM: Include in 3-year PQC roadmap."
        else:
            action = "LOW: Monitor Q-Day timeline. Plan migration within 5 years."

        return HNDLRiskResult(
            data_category=record.data_category,
            risk_score=round(risk_score, 1),
            hndl_exposure_score=round(hndl_score, 1),
            data_value_score=float(value_score),
            retention_years=retention,
            qday_median_years=int(qday),
            years_at_risk=round(years_at_risk, 1),
            encryption_broken_by_quantum=quantum_broken,
            adversary_capture_likelihood=adversary_str,
            recommended_action=action,
            estimated_annual_exposure_gb=round(annual_gb, 2),
            financial_exposure_estimate_usd=financial_exposure,
            priority_rank=0,   # Set by portfolio assessment
        )

    def assess_portfolio(
        self,
        records: list,
        adversary_type: str = "nation_state",
        qday_scenario: str = "median",
    ) -> HNDLPortfolioReport:
        """Assess HNDL risk across full portfolio of data assets"""

        results = [
            self.assess_exposure(r, adversary_type, qday_scenario)
            for r in records
        ]

        # Sort and rank by risk score
        results.sort(key=lambda x: x.risk_score, reverse=True)
        for i, r in enumerate(results):
            r.priority_rank = i + 1

        total_gb_day    = sum(r.volume_gb_per_day for r in records)
        total_gb_annual = total_gb_day * 365
        total_exposure  = sum(r.financial_exposure_estimate_usd for r in results)
        critical_count  = sum(1 for r in results if r.risk_score > 75)
        avg_risk        = sum(r.risk_score for r in results) / len(results) if results else 0

        immediate_actions = [
            f"[P{r.priority_rank}] {r.data_category.value}: {r.recommended_action}"
            for r in results if r.risk_score > 60
        ]

        qday_by_scenario = {
            scenario: {
                "qday_year": 2026 + years,
                "years_remaining": years,
                "assets_at_risk": sum(
                    1 for rec, res in zip(records, results)
                    if res.encryption_broken_by_quantum
                    and RETENTION_REQUIREMENTS.get(rec.data_category, 10) > years
                )
            }
            for scenario, years in self.QDAY_SCENARIOS.items()
        }

        return HNDLPortfolioReport(
            total_daily_volume_gb=round(total_gb_day, 2),
            total_annual_exposure_gb=round(total_gb_annual, 2),
            total_financial_exposure_usd=total_exposure,
            critical_assets=critical_count,
            overall_risk_score=round(avg_risk, 1),
            asset_results=[self._result_to_dict(r) for r in results],
            top_3_risks=[results[i].data_category.value for i in range(min(3, len(results)))],
            immediate_actions=immediate_actions[:5],
            qday_scenarios=qday_by_scenario,
        )

    def _result_to_dict(self, r: HNDLRiskResult) -> dict:
        return {
            "priority_rank":         r.priority_rank,
            "data_category":         r.data_category.value,
            "risk_score":            r.risk_score,
            "hndl_exposure_score":   r.hndl_exposure_score,
            "years_at_risk":         r.years_at_risk,
            "quantum_vulnerable":    r.encryption_broken_by_quantum,
            "adversary_likelihood":  r.adversary_capture_likelihood,
            "financial_exposure_usd": r.financial_exposure_estimate_usd,
            "annual_exposure_gb":    r.estimated_annual_exposure_gb,
            "action":                r.recommended_action,
        }
