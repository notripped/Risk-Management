"""
Post-Quantum Cryptography Migration Engine

Provides automated analysis and migration planning for financial institutions
transitioning from classical cryptography to NIST-standardized PQC algorithms.

Covers:
- Cryptographic inventory scanning
- Risk scoring for each asset
- Migration priority matrix
- Hybrid mode planning (classical + PQC simultaneously during transition)
- TLS 1.3 migration profiles
- SWIFT, FIX protocol, FpML compatibility analysis
- Timeline and effort estimation
- DORA and CNSA 2.0 compliance mapping
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from .kyber     import KyberVariant, KYBER_PARAMS
from .dilithium import DilithiumVariant, FALCONVariant, DILITHIUM_PARAMS, FALCON_PARAMS


class ClassicalAlgorithm(Enum):
    RSA_1024    = "rsa_1024"
    RSA_2048    = "rsa_2048"
    RSA_3072    = "rsa_3072"
    RSA_4096    = "rsa_4096"
    ECDH_P256   = "ecdh_p256"
    ECDH_P384   = "ecdh_p384"
    ECDSA_P256  = "ecdsa_p256"
    ECDSA_P384  = "ecdsa_p384"
    DH_2048     = "dh_2048"
    AES_128_GCM = "aes_128_gcm"
    AES_256_GCM = "aes_256_gcm"
    SHA256      = "sha256"
    SHA384      = "sha384"


class MigrationUrgency(Enum):
    CRITICAL  = "critical"    # Must migrate immediately
    HIGH      = "high"        # Migrate within 12 months
    MEDIUM    = "medium"      # Migrate within 3 years
    LOW       = "low"         # Migrate within 5 years
    NONE      = "none"        # Already quantum-safe


class FinancialProtocol(Enum):
    TLS_1_2   = "tls_1.2"
    TLS_1_3   = "tls_1.3"
    SWIFT      = "swift"
    FIX_4_4   = "fix_4.4"
    FIX_5_0   = "fix_5.0"
    FPML       = "fpml"
    ISO_20022  = "iso_20022"
    HTTPS      = "https"
    SSH_2      = "ssh2"


@dataclass
class CryptoAsset:
    """Represents a cryptographic asset in a financial institution"""
    asset_id: str
    name: str
    algorithm: ClassicalAlgorithm
    protocol: FinancialProtocol
    data_sensitivity: str          # "public", "internal", "confidential", "secret"
    retention_years: int           # How long data must remain confidential
    system: str                    # e.g., "trading_engine", "settlement", "swift_gateway"
    certificate_expiry_days: Optional[int] = None
    daily_transaction_volume: int = 0
    notes: str = ""


@dataclass
class MigrationAssessment:
    asset: CryptoAsset
    urgency: MigrationUrgency
    risk_score: float               # 0-100
    hndl_risk_years: float          # Years until data becomes decryptable
    recommended_kem: str
    recommended_sig: str
    hybrid_mode_needed: bool
    estimated_migration_effort: str # "days", "weeks", "months"
    compatibility_notes: list
    compliance_flags: list
    migration_steps: list


@dataclass
class MigrationPlan:
    institution_name: str
    total_assets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_score: float
    assessments: list
    executive_summary: str
    quick_wins: list
    compliance_status: dict


# Algorithm vulnerability data
ALGORITHM_VULNERABILITY = {
    ClassicalAlgorithm.RSA_1024:    {"quantum_broken": True,  "classical_broken": True,  "qday_years": 0,  "security_bits_classical": 80,  "security_bits_quantum": 0},
    ClassicalAlgorithm.RSA_2048:    {"quantum_broken": True,  "classical_broken": False, "qday_years": 10, "security_bits_classical": 112, "security_bits_quantum": 0},
    ClassicalAlgorithm.RSA_3072:    {"quantum_broken": True,  "classical_broken": False, "qday_years": 12, "security_bits_classical": 128, "security_bits_quantum": 0},
    ClassicalAlgorithm.RSA_4096:    {"quantum_broken": True,  "classical_broken": False, "qday_years": 14, "security_bits_classical": 140, "security_bits_quantum": 0},
    ClassicalAlgorithm.ECDH_P256:   {"quantum_broken": True,  "classical_broken": False, "qday_years": 10, "security_bits_classical": 128, "security_bits_quantum": 0},
    ClassicalAlgorithm.ECDH_P384:   {"quantum_broken": True,  "classical_broken": False, "qday_years": 12, "security_bits_classical": 192, "security_bits_quantum": 0},
    ClassicalAlgorithm.ECDSA_P256:  {"quantum_broken": True,  "classical_broken": False, "qday_years": 10, "security_bits_classical": 128, "security_bits_quantum": 0},
    ClassicalAlgorithm.ECDSA_P384:  {"quantum_broken": True,  "classical_broken": False, "qday_years": 12, "security_bits_classical": 192, "security_bits_quantum": 0},
    ClassicalAlgorithm.DH_2048:     {"quantum_broken": True,  "classical_broken": False, "qday_years": 10, "security_bits_classical": 112, "security_bits_quantum": 0},
    ClassicalAlgorithm.AES_128_GCM: {"quantum_broken": False, "classical_broken": False, "qday_years": 99, "security_bits_classical": 128, "security_bits_quantum": 64},
    ClassicalAlgorithm.AES_256_GCM: {"quantum_broken": False, "classical_broken": False, "qday_years": 99, "security_bits_classical": 256, "security_bits_quantum": 128},
    ClassicalAlgorithm.SHA256:      {"quantum_broken": False, "classical_broken": False, "qday_years": 99, "security_bits_classical": 128, "security_bits_quantum": 64},
    ClassicalAlgorithm.SHA384:      {"quantum_broken": False, "classical_broken": False, "qday_years": 99, "security_bits_classical": 192, "security_bits_quantum": 96},
}

# Recommended replacement mapping
RECOMMENDED_REPLACEMENTS = {
    ClassicalAlgorithm.RSA_2048:   {"kem": "Kyber-768",    "sig": "Dilithium3",  "hybrid_sig": "Dilithium3+ECDSA-P256"},
    ClassicalAlgorithm.RSA_4096:   {"kem": "Kyber-1024",   "sig": "Dilithium5",  "hybrid_sig": "Dilithium5+ECDSA-P384"},
    ClassicalAlgorithm.ECDH_P256:  {"kem": "Kyber-768",    "sig": "FALCON-512",  "hybrid_sig": "FALCON-512+ECDSA-P256"},
    ClassicalAlgorithm.ECDH_P384:  {"kem": "Kyber-1024",   "sig": "FALCON-1024", "hybrid_sig": "FALCON-1024+ECDSA-P384"},
    ClassicalAlgorithm.ECDSA_P256: {"kem": "Kyber-768",    "sig": "Dilithium3",  "hybrid_sig": "Dilithium3+ECDSA-P256"},
    ClassicalAlgorithm.ECDSA_P384: {"kem": "Kyber-1024",   "sig": "Dilithium5",  "hybrid_sig": "Dilithium5+ECDSA-P384"},
    ClassicalAlgorithm.DH_2048:    {"kem": "Kyber-768",    "sig": "Dilithium3",  "hybrid_sig": "Dilithium3+RSA-2048"},
    ClassicalAlgorithm.AES_128_GCM:{"kem": "AES-256-GCM",  "sig": "N/A — symmetric", "hybrid_sig": "N/A"},
    ClassicalAlgorithm.AES_256_GCM:{"kem": "AES-256-GCM",  "sig": "N/A — already quantum-safe at L1", "hybrid_sig": "N/A"},
    ClassicalAlgorithm.SHA256:     {"kem": "SHA3-256",      "sig": "N/A", "hybrid_sig": "N/A"},
    ClassicalAlgorithm.RSA_1024:   {"kem": "Kyber-768",    "sig": "Dilithium3",  "hybrid_sig": "Dilithium3"},
    ClassicalAlgorithm.RSA_3072:   {"kem": "Kyber-768",    "sig": "Dilithium3",  "hybrid_sig": "Dilithium3+RSA-3072"},
    ClassicalAlgorithm.SHA384:     {"kem": "SHA3-384",      "sig": "N/A", "hybrid_sig": "N/A"},
}


class MigrationEngine:
    """
    Automated PQC migration planning engine for financial institutions.
    """

    # Q-Day estimate distribution (years from now)
    QDAY_OPTIMISTIC  = 8
    QDAY_MEDIAN      = 12
    QDAY_PESSIMISTIC = 17

    def assess_asset(self, asset: CryptoAsset) -> MigrationAssessment:
        """Assess a single cryptographic asset's migration needs"""
        vuln = ALGORITHM_VULNERABILITY.get(asset.algorithm, {})
        repl = RECOMMENDED_REPLACEMENTS.get(asset.algorithm, {})

        quantum_broken  = vuln.get("quantum_broken", True)
        qday_years      = vuln.get("qday_years", 10)

        # Risk score calculation
        risk_score = self._compute_risk_score(asset, vuln)

        # HNDL risk: if data retained beyond Q-Day, already compromised retroactively
        hndl_risk = max(0.0, asset.retention_years - qday_years)

        # Migration urgency
        urgency = self._determine_urgency(asset, vuln, risk_score)

        # Hybrid mode recommendation
        hybrid_needed = (
            asset.protocol in [FinancialProtocol.TLS_1_2, FinancialProtocol.TLS_1_3, FinancialProtocol.HTTPS]
            and quantum_broken
        )

        # Effort estimate
        effort = self._estimate_effort(asset)

        # Compliance flags
        compliance = self._check_compliance(asset, urgency)

        # Migration steps
        steps = self._generate_migration_steps(asset, repl, hybrid_needed)

        return MigrationAssessment(
            asset=asset,
            urgency=urgency,
            risk_score=round(risk_score, 1),
            hndl_risk_years=round(hndl_risk, 1),
            recommended_kem=repl.get("kem", "Kyber-768"),
            recommended_sig=repl.get("sig", "Dilithium3"),
            hybrid_mode_needed=hybrid_needed,
            estimated_migration_effort=effort,
            compatibility_notes=self._compatibility_notes(asset),
            compliance_flags=compliance,
            migration_steps=steps,
        )

    def generate_plan(
        self, institution_name: str, assets: list
    ) -> MigrationPlan:
        """Generate full migration plan for an institution"""
        assessments = [self.assess_asset(a) for a in assets]

        counts = {u: sum(1 for a in assessments if a.urgency == u) for u in MigrationUrgency}
        avg_risk = sum(a.risk_score for a in assessments) / len(assessments) if assessments else 0

        quick_wins = [
            a for a in assessments
            if a.urgency in [MigrationUrgency.CRITICAL, MigrationUrgency.HIGH]
            and a.estimated_migration_effort == "days"
        ]

        compliance_status = {
            "NIST_SP_800_208":   all(a.urgency not in [MigrationUrgency.CRITICAL] for a in assessments),
            "CNSA_2.0":          counts[MigrationUrgency.CRITICAL] == 0,
            "DORA_quantum_risk": counts[MigrationUrgency.CRITICAL] + counts[MigrationUrgency.HIGH] < len(assets) // 4,
            "NSA_CNSSP_15":      all(a.asset.algorithm != ClassicalAlgorithm.RSA_1024 for a in assessments),
        }

        exec_summary = (
            f"{institution_name} has {len(assets)} cryptographic assets assessed. "
            f"{counts[MigrationUrgency.CRITICAL]} require critical attention, "
            f"{counts[MigrationUrgency.HIGH]} are high priority. "
            f"Overall quantum risk score: {avg_risk:.0f}/100. "
            f"Estimated Q-Day exposure window: {self.QDAY_OPTIMISTIC}-{self.QDAY_PESSIMISTIC} years."
        )

        return MigrationPlan(
            institution_name=institution_name,
            total_assets=len(assets),
            critical_count=counts[MigrationUrgency.CRITICAL],
            high_count=counts[MigrationUrgency.HIGH],
            medium_count=counts[MigrationUrgency.MEDIUM],
            low_count=counts[MigrationUrgency.LOW],
            overall_risk_score=round(avg_risk, 1),
            assessments=assessments,
            executive_summary=exec_summary,
            quick_wins=[a.asset.name for a in quick_wins],
            compliance_status=compliance_status,
        )

    def _compute_risk_score(self, asset: CryptoAsset, vuln: dict) -> float:
        score = 0.0
        # Quantum vulnerability weight (40 points)
        if vuln.get("quantum_broken"):
            score += 40
        elif vuln.get("security_bits_quantum", 128) < 128:
            score += 20
        # Data sensitivity weight (30 points)
        sensitivity_map = {"public": 0, "internal": 10, "confidential": 20, "secret": 30}
        score += sensitivity_map.get(asset.data_sensitivity, 15)
        # Retention risk (20 points)
        qday = vuln.get("qday_years", 10)
        if asset.retention_years > qday:
            score += 20
        elif asset.retention_years > qday - 3:
            score += 10
        # Volume (10 points)
        if asset.daily_transaction_volume > 1_000_000:
            score += 10
        elif asset.daily_transaction_volume > 10_000:
            score += 5
        return min(score, 100.0)

    def _determine_urgency(self, asset: CryptoAsset, vuln: dict, risk_score: float) -> MigrationUrgency:
        if not vuln.get("quantum_broken", False):
            return MigrationUrgency.NONE
        if vuln.get("classical_broken", False):
            return MigrationUrgency.CRITICAL
        if risk_score >= 80:
            return MigrationUrgency.CRITICAL
        if risk_score >= 60:
            return MigrationUrgency.HIGH
        if risk_score >= 35:
            return MigrationUrgency.MEDIUM
        return MigrationUrgency.LOW

    def _estimate_effort(self, asset: CryptoAsset) -> str:
        if asset.protocol in [FinancialProtocol.TLS_1_3, FinancialProtocol.HTTPS]:
            return "days"
        if asset.protocol in [FinancialProtocol.TLS_1_2, FinancialProtocol.SSH_2]:
            return "weeks"
        if asset.protocol in [FinancialProtocol.FIX_4_4, FinancialProtocol.FIX_5_0]:
            return "weeks"
        if asset.protocol in [FinancialProtocol.SWIFT, FinancialProtocol.ISO_20022]:
            return "months"
        return "weeks"

    def _check_compliance(self, asset: CryptoAsset, urgency: MigrationUrgency) -> list:
        flags = []
        if urgency == MigrationUrgency.CRITICAL:
            flags.append("NON-COMPLIANT: CNSA 2.0 requires PQC for national security systems")
        if asset.algorithm in [ClassicalAlgorithm.RSA_1024]:
            flags.append("NON-COMPLIANT: RSA-1024 deprecated by NIST SP 800-131A")
        if asset.retention_years > 10 and urgency != MigrationUrgency.NONE:
            flags.append("RISK: HNDL threat — data could be decrypted before retention period ends")
        if asset.protocol == FinancialProtocol.TLS_1_2:
            flags.append("WARNING: TLS 1.2 does not support hybrid PQC — upgrade to TLS 1.3")
        if not flags:
            flags.append("COMPLIANT: No immediate compliance issues")
        return flags

    def _compatibility_notes(self, asset: CryptoAsset) -> list:
        notes = []
        if asset.protocol == FinancialProtocol.TLS_1_3:
            notes.append("TLS 1.3 supports hybrid key exchange (X25519Kyber768) — minimal code change")
        if asset.protocol == FinancialProtocol.SWIFT:
            notes.append("SWIFT CSP (Customer Security Programme) migration path available via SWIFTNet PKI update")
        if asset.protocol == FinancialProtocol.FIX_5_0:
            notes.append("FIX 5.0 SP2 supports custom security extensions — Kyber/Dilithium feasible")
        if asset.protocol == FinancialProtocol.ISO_20022:
            notes.append("ISO 20022 XML signature standard can adopt Dilithium with schema extension")
        return notes if notes else ["Standard migration path applies"]

    def _generate_migration_steps(self, asset: CryptoAsset, repl: dict, hybrid: bool) -> list:
        steps = [
            f"1. Inventory: Document all systems using {asset.algorithm.value}",
            f"2. Test: Deploy {repl.get('kem', 'Kyber-768')} in test environment",
        ]
        if hybrid:
            steps.append(f"3. Hybrid: Enable {repl.get('hybrid_sig', 'Dilithium3+ECDSA')} simultaneously")
            steps.append(f"4. Monitor: Validate no performance regression over 2-week window")
            steps.append(f"5. Cutover: Migrate to pure PQC after hybrid validation")
        else:
            steps.append(f"3. Migrate: Replace with {repl.get('sig', 'Dilithium3')}")
            steps.append(f"4. Validate: Run end-to-end tests on all protocol flows")
        steps.append(f"5. Document: Update crypto policy and compliance records")
        return steps
