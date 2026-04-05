"""
Cryptographic Inventory Auditor

Scans and audits the cryptographic posture of a financial institution's
infrastructure. Provides cipher suite analysis, certificate health checks,
protocol version mapping, and quantum vulnerability scoring.

Used for:
- Pre-migration baseline assessment
- Compliance reporting (DORA, CNSA 2.0, PCI-DSS, SOC2)
- Board-level quantum risk dashboard
- Integration point before PQC migration planner
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class CipherSuiteRating(Enum):
    QUANTUM_SAFE    = "quantum_safe"
    HYBRID_READY    = "hybrid_ready"
    CLASSICAL_WEAK  = "classical_weak"
    BROKEN          = "broken"


@dataclass
class CipherSuiteProfile:
    iana_name: str
    key_exchange: str
    authentication: str
    bulk_cipher: str
    mac: str
    tls_versions: list
    quantum_rating: CipherSuiteRating
    classical_security_bits: int
    quantum_security_bits: int
    deprecation_status: str


@dataclass
class SystemCryptoProfile:
    """Cryptographic profile of a single system/service"""
    system_name: str
    system_type: str          # "trading_engine", "web_api", "database", etc.
    cipher_suites: list       # List of IANA cipher suite names in use
    tls_version: str
    certificate_algorithm: str
    certificate_key_size: int
    certificate_expiry_days: int
    hsts_enabled: bool
    forward_secrecy: bool
    hostname: str
    department: str


@dataclass
class CryptoAuditResult:
    system: SystemCryptoProfile
    quantum_vulnerability_score: float   # 0-100
    weak_suites: list
    broken_suites: list
    compliant_suites: list
    tls_issues: list
    certificate_issues: list
    overall_grade: str          # A+ to F
    compliance_status: dict
    recommendations: list


@dataclass
class InstitutionCryptoAudit:
    institution: str
    total_systems: int
    systems_audited: int
    grade_distribution: dict
    critical_findings: int
    quantum_vulnerable_systems: int
    avg_quantum_vulnerability_score: float
    system_audits: list
    summary_recommendations: list
    compliance_overview: dict


# Cipher suite database — IANA names + quantum ratings
CIPHER_SUITE_DB = {
    # TLS 1.3 suites — safe against classical, AES-256 partially safe against quantum
    "TLS_AES_256_GCM_SHA384":               CipherSuiteProfile("TLS_AES_256_GCM_SHA384", "ECDHE", "RSA/ECDSA", "AES-256-GCM", "SHA384", ["1.3"], CipherSuiteRating.HYBRID_READY, 256, 128, "Current — upgrade KEM to Kyber"),
    "TLS_AES_128_GCM_SHA256":               CipherSuiteProfile("TLS_AES_128_GCM_SHA256", "ECDHE", "RSA/ECDSA", "AES-128-GCM", "SHA256", ["1.3"], CipherSuiteRating.HYBRID_READY, 128, 64, "Current — upgrade KEM and to AES-256"),
    "TLS_CHACHA20_POLY1305_SHA256":         CipherSuiteProfile("TLS_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA/ECDSA", "CHACHA20", "SHA256", ["1.3"], CipherSuiteRating.HYBRID_READY, 256, 128, "Current — add Kyber KEM"),
    # TLS 1.2 with ECDHE — quantum vulnerable KE
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": CipherSuiteProfile("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES-256-GCM", "SHA384", ["1.2", "1.3"], CipherSuiteRating.CLASSICAL_WEAK, 256, 0, "ECDHE broken by Grover+Shor"),
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": CipherSuiteProfile("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES-128-GCM", "SHA256", ["1.2"], CipherSuiteRating.CLASSICAL_WEAK, 128, 0, "Weak — ECDHE quantum-broken"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": CipherSuiteProfile("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AES-256-GCM", "SHA384", ["1.2"], CipherSuiteRating.CLASSICAL_WEAK, 256, 0, "Both KE and auth broken by quantum"),
    # RSA key exchange — worst case
    "TLS_RSA_WITH_AES_256_GCM_SHA384":      CipherSuiteProfile("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AES-256-GCM", "SHA384", ["1.2"], CipherSuiteRating.BROKEN, 256, 0, "No forward secrecy + quantum-broken KE"),
    "TLS_RSA_WITH_AES_128_GCM_SHA256":      CipherSuiteProfile("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AES-128-GCM", "SHA256", ["1.2"], CipherSuiteRating.BROKEN, 128, 0, "No forward secrecy + quantum-broken KE"),
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA":        CipherSuiteProfile("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", "SHA1", ["1.0", "1.1", "1.2"], CipherSuiteRating.BROKEN, 112, 0, "DEPRECATED: Sweet32 attack + quantum-broken"),
    # Post-quantum hybrid (future)
    "TLS_KYBER768_WITH_AES_256_GCM_SHA384": CipherSuiteProfile("TLS_KYBER768_WITH_AES_256_GCM_SHA384", "Kyber-768", "Dilithium3", "AES-256-GCM", "SHA384", ["1.3"], CipherSuiteRating.QUANTUM_SAFE, 192, 178, "Recommended — NIST standardized PQC"),
    "X25519Kyber768Draft00":                CipherSuiteProfile("X25519Kyber768Draft00", "X25519+Kyber768", "RSA/ECDSA", "AES-256-GCM", "SHA384", ["1.3"], CipherSuiteRating.QUANTUM_SAFE, 256, 178, "Hybrid classical+PQC — recommended transition"),
}

# Certificate algorithm vulnerability
CERT_ALGORITHM_RATINGS = {
    "RSA-1024": {"quantum_safe": False, "classical_safe": False, "grade_penalty": 40},
    "RSA-2048": {"quantum_safe": False, "classical_safe": True,  "grade_penalty": 25},
    "RSA-3072": {"quantum_safe": False, "classical_safe": True,  "grade_penalty": 20},
    "RSA-4096": {"quantum_safe": False, "classical_safe": True,  "grade_penalty": 15},
    "EC-P-256":  {"quantum_safe": False, "classical_safe": True, "grade_penalty": 20},
    "EC-P-384":  {"quantum_safe": False, "classical_safe": True, "grade_penalty": 15},
    "Dilithium3":{"quantum_safe": True,  "classical_safe": True, "grade_penalty": 0},
    "FALCON-512":{"quantum_safe": True,  "classical_safe": True, "grade_penalty": 0},
}


class CryptoAuditor:
    """
    Cryptographic posture auditor for financial infrastructure.
    """

    def audit_system(self, system: SystemCryptoProfile) -> CryptoAuditResult:
        """Audit cryptographic posture of a single system"""

        weak_suites    = []
        broken_suites  = []
        compliant      = []
        tls_issues     = []
        cert_issues    = []
        recommendations = []

        # Cipher suite analysis
        vuln_score = 0.0
        for suite_name in system.cipher_suites:
            profile = CIPHER_SUITE_DB.get(suite_name)
            if not profile:
                weak_suites.append(f"{suite_name} (unknown — treat as vulnerable)")
                vuln_score += 20
                continue
            if profile.quantum_rating == CipherSuiteRating.BROKEN:
                broken_suites.append(suite_name)
                vuln_score += 40
            elif profile.quantum_rating == CipherSuiteRating.CLASSICAL_WEAK:
                weak_suites.append(suite_name)
                vuln_score += 25
            elif profile.quantum_rating == CipherSuiteRating.QUANTUM_SAFE:
                compliant.append(suite_name)

        # TLS version
        if system.tls_version in ["1.0", "1.1"]:
            tls_issues.append(f"TLS {system.tls_version} is deprecated (CVE exposure + no PQC support)")
            vuln_score += 15
        elif system.tls_version == "1.2":
            tls_issues.append("TLS 1.2: No hybrid PQC support — upgrade to TLS 1.3 recommended")
            vuln_score += 5

        if not system.forward_secrecy:
            tls_issues.append("Forward secrecy disabled — all past traffic decryptable if key compromised")
            vuln_score += 15

        # Certificate analysis
        cert_rating = CERT_ALGORITHM_RATINGS.get(system.certificate_algorithm, {})
        vuln_score += cert_rating.get("grade_penalty", 20)

        if not cert_rating.get("quantum_safe", False):
            cert_issues.append(f"Certificate algorithm {system.certificate_algorithm} is quantum-vulnerable")
        if system.certificate_expiry_days < 30:
            cert_issues.append(f"Certificate expires in {system.certificate_expiry_days} days — critical")
        elif system.certificate_expiry_days < 90:
            cert_issues.append(f"Certificate expires in {system.certificate_expiry_days} days — schedule renewal")

        vuln_score = min(vuln_score, 100.0)

        # Grade
        grade = self._compute_grade(vuln_score, bool(broken_suites), bool(tls_issues))

        # Compliance
        compliance = self._check_compliance(system, grade, bool(broken_suites))

        # Recommendations
        if broken_suites:
            recommendations.append(f"IMMEDIATE: Disable {len(broken_suites)} broken cipher suite(s)")
        if system.tls_version in ["1.0", "1.1"]:
            recommendations.append("CRITICAL: Upgrade TLS to 1.3 immediately")
        if not cert_rating.get("quantum_safe", False):
            recommendations.append(f"Migrate certificate to CRYSTALS-Dilithium3 or FALCON-512")
        if not any("Kyber" in s for s in compliant):
            recommendations.append("Add X25519Kyber768 hybrid cipher suite for post-quantum key exchange")
        if not system.forward_secrecy:
            recommendations.append("Enable forward secrecy — required for HNDL protection")

        return CryptoAuditResult(
            system=system,
            quantum_vulnerability_score=round(vuln_score, 1),
            weak_suites=weak_suites,
            broken_suites=broken_suites,
            compliant_suites=compliant,
            tls_issues=tls_issues,
            certificate_issues=cert_issues,
            overall_grade=grade,
            compliance_status=compliance,
            recommendations=recommendations,
        )

    def audit_institution(
        self, institution: str, systems: list
    ) -> InstitutionCryptoAudit:
        """Full institution-wide cryptographic audit"""
        results = [self.audit_system(s) for s in systems]

        grade_dist = {}
        for r in results:
            grade_dist[r.overall_grade] = grade_dist.get(r.overall_grade, 0) + 1

        critical = sum(1 for r in results if r.overall_grade in ["D", "F"])
        vuln_scores = [r.quantum_vulnerability_score for r in results]
        avg_score = sum(vuln_scores) / len(vuln_scores) if vuln_scores else 0
        quantum_vuln = sum(1 for r in results if r.quantum_vulnerability_score > 50)

        # Summary recommendations
        summary = []
        if any(r.broken_suites for r in results):
            n = sum(len(r.broken_suites) for r in results)
            summary.append(f"Immediate: Disable {n} broken cipher suites across {sum(1 for r in results if r.broken_suites)} systems")
        if any("1.0" in r.system.tls_version or "1.1" in r.system.tls_version for r in results):
            summary.append("Critical: Upgrade all TLS 1.0/1.1 endpoints to TLS 1.3")
        summary.append("Deploy X25519Kyber768 hybrid KEM across all TLS 1.3 endpoints")
        summary.append("Begin certificate migration to Dilithium3 starting with external-facing systems")

        compliance_over = {
            "PCI_DSS_4.0":     all(r.system.tls_version not in ["1.0", "1.1"] for r in results),
            "NIST_SP_800_52":   not any(r.broken_suites for r in results),
            "CNSA_2.0":         quantum_vuln == 0,
            "DORA_Art_9":       avg_score < 50,
        }

        return InstitutionCryptoAudit(
            institution=institution,
            total_systems=len(systems),
            systems_audited=len(results),
            grade_distribution=grade_dist,
            critical_findings=critical,
            quantum_vulnerable_systems=quantum_vuln,
            avg_quantum_vulnerability_score=round(avg_score, 1),
            system_audits=[self._result_to_dict(r) for r in results],
            summary_recommendations=summary,
            compliance_overview=compliance_over,
        )

    def _compute_grade(self, vuln_score: float, has_broken: bool, has_tls_issues: bool) -> str:
        if has_broken or vuln_score > 85:
            return "F"
        if vuln_score > 70:
            return "D"
        if vuln_score > 55:
            return "C"
        if vuln_score > 35:
            return "B"
        if has_tls_issues:
            return "B+"
        if vuln_score > 15:
            return "A"
        return "A+"

    def _check_compliance(self, system: SystemCryptoProfile, grade: str, has_broken: bool) -> dict:
        return {
            "PCI_DSS_4.0": grade not in ["D", "F"] and system.tls_version not in ["1.0", "1.1"],
            "NIST_SP_800_52": not has_broken,
            "FIPS_140_3": system.tls_version == "1.3" and not has_broken,
            "quantum_ready": grade in ["A+", "A"],
        }

    def _result_to_dict(self, r: CryptoAuditResult) -> dict:
        return {
            "system": r.system.system_name,
            "grade": r.overall_grade,
            "quantum_vulnerability_score": r.quantum_vulnerability_score,
            "broken_suites": r.broken_suites,
            "weak_suites": r.weak_suites,
            "tls_issues": r.tls_issues,
            "cert_issues": r.certificate_issues,
            "recommendations": r.recommendations,
            "compliance": r.compliance_status,
        }
