"""PQC algorithms and migration API routes"""

from fastapi import APIRouter, HTTPException
from api.models.schemas import (
    KyberBenchmarkRequest, DilithiumBenchmarkRequest,
    MigrationPlanRequest,
)
from core.pqc import (
    KyberSimulator, KyberVariant,
    DilithiumSimulator, FALCONSimulator, DilithiumVariant, FALCONVariant,
    MigrationEngine, CryptoAsset, ClassicalAlgorithm, FinancialProtocol,
)

router = APIRouter(prefix="/api/v1/pqc", tags=["Post-Quantum Cryptography"])


@router.post("/kyber/benchmark", summary="CRYSTALS-Kyber Performance vs RSA-2048")
def kyber_benchmark(req: KyberBenchmarkRequest):
    """
    Benchmark CRYSTALS-Kyber KEM (NIST FIPS 203) against RSA-2048.
    Returns key sizes, performance timings, and security level comparison.
    """
    try:
        variant_map = {
            "kyber512": KyberVariant.KYBER_512,
            "kyber768": KyberVariant.KYBER_768,
            "kyber1024": KyberVariant.KYBER_1024,
        }
        variant = variant_map.get(req.variant, KyberVariant.KYBER_768)
        sim = KyberSimulator()
        return sim.benchmark_vs_rsa(variant)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/kyber/keygen", summary="Simulate Kyber Key Generation")
def kyber_keygen(req: KyberBenchmarkRequest):
    """Generate a Kyber key pair and return sizes, parameters, and timing"""
    try:
        variant_map = {"kyber512": KyberVariant.KYBER_512, "kyber768": KyberVariant.KYBER_768, "kyber1024": KyberVariant.KYBER_1024}
        variant = variant_map.get(req.variant, KyberVariant.KYBER_768)
        sim = KyberSimulator()
        keypair = sim.keygen(variant)
        enc     = sim.encapsulate(keypair)
        dec     = sim.decapsulate(keypair, enc.ciphertext, enc.shared_secret)
        return {
            "algorithm": keypair.params.name,
            "nist_security_level": keypair.params.nist_security_level,
            "public_key_bytes": keypair.params.public_key_bytes,
            "secret_key_bytes": keypair.params.secret_key_bytes,
            "ciphertext_bytes": keypair.params.ciphertext_bytes,
            "shared_secret_bytes": keypair.params.shared_secret_bytes,
            "keygen_time_ms": keypair.generation_time_ms,
            "encapsulation_time_ms": enc.encapsulation_time_ms,
            "decapsulation_time_ms": dec.decapsulation_time_ms,
            "secrets_match": dec.secrets_match,
            "quantum_security_bits": keypair.params.quantum_security_bits,
            "classical_security_bits": keypair.params.classical_security_bits,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dilithium/benchmark", summary="CRYSTALS-Dilithium vs ECDSA P-256")
def dilithium_benchmark(req: DilithiumBenchmarkRequest):
    """
    Benchmark CRYSTALS-Dilithium (NIST FIPS 204) against ECDSA P-256.
    Returns signature sizes, performance, and security comparison.
    """
    try:
        variant_map = {
            "dilithium2": DilithiumVariant.DILITHIUM2,
            "dilithium3": DilithiumVariant.DILITHIUM3,
            "dilithium5": DilithiumVariant.DILITHIUM5,
        }
        variant = variant_map.get(req.variant, DilithiumVariant.DILITHIUM3)
        sim = DilithiumSimulator()
        return sim.benchmark_vs_ecdsa(variant)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/falcon/signature-comparison", summary="Signature Size Comparison All Algorithms")
def falcon_comparison():
    """Compare signature sizes across all PQC and classical digital signature schemes"""
    try:
        sim = FALCONSimulator()
        return sim.signature_size_comparison()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/migration/plan", summary="Generate PQC Migration Plan")
def migration_plan(req: MigrationPlanRequest):
    """
    Generate a full post-quantum cryptography migration plan for a financial institution.
    Input: list of cryptographic assets. Output: prioritized migration roadmap.
    """
    try:
        engine = MigrationEngine()
        assets = []
        for a in req.assets:
            try:
                algo = ClassicalAlgorithm(a.algorithm)
            except ValueError:
                algo = ClassicalAlgorithm.RSA_2048
            try:
                proto = FinancialProtocol(a.protocol)
            except ValueError:
                proto = FinancialProtocol.TLS_1_3

            assets.append(CryptoAsset(
                asset_id=a.asset_id,
                name=a.name,
                algorithm=algo,
                protocol=proto,
                data_sensitivity=a.data_sensitivity,
                retention_years=a.retention_years,
                system=a.system,
                daily_transaction_volume=a.daily_transaction_volume,
            ))

        plan = engine.generate_plan(req.institution_name, assets)
        return {
            "institution": plan.institution_name,
            "total_assets": plan.total_assets,
            "critical_count": plan.critical_count,
            "high_count": plan.high_count,
            "medium_count": plan.medium_count,
            "low_count": plan.low_count,
            "overall_risk_score": plan.overall_risk_score,
            "executive_summary": plan.executive_summary,
            "quick_wins": plan.quick_wins,
            "compliance_status": plan.compliance_status,
            "assessments": [
                {
                    "asset": a.asset.name,
                    "algorithm": a.asset.algorithm.value,
                    "urgency": a.urgency.value,
                    "risk_score": a.risk_score,
                    "hndl_risk_years": a.hndl_risk_years,
                    "recommended_kem": a.recommended_kem,
                    "recommended_sig": a.recommended_sig,
                    "hybrid_mode_needed": a.hybrid_mode_needed,
                    "effort": a.estimated_migration_effort,
                    "compliance_flags": a.compliance_flags,
                    "migration_steps": a.migration_steps,
                }
                for a in plan.assessments
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/algorithms/support-matrix", summary="Algorithm Support Matrix Across Financial Protocols")
def algorithm_support_matrix():
    """Return PQC algorithm compatibility matrix for financial protocols"""
    return {
        "kem_algorithms": [
            {"name": "Kyber-512",  "nist_level": 1, "standard": "FIPS 203", "tls13": True, "swift": False, "fix": False, "status": "Standardized 2024"},
            {"name": "Kyber-768",  "nist_level": 3, "standard": "FIPS 203", "tls13": True, "swift": "Roadmap", "fix": "Roadmap", "status": "Recommended"},
            {"name": "Kyber-1024", "nist_level": 5, "standard": "FIPS 203", "tls13": True, "swift": False, "fix": False, "status": "Standardized 2024"},
        ],
        "signature_algorithms": [
            {"name": "Dilithium2",   "nist_level": 2, "standard": "FIPS 204", "tls13": True, "code_signing": True, "status": "Standardized 2024"},
            {"name": "Dilithium3",   "nist_level": 3, "standard": "FIPS 204", "tls13": True, "code_signing": True, "status": "Recommended"},
            {"name": "FALCON-512",   "nist_level": 1, "standard": "FIPS 206", "tls13": True, "code_signing": True, "status": "Smallest signatures"},
            {"name": "FALCON-1024",  "nist_level": 5, "standard": "FIPS 206", "tls13": True, "code_signing": True, "status": "Standardized 2024"},
            {"name": "SPHINCS+-128f","nist_level": 1, "standard": "FIPS 205", "tls13": True, "code_signing": True, "status": "Hash-based — most conservative"},
        ],
        "hybrid_schemes": [
            {"name": "X25519Kyber768", "description": "Hybrid classical+PQC for TLS 1.3 transition", "tlsrfc": "draft-ietf-tls-hybrid-design"},
            {"name": "P384Kyber1024",  "description": "High-security hybrid", "tlsrfc": "draft"},
        ],
        "deprecated_algorithms": [
            {"name": "RSA-1024",  "reason": "Classically broken — NIST deprecated 2010"},
            {"name": "DH-1024",   "reason": "Logjam vulnerability"},
            {"name": "3DES",      "reason": "Sweet32 attack — NIST deprecated 2023"},
            {"name": "RC4",       "reason": "Multiple vulnerabilities — never use"},
        ]
    }
