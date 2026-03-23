"""Threat modeling API routes"""

from fastapi import APIRouter, HTTPException
from api.models.schemas import HNDLPortfolioRequest, CryptoAuditRequest
from core.threat import (
    HNDLRiskEngine, HNDLExposureRecord, DataCategory,
    QDayTimeline,
    CryptoAuditor, SystemCryptoProfile,
)

router = APIRouter(prefix="/api/v1/threat", tags=["Threat Modeling"])


@router.post("/hndl/assess", summary="HNDL Portfolio Risk Assessment")
def assess_hndl(req: HNDLPortfolioRequest):
    """
    Assess Harvest-Now-Decrypt-Later exposure across a portfolio of financial data assets.
    Produces risk scores, financial exposure estimates, and prioritized remediation.
    """
    try:
        engine  = HNDLRiskEngine()
        records = []
        for item in req.records:
            cat = DataCategory(item.data_category)
            records.append(HNDLExposureRecord(
                data_category=cat,
                volume_gb_per_day=item.volume_gb_per_day,
                encryption_algorithm=item.encryption_algorithm,
                channel=item.channel,
                adversary_access_likelihood=item.adversary_access_likelihood,
            ))
        report = engine.assess_portfolio(records, req.adversary_type, req.qday_scenario)
        return {
            "total_daily_volume_gb":      report.total_daily_volume_gb,
            "total_annual_exposure_gb":   report.total_annual_exposure_gb,
            "total_financial_exposure_usd": report.total_financial_exposure_usd,
            "critical_assets":            report.critical_assets,
            "overall_risk_score":         report.overall_risk_score,
            "top_3_risks":                report.top_3_risks,
            "immediate_actions":          report.immediate_actions,
            "qday_scenarios":             report.qday_scenarios,
            "asset_results":              report.asset_results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/qday/timeline", summary="Q-Day Timeline Analysis")
def qday_timeline(current_year: int = 2026):
    """
    Return probabilistic Q-Day timeline with hardware roadmap assessments.
    Based on published quantum hardware roadmaps and academic consensus.
    """
    try:
        analyzer = QDayTimeline()
        result   = analyzer.analyze(current_year=current_year)
        return {
            "current_year": result.current_year,
            "median_qday_year": result.median_qday_year,
            "probability_before_2030": result.probability_before_2030,
            "probability_before_2035": result.probability_before_2035,
            "probability_before_2040": result.probability_before_2040,
            "scenarios": result.scenarios,
            "hardware_assessments": result.hardware_assessments,
            "shor_algorithm_requirements": result.shor_algorithm_requirements,
            "risk_horizon_for_finance": result.risk_horizon_for_finance,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/qday/probability-density", summary="Q-Day Annual Probability Density")
def qday_probability_density(start_year: int = 2028, end_year: int = 2060):
    """Return annual probability density for Q-Day occurrence"""
    try:
        analyzer = QDayTimeline()
        years = list(range(start_year, end_year + 1))
        return analyzer.probability_density(years)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crypto-audit/institution", summary="Institution-Wide Cryptographic Audit")
def crypto_audit(req: CryptoAuditRequest):
    """
    Audit cryptographic posture of all systems in a financial institution.
    Returns cipher suite grades, vulnerability scores, and compliance status.
    """
    try:
        auditor = CryptoAuditor()
        systems = [
            SystemCryptoProfile(
                system_name=s.system_name,
                system_type=s.system_type,
                cipher_suites=s.cipher_suites,
                tls_version=s.tls_version,
                certificate_algorithm=s.certificate_algorithm,
                certificate_key_size=s.certificate_key_size,
                certificate_expiry_days=s.certificate_expiry_days,
                hsts_enabled=s.hsts_enabled,
                forward_secrecy=s.forward_secrecy,
                hostname=s.hostname,
                department=s.department,
            )
            for s in req.systems
        ]
        result = auditor.audit_institution(req.institution, systems)
        return {
            "institution": result.institution,
            "total_systems": result.total_systems,
            "grade_distribution": result.grade_distribution,
            "critical_findings": result.critical_findings,
            "quantum_vulnerable_systems": result.quantum_vulnerable_systems,
            "avg_quantum_vulnerability_score": result.avg_quantum_vulnerability_score,
            "summary_recommendations": result.summary_recommendations,
            "compliance_overview": result.compliance_overview,
            "system_audits": result.system_audits,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/data-categories", summary="List Available Data Categories for HNDL Assessment")
def list_data_categories():
    """Return all supported financial data categories with retention requirements"""
    from core.threat.hndl import RETENTION_REQUIREMENTS, DATA_VALUE_SCORES
    return [
        {
            "category": cat.value,
            "retention_years": RETENTION_REQUIREMENTS.get(cat, "N/A"),
            "value_score": DATA_VALUE_SCORES.get(cat, "N/A"),
        }
        for cat in DataCategory
    ]
