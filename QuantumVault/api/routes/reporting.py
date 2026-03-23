"""Reporting and roadmap API routes"""

from fastapi import APIRouter, HTTPException
from api.models.schemas import RoadmapRequest, TopologyRequest, RepeaterChainRequest, KeyGenerationRequest, KeyRequestETSI
from core.reporting import RoadmapGenerator, INSTITUTION_PROFILES
from core.network import QKDNetworkModeler, TrustedRelayDesigner
from core.key_management import QKDKeyManagementSystem, KeyUsePurpose

router = APIRouter(prefix="/api/v1", tags=["Reporting & Infrastructure"])

# Global KMS instance (in production: per-tenant, persisted)
_kms = QKDKeyManagementSystem()


@router.post("/roadmap/generate", summary="Generate QKD Deployment Roadmap")
def generate_roadmap(req: RoadmapRequest):
    """
    Generate a phased QKD infrastructure deployment roadmap for a financial institution.
    Includes cost model, ROI projections, compliance milestones, and vendor recommendations.
    """
    try:
        gen = RoadmapGenerator()
        roadmap = gen.generate(
            institution_name=req.institution_name,
            institution_type=req.institution_type,
            current_risk_score=req.current_risk_score,
            n_offices=req.n_offices,
            prioritize_pqc_first=req.prioritize_pqc_first,
        )
        return {
            "institution_name": roadmap.institution_name,
            "institution_type": roadmap.institution_type,
            "assessment_date": roadmap.assessment_date,
            "total_duration_months": roadmap.total_duration_months,
            "total_capital_cost_usd": roadmap.total_capital_cost_usd,
            "total_annual_opex_usd": roadmap.total_annual_opex_usd,
            "executive_summary": roadmap.executive_summary,
            "board_presentation_points": roadmap.board_presentation_points,
            "quick_wins": roadmap.quick_wins,
            "phases": roadmap.phases,
            "roi_projections": roadmap.roi_projections,
            "vendor_recommendations": roadmap.vendor_recommendations,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/roadmap/institution-types", summary="List Supported Institution Types")
def institution_types():
    """Return all supported institution types with profile details"""
    return {k: {**v, "breach_cost_estimate_usd": v["breach_cost_estimate_usd"]} for k, v in INSTITUTION_PROFILES.items()}


@router.post("/network/topology/analyze", summary="Analyze QKD Network Topology")
def analyze_topology(req: TopologyRequest):
    """
    Model and analyze a QKD network topology for a financial institution.
    Returns link viability, key rates, costs, and recommendations.
    """
    try:
        modeler  = QKDNetworkModeler()
        topology = modeler.create_financial_topology(
            institution=req.institution,
            offices=[o.dict() for o in req.offices],
            topology_type=req.topology_type,
        )
        result = modeler.analyze_topology(topology)
        return {
            "institution": topology.institution,
            "topology_type": topology.topology_type,
            "total_nodes": len(topology.nodes),
            "total_links": result.total_links,
            "viable_links": result.viable_links,
            "bottleneck_links": result.bottleneck_links,
            "min_key_rate_bps": result.min_key_rate_bps,
            "avg_key_rate_bps": result.avg_key_rate_bps,
            "max_key_rate_bps": result.max_key_rate_bps,
            "trusted_nodes_required": result.trusted_nodes_required,
            "total_infrastructure_cost_usd": result.total_infrastructure_cost_usd,
            "annual_key_material_bits": result.annual_key_material_bits,
            "network_resilience_score": result.network_resilience_score,
            "recommendations": result.recommendations,
            "link_analysis": result.link_analysis,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/repeater/design", summary="Design Trusted Relay Chain")
def design_repeater_chain(req: RepeaterChainRequest):
    """
    Design an optimal trusted relay chain for long-distance QKD.
    Compares trusted relay vs satellite vs future quantum repeater options.
    """
    try:
        designer = TrustedRelayDesigner()
        chain    = designer.design_chain(
            total_distance_km=req.total_distance_km,
            target_key_rate_bps=req.target_key_rate_bps,
            max_segment_km=req.max_segment_km,
        )
        options  = designer.compare_long_distance_options(req.total_distance_km)
        return {
            "relay_chain": {
                "total_distance_km": chain.total_distance_km,
                "n_segments": chain.n_segments,
                "relay_nodes": chain.repeater_nodes,
                "effective_key_rate_bps": chain.effective_key_rate_bps,
                "security_level": chain.chain_security_level,
                "total_capital_cost_usd": chain.total_capital_cost_usd,
                "annual_opex_usd": chain.annual_opex_usd,
                "availability_percent": chain.availability_percent,
                "max_segment_km": chain.max_segment_distance_km,
                "single_point_of_failure_risk": chain.single_point_of_failure,
            },
            "alternative_options": options,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------ #
#  ETSI QKD KMS Routes                                                  #
# ------------------------------------------------------------------ #

@router.post("/keys/{slave_sae_id}/generate", summary="Generate Keys into QKD KMS")
def generate_keys(slave_sae_id: str, req: KeyGenerationRequest):
    """Populate the KMS with simulated QKD keys"""
    try:
        n = _kms.generate_simulated_keys(
            n_keys=req.n_keys,
            link_id=req.link_id,
            key_size_bits=req.key_size_bits,
            ttl_seconds=req.ttl_seconds,
        )
        return {"keys_generated": n, "link_id": req.link_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/keys/{slave_sae_id}/enc_keys", summary="ETSI QKD 014 — Get Encryption Keys")
def get_enc_keys(slave_sae_id: str, number: int = 1, size: int = 256):
    """
    ETSI GS QKD 014 compliant key retrieval endpoint.
    Returns fresh quantum key material for consumption.
    """
    try:
        result = _kms.get_key(slave_sae_id=slave_sae_id, number=number, size_bits=size)
        if result is None:
            raise HTTPException(status_code=503, detail="Insufficient key material — refill QKD store")
        return {"keys": result.keys}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/keys/{slave_sae_id}/status", summary="ETSI QKD 014 — KMS Status")
def kms_status(slave_sae_id: str):
    """ETSI GS QKD 014 compliant status endpoint"""
    try:
        return _kms.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/keys/{link_id}/rotate", summary="Rotate QKD Keys on Link")
def rotate_keys(link_id: str, new_key_rate_bps: float = 1000.0):
    """Trigger key rotation on a QKD link"""
    try:
        return _kms.rotate_keys(link_id=link_id, new_key_rate_bps=new_key_rate_bps)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/keys/stats", summary="QKD KMS Store Statistics")
def kms_stats():
    """Return comprehensive key store statistics"""
    try:
        stats = _kms.get_stats()
        return {
            "total_keys": stats.total_keys,
            "fresh_keys": stats.fresh_keys,
            "reserved_keys": stats.reserved_keys,
            "consumed_keys": stats.consumed_keys,
            "expired_keys": stats.expired_keys,
            "total_bits_available": stats.total_bits_available,
            "total_bits_consumed": stats.total_bits_consumed,
            "key_consumption_rate_bps": stats.key_consumption_rate_bps,
            "average_ttl_remaining_s": stats.average_ttl_remaining_s,
            "per_link_stats": stats.links,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
