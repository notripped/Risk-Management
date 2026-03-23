"""QKD simulation API routes"""

from fastapi import APIRouter, HTTPException
from api.models.schemas import (
    BB84Request, BB84Response, E91Request, E91Response,
    MDIQKDRequest, ChannelAnalysisRequest, DistanceSweepRequest, AttackSweepRequest
)
from core.qkd import (
    BB84Simulator, QuantumChannel, AttackType,
    E91Simulator,
    MDIQKDSimulator,
    QKDChannelAnalyzer, ChannelMedium, HARDWARE_PROFILES
)

router = APIRouter(prefix="/api/v1/qkd", tags=["QKD Protocols"])


@router.post("/bb84/simulate", response_model=BB84Response, summary="Run BB84 QKD Protocol Simulation")
def simulate_bb84(req: BB84Request):
    """
    Simulate the BB84 Quantum Key Distribution protocol.

    Returns QBER, secure key rate, eavesdropping detection, and full protocol statistics.
    Attack types: none, intercept_resend, photon_number_splitting
    """
    try:
        attack_map = {
            "none": AttackType.NONE,
            "intercept_resend": AttackType.INTERCEPT_RESEND,
            "photon_number_splitting": AttackType.PHOTON_NUMBER_SPLITTING,
        }
        attack = attack_map.get(req.attack_type, AttackType.NONE)

        channel = QuantumChannel(
            distance_km=req.distance_km,
            detector_efficiency=req.detector_efficiency,
            dark_count_rate=req.dark_count_rate,
            attack=attack,
            attack_intercept_fraction=req.intercept_fraction,
        )

        sim = BB84Simulator()
        result = sim.run(n_qubits=req.n_qubits, channel=channel)

        return BB84Response(
            n_qubits_sent=result.n_qubits_sent,
            n_sifted_bits=result.n_sifted_bits,
            n_secure_key_bits=result.n_secure_key_bits,
            qber=result.qber,
            secure_key_rate_bps=result.secure_key_rate_bps,
            eve_detected=result.eve_detected,
            eve_information=result.eve_information,
            attack_type=result.attack_type.value,
            error_correction_bits_leaked=result.error_correction_bits_leaked,
            privacy_amplification_compression=result.privacy_amplification_compression,
            simulation_stats=result.simulation_stats,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/e91/simulate", response_model=E91Response, summary="Run E91 Entanglement-Based QKD Simulation")
def simulate_e91(req: E91Request):
    """
    Simulate E91 quantum key distribution using entangled EPR pairs and Bell inequality tests.
    Returns CHSH Bell parameter, eavesdropping detection, and secure key rate.
    """
    try:
        sim = E91Simulator()
        result = sim.run(
            n_pairs=req.n_pairs,
            distance_km=req.distance_km,
            entanglement_fidelity=req.entanglement_fidelity,
            eavesdropping=req.eavesdropping,
            eve_intercept_fraction=req.eve_intercept_fraction,
        )
        return E91Response(
            n_pairs_sent=result.n_pairs_sent,
            n_sifted_bits=result.n_sifted_bits,
            n_secure_key_bits=result.n_secure_key_bits,
            bell_parameter_s=result.bell_parameter_s,
            bell_violation=result.bell_violation,
            qber=result.qber,
            eavesdropping_detected=result.eavesdropping_detected,
            entanglement_fidelity=result.entanglement_fidelity,
            secure_key_rate_bps=result.secure_key_rate_bps,
            simulation_stats=result.simulation_stats,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mdi-qkd/simulate", summary="Run MDI-QKD Simulation (Detector-Attack Immune)")
def simulate_mdi_qkd(req: MDIQKDRequest):
    """
    Simulate Measurement Device Independent QKD.
    Security holds even if the central relay (Charlie) is fully controlled by Eve.
    """
    try:
        sim = MDIQKDSimulator()
        result = sim.run(
            n_pulses=req.n_pulses,
            alice_distance_km=req.alice_distance_km,
            bob_distance_km=req.bob_distance_km,
            charlie_is_malicious=req.charlie_is_malicious,
        )
        return {
            "n_pulses_sent": result.n_pulses_sent,
            "n_successful_bsm": result.n_successful_bsm,
            "n_sifted_bits": result.n_sifted_bits,
            "n_secure_key_bits": result.n_secure_key_bits,
            "qber": result.qber,
            "bsm_success_rate": result.bsm_success_rate,
            "secure_key_rate_bps": result.secure_key_rate_bps,
            "detector_attack_immune": result.detector_attack_immune,
            "charlie_malicious_impact": "None — MDI-QKD security holds regardless" if req.charlie_is_malicious else "N/A",
            "simulation_stats": result.simulation_stats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/channel/analyze", summary="Analyze QKD Channel Capacity")
def analyze_channel(req: ChannelAnalysisRequest):
    """
    Analyze QKD channel capacity for a given hardware profile, medium, and distance.
    Returns key rates, loss, QBER, and viability.
    """
    try:
        medium_map = {m.value: m for m in ChannelMedium}
        medium = medium_map.get(req.medium, ChannelMedium.FIBER_SMF28)
        analyzer = QKDChannelAnalyzer()
        result = analyzer.analyze(
            hardware_key=req.hardware_key,
            medium=medium,
            distance_km=req.distance_km,
            additional_loss_db=req.additional_loss_db,
        )
        return {
            "hardware": result.hardware,
            "medium": result.medium.value,
            "distance_km": result.distance_km,
            "raw_key_rate_bps": result.raw_key_rate_bps,
            "sifted_key_rate_bps": result.sifted_key_rate_bps,
            "secure_key_rate_bps": result.secure_key_rate_bps,
            "qber": result.qber,
            "channel_loss_db": result.channel_loss_db,
            "total_loss_db": result.total_loss_db,
            "viable": result.viable,
            "max_viable_distance_km": result.max_viable_distance_km,
            "decoy_state_enabled": result.decoy_state_enabled,
            "notes": result.notes,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bb84/sweep-distance", summary="BB84 Key Rate vs Distance Sweep")
def sweep_distance(req: DistanceSweepRequest):
    """Compute BB84 secure key rate across a range of distances"""
    try:
        sim = BB84Simulator()
        return sim.sweep_distance(req.distances_km, n_qubits=req.n_qubits)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bb84/sweep-attack", summary="BB84 QBER vs Eavesdropping Intensity")
def sweep_attack(req: AttackSweepRequest):
    """Model QBER and Eve's information gain vs intercept fraction"""
    try:
        sim = BB84Simulator()
        return sim.sweep_attack(req.intercept_fractions)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hardware/profiles", summary="List Available QKD Hardware Profiles")
def get_hardware_profiles():
    """Return all available QKD hardware profiles with specifications"""
    return {
        key: {
            "name": hw.name,
            "vendor": hw.vendor,
            "source_type": hw.source_type,
            "clock_rate_hz": hw.clock_rate_hz,
            "detector_efficiency": hw.detector_efficiency,
            "max_range_km": hw.max_range_km,
            "approx_cost_usd": hw.approx_cost_usd,
            "decoy_state_needed": hw.is_decoy_state_needed,
        }
        for key, hw in HARDWARE_PROFILES.items()
    }


@router.post("/hardware/compare", summary="Compare Hardware at Distance")
def compare_hardware(distance_km: float = 50.0):
    """Compare all QKD hardware profiles at a given distance"""
    try:
        analyzer = QKDChannelAnalyzer()
        return analyzer.sweep_hardware_comparison(distance_km=distance_km)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
