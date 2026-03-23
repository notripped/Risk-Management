"""
Pydantic schemas for QuantumVault API request/response models.
All endpoints follow OpenAPI 3.0 specification.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


# ------------------------------------------------------------------ #
#  QKD Schemas                                                          #
# ------------------------------------------------------------------ #

class BB84Request(BaseModel):
    n_qubits: int = Field(default=10000, ge=1000, le=500000, description="Number of qubits to send")
    distance_km: float = Field(default=10.0, ge=0.1, le=500.0)
    detector_efficiency: float = Field(default=0.85, ge=0.1, le=1.0)
    dark_count_rate: float = Field(default=100.0, ge=0.0)
    attack_type: str = Field(default="none", description="none|intercept_resend|photon_number_splitting")
    intercept_fraction: float = Field(default=0.0, ge=0.0, le=1.0)

class BB84Response(BaseModel):
    n_qubits_sent: int
    n_sifted_bits: int
    n_secure_key_bits: int
    qber: float
    secure_key_rate_bps: float
    eve_detected: bool
    eve_information: float
    attack_type: str
    error_correction_bits_leaked: int
    privacy_amplification_compression: float
    simulation_stats: dict


class E91Request(BaseModel):
    n_pairs: int = Field(default=10000, ge=1000, le=200000)
    distance_km: float = Field(default=50.0, ge=0.1, le=500.0)
    entanglement_fidelity: float = Field(default=0.97, ge=0.5, le=1.0)
    eavesdropping: bool = Field(default=False)
    eve_intercept_fraction: float = Field(default=0.0, ge=0.0, le=1.0)

class E91Response(BaseModel):
    n_pairs_sent: int
    n_sifted_bits: int
    n_secure_key_bits: int
    bell_parameter_s: float
    bell_violation: bool
    qber: float
    eavesdropping_detected: bool
    entanglement_fidelity: float
    secure_key_rate_bps: float
    simulation_stats: dict


class MDIQKDRequest(BaseModel):
    n_pulses: int = Field(default=50000, ge=1000, le=500000)
    alice_distance_km: float = Field(default=25.0, ge=0.1, le=250.0)
    bob_distance_km: float = Field(default=25.0, ge=0.1, le=250.0)
    charlie_is_malicious: bool = Field(default=False)

class ChannelAnalysisRequest(BaseModel):
    hardware_key: str = Field(default="toshiba_qkd")
    medium: str = Field(default="fiber_smf28")
    distance_km: float = Field(default=50.0, ge=0.1, le=500.0)
    additional_loss_db: float = Field(default=3.0, ge=0.0, le=20.0)

class DistanceSweepRequest(BaseModel):
    distances_km: List[float] = Field(default=[10, 20, 40, 60, 80, 100, 150])
    n_qubits: int = Field(default=20000, ge=5000)

class AttackSweepRequest(BaseModel):
    intercept_fractions: List[float] = Field(default=[0.0, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 1.0])


# ------------------------------------------------------------------ #
#  PQC Schemas                                                          #
# ------------------------------------------------------------------ #

class KyberBenchmarkRequest(BaseModel):
    variant: str = Field(default="kyber768", description="kyber512|kyber768|kyber1024")

class DilithiumBenchmarkRequest(BaseModel):
    variant: str = Field(default="dilithium3")

class CryptoAssetInput(BaseModel):
    asset_id: str
    name: str
    algorithm: str
    protocol: str
    data_sensitivity: str = Field(default="confidential")
    retention_years: int = Field(default=7, ge=1, le=50)
    system: str = Field(default="trading_engine")
    daily_transaction_volume: int = Field(default=0, ge=0)

class MigrationPlanRequest(BaseModel):
    institution_name: str
    assets: List[CryptoAssetInput]


# ------------------------------------------------------------------ #
#  Threat Schemas                                                       #
# ------------------------------------------------------------------ #

class HNDLExposureInput(BaseModel):
    data_category: str
    volume_gb_per_day: float = Field(ge=0.001)
    encryption_algorithm: str
    channel: str
    adversary_access_likelihood: float = Field(ge=0.0, le=1.0)

class HNDLPortfolioRequest(BaseModel):
    records: List[HNDLExposureInput]
    adversary_type: str = Field(default="nation_state")
    qday_scenario: str = Field(default="median")

class SystemCryptoInput(BaseModel):
    system_name: str
    system_type: str
    cipher_suites: List[str]
    tls_version: str
    certificate_algorithm: str
    certificate_key_size: int = Field(default=2048)
    certificate_expiry_days: int = Field(default=365)
    hsts_enabled: bool = Field(default=True)
    forward_secrecy: bool = Field(default=True)
    hostname: str = Field(default="")
    department: str = Field(default="")

class CryptoAuditRequest(BaseModel):
    institution: str
    systems: List[SystemCryptoInput]


# ------------------------------------------------------------------ #
#  Network Schemas                                                      #
# ------------------------------------------------------------------ #

class OfficeLocation(BaseModel):
    name: str
    city: str
    lat: float = Field(default=51.5)
    lon: float = Field(default=-0.1)

class TopologyRequest(BaseModel):
    institution: str
    offices: List[OfficeLocation]
    topology_type: str = Field(default="ring", description="ring|star|mesh")

class RepeaterChainRequest(BaseModel):
    total_distance_km: float = Field(ge=1.0, le=5000.0)
    target_key_rate_bps: float = Field(default=10000.0)
    max_segment_km: float = Field(default=80.0)


# ------------------------------------------------------------------ #
#  KMS Schemas                                                          #
# ------------------------------------------------------------------ #

class KeyGenerationRequest(BaseModel):
    n_keys: int = Field(default=100, ge=1, le=10000)
    link_id: str = Field(default="link_01")
    key_size_bits: int = Field(default=256, ge=64, le=4096)
    ttl_seconds: int = Field(default=3600, ge=60)

class KeyRequestETSI(BaseModel):
    slave_sae_id: str
    number: int = Field(default=1, ge=1, le=100)
    size: int = Field(default=256, ge=64, le=4096)
    purpose: str = Field(default="aes_rekey")


# ------------------------------------------------------------------ #
#  Reporting Schemas                                                    #
# ------------------------------------------------------------------ #

class RoadmapRequest(BaseModel):
    institution_name: str
    institution_type: str = Field(default="hedge_fund")
    current_risk_score: float = Field(default=75.0, ge=0.0, le=100.0)
    n_offices: int = Field(default=3, ge=2, le=50)
    prioritize_pqc_first: bool = Field(default=True)
