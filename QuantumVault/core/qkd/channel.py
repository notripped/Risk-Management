"""
Quantum Channel Models for QKD Infrastructure

Models physical quantum channels used in financial-grade QKD deployments:
- SMF-28 single-mode fiber (inter-office, metro, long-haul)
- Free-space optical (satellite-to-ground, building-to-building)
- Underwater optical (submarine cable alternative)

Provides realistic loss, noise, and capacity calculations for
network planning and infrastructure sizing.
"""

import numpy as np
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class ChannelMedium(Enum):
    FIBER_SMF28    = "fiber_smf28"       # Standard telecom fiber
    FIBER_ULTRA_LOW_LOSS = "fiber_ull"  # Ultra-low-loss fiber (0.16 dB/km)
    FREE_SPACE     = "free_space"        # Atmospheric/satellite
    UNDERWATER     = "underwater"        # Submarine optical


@dataclass
class QKDHardwareProfile:
    """Characterizes QKD hardware platform"""
    name: str
    source_type: str              # "weak_coherent", "entangled", "single_photon"
    mean_photon_number: float     # mu parameter for WCP source
    clock_rate_hz: float
    detector_efficiency: float
    dark_count_rate_hz: float
    timing_jitter_ps: float       # Timing jitter in picoseconds
    max_range_km: float
    vendor: str
    approx_cost_usd: int

    @property
    def is_decoy_state_needed(self) -> bool:
        """Decoy state protocol needed for WCP sources to resist PNS attacks"""
        return self.source_type == "weak_coherent"


# Industry hardware profiles (representative specs)
HARDWARE_PROFILES = {
    "toshiba_qkd": QKDHardwareProfile(
        name="Toshiba Multiplexed QKD",
        source_type="weak_coherent",
        mean_photon_number=0.1,
        clock_rate_hz=3e9,
        detector_efficiency=0.85,
        dark_count_rate_hz=100,
        timing_jitter_ps=20,
        max_range_km=100,
        vendor="Toshiba Research",
        approx_cost_usd=150_000
    ),
    "idq_clavis3": QKDHardwareProfile(
        name="ID Quantique Clavis3",
        source_type="weak_coherent",
        mean_photon_number=0.1,
        clock_rate_hz=2.5e9,
        detector_efficiency=0.80,
        dark_count_rate_hz=200,
        timing_jitter_ps=40,
        max_range_km=80,
        vendor="ID Quantique",
        approx_cost_usd=120_000
    ),
    "quantinuum_H2": QKDHardwareProfile(
        name="Quantinuum Ion-Trap (Entangled)",
        source_type="entangled",
        mean_photon_number=1.0,
        clock_rate_hz=1e6,
        detector_efficiency=0.99,
        dark_count_rate_hz=10,
        timing_jitter_ps=100,
        max_range_km=50,
        vendor="Quantinuum",
        approx_cost_usd=500_000
    ),
    "research_grade": QKDHardwareProfile(
        name="Research Grade SNSPD",
        source_type="single_photon",
        mean_photon_number=0.9,
        clock_rate_hz=500e6,
        detector_efficiency=0.95,
        dark_count_rate_hz=50,
        timing_jitter_ps=15,
        max_range_km=150,
        vendor="Custom / Academic",
        approx_cost_usd=250_000
    )
}


@dataclass
class ChannelCapacityResult:
    """QKD channel capacity analysis"""
    hardware: str
    medium: ChannelMedium
    distance_km: float
    raw_key_rate_bps: float
    sifted_key_rate_bps: float
    secure_key_rate_bps: float
    qber: float
    channel_loss_db: float
    total_loss_db: float
    viable: bool             # True if secure key rate > 0
    max_viable_distance_km: float
    decoy_state_enabled: bool
    notes: list


class QKDChannelAnalyzer:
    """
    Compute QKD channel capacity, key rates, and viability
    for different hardware configurations and distances.
    Used for network planning and infrastructure sizing.
    """

    def analyze(
        self,
        hardware_key: str = "toshiba_qkd",
        medium: ChannelMedium = ChannelMedium.FIBER_SMF28,
        distance_km: float = 50.0,
        additional_loss_db: float = 3.0,    # Connectors, splices, etc.
    ) -> ChannelCapacityResult:
        hw = HARDWARE_PROFILES.get(hardware_key, HARDWARE_PROFILES["toshiba_qkd"])

        # Channel loss
        channel_loss_db = self._channel_loss(medium, distance_km)
        total_loss_db   = channel_loss_db + additional_loss_db
        transmittance   = 10 ** (-total_loss_db / 10)

        # Detection rate
        signal_rate     = hw.clock_rate_hz * hw.mean_photon_number * transmittance * hw.detector_efficiency
        dark_rate       = hw.dark_count_rate_hz
        total_rate      = signal_rate + dark_rate

        # QBER computation
        # Optical misalignment + dark counts + detector afterpulsing
        qber_optical    = 0.01   # 1% optical misalignment
        qber_dark       = dark_rate / (2 * total_rate) if total_rate > 0 else 0.5

        qber = qber_optical + qber_dark

        # Key rates
        raw_key_rate    = total_rate
        sifted_key_rate = raw_key_rate * 0.5    # 50% basis matching

        # Secret key fraction (Devetak-Winter / GLLP formula)
        def h(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        # Clamp to a minimum noise floor — real detectors always have dark counts
        # and alignment errors, so QBER=0 is physically unreachable
        qber = max(qber, 1e-3)

        if qber >= 0.11:
            secret_fraction = 0.0
        else:
            secret_fraction = max(0.0, 1 - 2 * h(qber))

        # PNS correction for WCP source
        if hw.source_type == "weak_coherent" and hw.is_decoy_state_needed:
            # Decoy state protocol: secret fraction ~= 1 - h(QBER) - h(phase_QBER)
            # Without decoy: severely limited by PNS
            pns_factor = 1.0   # With decoy state, full security restored
        else:
            pns_factor = 1.0

        secure_key_rate = sifted_key_rate * secret_fraction * pns_factor

        viable = secure_key_rate > 0 and qber < 0.11

        # Estimate max viable distance
        max_dist = self._max_viable_distance(hw, medium)

        notes = []
        if not viable:
            notes.append(f"Channel not viable at {distance_km}km — QBER {qber:.3f} exceeds threshold")
        if hw.is_decoy_state_needed:
            notes.append("Decoy state protocol enabled to counter PNS attacks")
        if distance_km > 80:
            notes.append("Consider trusted repeater or quantum repeater for this range")
        if total_loss_db > 25:
            notes.append(f"High channel loss ({total_loss_db:.1f}dB) — check fiber quality")

        return ChannelCapacityResult(
            hardware=hw.name,
            medium=medium,
            distance_km=distance_km,
            raw_key_rate_bps=round(raw_key_rate, 2),
            sifted_key_rate_bps=round(sifted_key_rate, 2),
            secure_key_rate_bps=round(secure_key_rate, 2),
            qber=round(qber, 6),
            channel_loss_db=round(channel_loss_db, 2),
            total_loss_db=round(total_loss_db, 2),
            viable=viable,
            max_viable_distance_km=round(max_dist, 1),
            decoy_state_enabled=hw.is_decoy_state_needed,
            notes=notes
        )

    def sweep_hardware_comparison(
        self, distance_km: float = 50.0
    ) -> list:
        """Compare all hardware profiles at a given distance"""
        results = []
        for hw_key in HARDWARE_PROFILES:
            r = self.analyze(hardware_key=hw_key, distance_km=distance_km)
            results.append({
                "hardware": r.hardware,
                "vendor": HARDWARE_PROFILES[hw_key].vendor,
                "secure_key_rate_bps": r.secure_key_rate_bps,
                "qber": r.qber,
                "viable": r.viable,
                "max_range_km": r.max_viable_distance_km,
                "cost_usd": HARDWARE_PROFILES[hw_key].approx_cost_usd,
                "cost_per_bps": (
                    HARDWARE_PROFILES[hw_key].approx_cost_usd / r.secure_key_rate_bps
                    if r.secure_key_rate_bps > 0 else float("inf")
                )
            })
        return sorted(results, key=lambda x: x["secure_key_rate_bps"], reverse=True)

    def _channel_loss(self, medium: ChannelMedium, distance_km: float) -> float:
        coefficients = {
            ChannelMedium.FIBER_SMF28:         0.20,   # dB/km
            ChannelMedium.FIBER_ULTRA_LOW_LOSS: 0.16,
            ChannelMedium.FREE_SPACE:           0.03,   # Clear atmosphere
            ChannelMedium.UNDERWATER:           0.04,   # Blue-green wavelength
        }
        return coefficients.get(medium, 0.20) * distance_km

    def _is_viable(self, hw: QKDHardwareProfile, medium: ChannelMedium, distance_km: float) -> bool:
        """Compute viability directly without calling analyze() to avoid recursion"""
        channel_loss_db = self._channel_loss(medium, distance_km)
        total_loss_db   = channel_loss_db + 3.0   # default additional loss
        transmittance   = 10 ** (-total_loss_db / 10)

        signal_rate = hw.clock_rate_hz * hw.mean_photon_number * transmittance * hw.detector_efficiency
        dark_rate   = hw.dark_count_rate_hz
        total_rate  = signal_rate + dark_rate

        qber_optical = 0.01
        qber_dark    = dark_rate / (2 * total_rate) if total_rate > 0 else 0.5
        qber         = qber_optical + qber_dark

        if qber >= 0.11:
            return False

        def h(p):
            if p <= 0 or p >= 1:
                return 0.0
            return -p * np.log2(p) - (1 - p) * np.log2(1 - p)

        secret_fraction = max(0.0, 1 - 2 * h(qber))
        secure_key_rate = (total_rate * 0.5) * secret_fraction
        return secure_key_rate > 0

    def _max_viable_distance(self, hw: QKDHardwareProfile, medium: ChannelMedium) -> float:
        """Binary search for maximum viable distance"""
        lo, hi = 0.0, 500.0
        for _ in range(30):
            mid = (lo + hi) / 2
            if self._is_viable(hw, medium, mid):
                lo = mid
            else:
                hi = mid
        return lo
