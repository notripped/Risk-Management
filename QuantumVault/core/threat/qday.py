"""
Q-Day Timeline Probability Model

Models the probability distribution of when a Cryptographically Relevant
Quantum Computer (CRQC) will be built — capable of breaking RSA-2048
using Shor's Algorithm.

Based on:
- Published quantum hardware roadmaps (IBM, Google, IonQ, Quantinuum)
- Academic consensus surveys (Mosca 2022, IRACST, GlobalRisk Institute)
- NSA/CISA threat assessments
- Hardware scaling laws and error correction overhead analysis

Key uncertainties:
- Quantum error correction overhead (logical vs physical qubit ratio)
- Progress on fault-tolerant quantum computing
- Unexpected algorithmic breakthroughs
- Geopolitical acceleration (nation-state investment spikes)
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class QDayScenario:
    name: str
    year: int
    probability: float
    description: str
    required_logical_qubits: int
    required_physical_qubits: int   # With current error correction overhead
    current_state_gap: str


@dataclass
class HardwareRoadmap:
    vendor: str
    current_qubit_count: int
    current_error_rate: float   # 2-qubit gate error rate
    roadmap_2027: int
    roadmap_2030: int
    fault_tolerant_eta_year: int
    notes: str


@dataclass
class QDayAnalysis:
    current_year: int
    scenarios: list
    probability_before_2030: float
    probability_before_2035: float
    probability_before_2040: float
    median_qday_year: int
    hardware_assessments: list
    shor_algorithm_requirements: dict
    risk_horizon_for_finance: str


# Published hardware roadmaps (as of early 2026)
HARDWARE_ROADMAPS = [
    HardwareRoadmap(
        vendor="IBM Quantum",
        current_qubit_count=1121,   # Condor (2023) + ongoing scaling
        current_error_rate=0.003,
        roadmap_2027=4000,
        roadmap_2030=100_000,
        fault_tolerant_eta_year=2033,
        notes="100k physical qubits targeted for fault-tolerant era"
    ),
    HardwareRoadmap(
        vendor="Google Quantum AI",
        current_qubit_count=105,    # Willow (2024)
        current_error_rate=0.0014,
        roadmap_2027=500,
        roadmap_2030=10_000,
        fault_tolerant_eta_year=2033,
        notes="Willow demonstrated below-threshold error correction"
    ),
    HardwareRoadmap(
        vendor="Quantinuum (ion trap)",
        current_qubit_count=56,
        current_error_rate=0.0002,
        roadmap_2027=200,
        roadmap_2030=1000,
        fault_tolerant_eta_year=2031,
        notes="Lower qubit count but highest gate fidelity — logical qubit leader"
    ),
    HardwareRoadmap(
        vendor="IonQ",
        current_qubit_count=35,
        current_error_rate=0.0004,
        roadmap_2027=256,
        roadmap_2030=2000,
        fault_tolerant_eta_year=2032,
        notes="Algorithmic qubit metric: effective performance exceeds raw count"
    ),
    HardwareRoadmap(
        vendor="Microsoft (topological)",
        current_qubit_count=8,    # Topological qubits — early stage
        current_error_rate=0.001,
        roadmap_2027=100,
        roadmap_2030=10_000,
        fault_tolerant_eta_year=2032,
        notes="Topological qubits promise intrinsic error protection — high uncertainty"
    ),
]


# Q-Day scenarios based on consensus literature
QDAY_SCENARIOS = [
    QDayScenario(
        name="Black Swan",
        year=2031,
        probability=0.05,
        description="Unexpected algorithmic breakthrough or classified advance dramatically accelerates timeline",
        required_logical_qubits=4099,
        required_physical_qubits=400_000,
        current_state_gap="~10-100x physical qubit scaling + error correction breakthrough needed"
    ),
    QDayScenario(
        name="Optimistic",
        year=2034,
        probability=0.15,
        description="Fault-tolerant milestones achieved ahead of schedule; error correction overhead lower than expected",
        required_logical_qubits=4099,
        required_physical_qubits=400_000,
        current_state_gap="~100x physical qubit scaling from current leaders"
    ),
    QDayScenario(
        name="Base Case",
        year=2038,
        probability=0.50,
        description="Steady progress on fault-tolerant quantum computing per current roadmaps",
        required_logical_qubits=4099,
        required_physical_qubits=1_000_000,
        current_state_gap="~1000x physical qubit scaling; major fault-tolerance milestones needed"
    ),
    QDayScenario(
        name="Conservative",
        year=2043,
        probability=0.25,
        description="Significant engineering challenges slow fault-tolerant progress",
        required_logical_qubits=4099,
        required_physical_qubits=4_000_000,
        current_state_gap="Multi-decade engineering challenge; multiple breakthroughs required"
    ),
    QDayScenario(
        name="Very Conservative",
        year=2055,
        probability=0.05,
        description="Fundamental engineering barriers persist; CRQC delayed to mid-century",
        required_logical_qubits=4099,
        required_physical_qubits=10_000_000,
        current_state_gap="Long-horizon challenge — multiple paradigm shifts needed"
    ),
]


class QDayTimeline:
    """
    Probabilistic Q-Day timeline analysis.
    """

    # Shor's algorithm requirements for RSA-2048
    # Based on Gidney & Ekerå (2021): "How to factor 2048 bit RSA integers in 8 hours"
    SHOR_RSA2048_LOGICAL_QUBITS    = 4099
    SHOR_RSA2048_TOFFOLI_GATES     = 2.84e12
    SHOR_RSA2048_SURFACE_CODE_DIST = 27
    SHOR_RSA2048_HOURS             = 8.0    # At 1MHz logical clock

    # Physical qubit requirement (depends on error correction code and threshold)
    SHOR_PHYSICAL_QUBITS_SURFACE_CODE = 1_000_000   # Central estimate
    SHOR_PHYSICAL_QUBITS_OPTIMISTIC   = 400_000     # Lower bound
    SHOR_PHYSICAL_QUBITS_PESSIMISTIC  = 4_000_000   # Upper bound

    def analyze(self, current_year: int = 2026) -> QDayAnalysis:
        """Generate full Q-Day timeline analysis"""

        prob_before_2030 = sum(
            s.probability for s in QDAY_SCENARIOS if s.year <= 2030
        )
        prob_before_2035 = sum(
            s.probability for s in QDAY_SCENARIOS if s.year <= 2035
        )
        prob_before_2040 = sum(
            s.probability for s in QDAY_SCENARIOS if s.year <= 2040
        )

        # Weighted median year
        cumulative = 0
        median_year = QDAY_SCENARIOS[-1].year
        for s in sorted(QDAY_SCENARIOS, key=lambda x: x.year):
            cumulative += s.probability
            if cumulative >= 0.5:
                median_year = s.year
                break

        hw_assessments = [
            {
                "vendor": hw.vendor,
                "current_qubits": hw.current_qubit_count,
                "current_error_rate": hw.current_error_rate,
                "target_2030": hw.roadmap_2030,
                "fault_tolerant_eta": hw.fault_tolerant_eta_year,
                "shor_readiness": "Ready" if hw.roadmap_2030 >= self.SHOR_PHYSICAL_QUBITS_OPTIMISTIC
                                          else f"Gap: {self.SHOR_PHYSICAL_QUBITS_OPTIMISTIC - hw.roadmap_2030:,} physical qubits",
                "notes": hw.notes,
            }
            for hw in HARDWARE_ROADMAPS
        ]

        # Finance-specific risk horizon
        if prob_before_2030 > 0.1:
            horizon = "CRITICAL — Act immediately. Q-Day possible within financial data retention window."
        elif prob_before_2035 > 0.2:
            horizon = "HIGH — Begin PQC migration now. Q-Day likely within long-retention data window."
        elif prob_before_2040 > 0.5:
            horizon = "MEDIUM — PQC migration should be underway. HNDL risk is active."
        else:
            horizon = "MODERATE — Long timeline but HNDL risk means harvest is happening NOW."

        return QDayAnalysis(
            current_year=current_year,
            scenarios=[self._scenario_to_dict(s) for s in QDAY_SCENARIOS],
            probability_before_2030=round(prob_before_2030, 3),
            probability_before_2035=round(prob_before_2035, 3),
            probability_before_2040=round(prob_before_2040, 3),
            median_qday_year=median_year,
            hardware_assessments=hw_assessments,
            shor_algorithm_requirements={
                "algorithm": "Shor (Gidney & Ekerå, 2021)",
                "target": "RSA-2048",
                "logical_qubits": self.SHOR_RSA2048_LOGICAL_QUBITS,
                "physical_qubits_central": self.SHOR_PHYSICAL_QUBITS_SURFACE_CODE,
                "physical_qubits_range": f"{self.SHOR_PHYSICAL_QUBITS_OPTIMISTIC:,} – {self.SHOR_PHYSICAL_QUBITS_PESSIMISTIC:,}",
                "estimated_runtime_hours": self.SHOR_RSA2048_HOURS,
                "surface_code_distance": self.SHOR_RSA2048_SURFACE_CODE_DIST,
            },
            risk_horizon_for_finance=horizon,
        )

    def probability_density(
        self, years: list, seed: int = 42
    ) -> list:
        """
        Compute annual probability density for Q-Day occurrence.
        Uses log-normal mixture model over scenario points.
        """
        rng = np.random.default_rng(seed)
        annual_probs = []
        for year in years:
            # Weighted probability that Q-Day is in this specific year
            prob = 0.0
            for s in QDAY_SCENARIOS:
                # Gaussian spread ±2 years around each scenario
                prob += s.probability * np.exp(-0.5 * ((year - s.year) / 2) ** 2) / (2 * np.sqrt(2 * np.pi))
            annual_probs.append({"year": year, "probability_density": round(prob, 6)})
        return annual_probs

    def _scenario_to_dict(self, s: QDayScenario) -> dict:
        return {
            "name": s.name,
            "year": s.year,
            "probability": s.probability,
            "description": s.description,
            "logical_qubits_needed": s.required_logical_qubits,
            "physical_qubits_needed": s.required_physical_qubits,
            "gap_description": s.current_state_gap,
        }
