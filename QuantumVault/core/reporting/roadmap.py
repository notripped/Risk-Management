"""
QKD Infrastructure Deployment Roadmap Generator

Generates detailed, phased deployment roadmaps for financial institutions
adopting QKD infrastructure. Outputs board-ready reports with:
- Phased implementation timeline
- Cost models and ROI analysis
- Vendor recommendations
- Compliance milestones
- Risk reduction trajectory
- Integration with existing infrastructure
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DeploymentPhase:
    phase_number: int
    name: str
    duration_months: int
    objectives: list
    deliverables: list
    capital_cost_usd: int
    opex_usd_per_year: int
    risk_reduction: float       # Percentage reduction in quantum risk score
    compliance_milestones: list
    dependencies: list
    key_activities: list


@dataclass
class ROIProjection:
    year: int
    cumulative_investment_usd: int
    risk_reduction_percent: float
    avoided_breach_cost_usd: int    # Statistical expected value
    regulatory_fine_avoidance_usd: int
    net_benefit_usd: int
    roi_percent: float


@dataclass
class DeploymentRoadmap:
    institution_name: str
    institution_type: str         # "tier1_bank", "hedge_fund", "exchange", "custodian"
    assessment_date: str
    total_duration_months: int
    phases: list
    total_capital_cost_usd: int
    total_annual_opex_usd: int
    roi_projections: list
    vendor_recommendations: list
    executive_summary: str
    board_presentation_points: list
    quick_wins: list


# Institution type profiles
INSTITUTION_PROFILES = {
    "tier1_bank": {
        "label": "Tier 1 Global Bank",
        "aum_range": "> $1T",
        "regulatory_requirements": ["DORA", "CNSA 2.0", "NIST SP 800-208", "Basel III", "PCI-DSS"],
        "urgency_multiplier": 1.5,
        "typical_nodes": 50,
        "annual_data_volume_tb": 5000,
        "breach_cost_estimate_usd": 500_000_000,
    },
    "hedge_fund": {
        "label": "Hedge Fund ($1B-$50B AUM)",
        "aum_range": "$1B-$50B",
        "regulatory_requirements": ["DORA", "FCA", "SEC"],
        "urgency_multiplier": 1.2,
        "typical_nodes": 5,
        "annual_data_volume_tb": 50,
        "breach_cost_estimate_usd": 50_000_000,
    },
    "exchange": {
        "label": "Stock/Derivatives Exchange",
        "aum_range": "N/A",
        "regulatory_requirements": ["DORA", "IOSCO", "MiFID II", "CFTC"],
        "urgency_multiplier": 1.8,
        "typical_nodes": 20,
        "annual_data_volume_tb": 1000,
        "breach_cost_estimate_usd": 1_000_000_000,
    },
    "custodian": {
        "label": "Custodian Bank",
        "aum_range": "$500B-$5T AUA",
        "regulatory_requirements": ["DORA", "CSDR", "EMIR", "Basel III"],
        "urgency_multiplier": 1.6,
        "typical_nodes": 30,
        "annual_data_volume_tb": 2000,
        "breach_cost_estimate_usd": 200_000_000,
    },
    "boutique_ib": {
        "label": "Boutique Investment Bank",
        "aum_range": "$10B-$500B",
        "regulatory_requirements": ["DORA", "MiFID II", "FCA"],
        "urgency_multiplier": 1.1,
        "typical_nodes": 10,
        "annual_data_volume_tb": 100,
        "breach_cost_estimate_usd": 100_000_000,
    },
}


class RoadmapGenerator:
    """
    Generates QKD infrastructure deployment roadmaps.
    """

    VENDOR_RECOMMENDATIONS = [
        {
            "vendor": "ID Quantique",
            "product": "Clavis XG + Cerberis XG",
            "use_case": "Metro QKD networks, point-to-point fiber links",
            "approx_cost_usd": 120_000,
            "range_km": 100,
            "website": "idquantique.com",
            "notes": "Market leader in financial QKD deployments"
        },
        {
            "vendor": "Toshiba Research",
            "product": "Toshiba Multiplexed QKD",
            "use_case": "High-rate metro networks, co-existence with DWDM",
            "approx_cost_usd": 150_000,
            "range_km": 100,
            "website": "toshiba.eu/quantum",
            "notes": "Highest key rate at metropolitan distances"
        },
        {
            "vendor": "Quantinuum",
            "product": "Network-as-a-Service QKD",
            "use_case": "Long-distance entanglement-based QKD",
            "approx_cost_usd": 500_000,
            "range_km": 50,
            "website": "quantinuum.com",
            "notes": "Best-in-class fidelity; enterprise quantum network service"
        },
        {
            "vendor": "Open Quantum Safe (liboqs)",
            "product": "PQC Software Library",
            "use_case": "TLS/PKI post-quantum migration — software only",
            "approx_cost_usd": 0,
            "range_km": 999999,
            "website": "openquantumsafe.org",
            "notes": "Free, NIST-standardized PQC. Deploy before hardware QKD."
        },
    ]

    def generate(
        self,
        institution_name: str,
        institution_type: str = "hedge_fund",
        current_risk_score: float = 75.0,
        n_offices: int = 3,
        prioritize_pqc_first: bool = True,
    ) -> DeploymentRoadmap:
        """Generate full QKD deployment roadmap"""

        profile = INSTITUTION_PROFILES.get(institution_type, INSTITUTION_PROFILES["hedge_fund"])

        phases = self._build_phases(profile, n_offices, prioritize_pqc_first)

        total_capex = sum(p.capital_cost_usd for p in phases)
        total_opex  = sum(p.opex_usd_per_year for p in phases)
        total_months = sum(p.duration_months for p in phases)

        roi = self._compute_roi(profile, phases, total_capex)

        quick_wins = [
            "Deploy liboqs PQC library — free, zero downtime, immediate quantum protection for TLS",
            "Enable X25519Kyber768 hybrid cipher in all TLS 1.3 endpoints",
            "Perform cryptographic inventory audit — no cost, identifies highest-risk assets",
            "Disable broken cipher suites (TLS_RSA_*, 3DES) — compliance quick win",
        ]

        board_points = [
            f"Q-Day probability before 2038: ~65% — action required NOW due to Harvest-Now-Decrypt-Later threat",
            f"All current {', '.join(profile['regulatory_requirements'][:3])} encrypted data is at retroactive risk",
            f"Estimated breach cost if CRQC deployed: ${profile['breach_cost_estimate_usd']:,.0f}",
            f"Total QKD investment: ${total_capex:,.0f} capex + ${total_opex:,.0f}/yr opex",
            f"ROI positive by year {next((r['year'] for r in roi if r['net_benefit_usd'] > 0), 5)}",
            "Regulatory compliance (DORA, CNSA 2.0) requires PQC migration — financial penalties for non-compliance",
            "First-mover advantage: quantum-safe infrastructure as competitive differentiator to institutional clients",
        ]

        exec_summary = (
            f"{institution_name} ({profile['label']}) requires a {total_months}-month quantum security "
            f"transformation program. The current cryptographic posture carries an estimated "
            f"${total_capex + total_opex * 5:,.0f} exposure over 5 years if action is not taken. "
            f"The proposed roadmap delivers full QKD infrastructure at ${total_capex:,.0f} capital cost "
            f"across {len(phases)} phases, with compliance achieved by Phase 2."
        )

        return DeploymentRoadmap(
            institution_name=institution_name,
            institution_type=profile["label"],
            assessment_date="2026",
            total_duration_months=total_months,
            phases=[self._phase_to_dict(p) for p in phases],
            total_capital_cost_usd=total_capex,
            total_annual_opex_usd=total_opex,
            roi_projections=roi,
            vendor_recommendations=self.VENDOR_RECOMMENDATIONS,
            executive_summary=exec_summary,
            board_presentation_points=board_points,
            quick_wins=quick_wins,
        )

    def _build_phases(self, profile: dict, n_offices: int, pqc_first: bool) -> list:
        """Construct deployment phases"""
        phases = []

        # Phase 1: Foundation (PQC software + crypto audit)
        phases.append(DeploymentPhase(
            phase_number=1,
            name="Foundation — PQC Software Deployment & Crypto Audit",
            duration_months=3,
            objectives=[
                "Complete cryptographic inventory",
                "Deploy NIST PQC algorithms in TLS stack",
                "Disable deprecated cipher suites",
                "Establish quantum security program governance",
            ],
            deliverables=[
                "Cryptographic asset register",
                "TLS stack upgraded with X25519Kyber768 hybrid",
                "Certificate renewal roadmap",
                "Security policy updated for quantum threats",
            ],
            capital_cost_usd=50_000,
            opex_usd_per_year=25_000,
            risk_reduction=25.0,
            compliance_milestones=[
                "NIST SP 800-131A: deprecated cipher removal",
                "DORA Article 9: ICT risk assessment updated",
            ],
            dependencies=[],
            key_activities=[
                "Deploy liboqs across all TLS 1.3 endpoints",
                "Disable TLS 1.0/1.1, 3DES, RC4, export ciphers",
                "Run QuantumVault crypto audit across all systems",
                "Complete HNDL risk assessment",
            ],
        ))

        # Phase 2: Certificate and PKI Migration
        phases.append(DeploymentPhase(
            phase_number=2,
            name="PKI & Certificate Migration to Post-Quantum",
            duration_months=4,
            objectives=[
                "Migrate all certificates to Dilithium3/FALCON-512",
                "Update internal CA to support PQC algorithms",
                "Deploy hybrid certificates for transition compatibility",
            ],
            deliverables=[
                "PQC-capable Certificate Authority",
                "All external certificates migrated",
                "Hybrid certificate deployment for compatibility",
                "Updated code-signing infrastructure",
            ],
            capital_cost_usd=100_000,
            opex_usd_per_year=50_000,
            risk_reduction=25.0,
            compliance_milestones=[
                "CNSA 2.0: certificate algorithms compliant",
                "FIPS 204 (Dilithium): deployed",
                "FIPS 203 (Kyber): deployed in TLS KEM",
            ],
            dependencies=["Phase 1 complete"],
            key_activities=[
                "Stand up PQC-capable internal CA",
                "Migrate external-facing certificates first",
                "Update SWIFT PKI configuration",
                "Deploy Dilithium3 code-signing for trading software",
            ],
        ))

        # Phase 3: QKD Pilot (1-2 key links)
        hw_cost = 150_000 * 2  # Two QKD systems
        phases.append(DeploymentPhase(
            phase_number=3,
            name="QKD Pilot — Primary Links",
            duration_months=6,
            objectives=[
                f"Deploy QKD on 1-2 highest-risk links",
                "Establish QKD Key Management System",
                "Integrate QKD keys with AES session encryption",
                "Validate ETSI QKD 014 API integration",
            ],
            deliverables=[
                "Live QKD link between primary trading systems",
                "ETSI-compliant QKD KMS deployment",
                "Integration with trading system key refresh",
                "Operations runbook for QKD infrastructure",
            ],
            capital_cost_usd=hw_cost + 200_000,   # Hardware + integration
            opex_usd_per_year=100_000,
            risk_reduction=30.0,
            compliance_milestones=[
                "DORA: quantum risk mitigation evidence",
                "ETSI GS QKD 014: compliant deployment",
            ],
            dependencies=["Phase 2 complete"],
            key_activities=[
                "Procure and install QKD hardware (ID Quantique/Toshiba)",
                "Deploy QKD KMS (ETSI 014 compliant)",
                "Integrate with AES key refresh for trading connections",
                "Security operations training for QKD infrastructure",
            ],
        ))

        # Phase 4: Full Network QKD Deployment
        additional_nodes = max(0, n_offices - 2)
        phases.append(DeploymentPhase(
            phase_number=4,
            name="Full QKD Network Deployment",
            duration_months=9,
            objectives=[
                f"Extend QKD to all {n_offices} office/datacenter nodes",
                "Trusted relay deployment for long-distance links",
                "Full integration with SWIFT and settlement systems",
                "Satellite QKD assessment for cross-border links",
            ],
            deliverables=[
                f"QKD network covering all {n_offices} primary locations",
                "Trusted relay nodes physically secured",
                "SWIFT message encryption via QKD keys",
                "Quantum security operations dashboard",
            ],
            capital_cost_usd=150_000 * additional_nodes + 500_000,
            opex_usd_per_year=200_000,
            risk_reduction=20.0,
            compliance_milestones=[
                "Full CNSA 2.0 compliance",
                "DORA quantum resilience framework complete",
                "Regulatory evidence package for examiners",
            ],
            dependencies=["Phase 3 complete"],
            key_activities=[
                "Roll out QKD to remaining office locations",
                "Deploy trusted repeater nodes where needed",
                "Integrate QKD keys with SWIFT messaging",
                "Begin satellite QKD evaluation for cross-border links",
            ],
        ))

        return phases

    def _compute_roi(self, profile: dict, phases: list, total_capex: int) -> list:
        breach_cost = profile["breach_cost_estimate_usd"]
        annual_prob_breach = 0.02     # 2% annual probability of breach (industry estimate)
        expected_annual_breach_cost = breach_cost * annual_prob_breach

        projections = []
        cumulative_investment = 0
        risk_reduction = 0

        for year in range(1, 7):
            # Investment in this year
            year_investment = sum(
                p.capital_cost_usd for p in phases
                if (p.phase_number - 1) // 2 + 1 == year
            ) + sum(
                p.opex_usd_per_year for p in phases
                if (p.phase_number - 1) // 2 + 1 <= year
            )

            cumulative_investment += year_investment

            # Risk reduction accumulates as phases complete
            phases_done = min(year * 1.5, len(phases))
            risk_reduction = sum(p.risk_reduction for p in phases[:int(phases_done)])
            risk_reduction = min(risk_reduction, 95.0)

            avoided_breach = int(expected_annual_breach_cost * (risk_reduction / 100))
            reg_avoidance  = int(10_000_000 * (risk_reduction / 100))  # Regulatory fine avoidance
            benefit        = avoided_breach + reg_avoidance

            net = benefit * year - cumulative_investment
            roi  = (net / cumulative_investment * 100) if cumulative_investment > 0 else 0

            projections.append({
                "year": 2026 + year,
                "cumulative_investment_usd": cumulative_investment,
                "risk_reduction_percent": round(risk_reduction, 1),
                "avoided_breach_cost_usd": avoided_breach,
                "regulatory_fine_avoidance_usd": reg_avoidance,
                "net_benefit_usd": net,
                "roi_percent": round(roi, 1),
            })

        return projections

    def _phase_to_dict(self, p: DeploymentPhase) -> dict:
        return {
            "phase": p.phase_number,
            "name": p.name,
            "duration_months": p.duration_months,
            "objectives": p.objectives,
            "deliverables": p.deliverables,
            "capital_cost_usd": p.capital_cost_usd,
            "opex_usd_per_year": p.opex_usd_per_year,
            "risk_reduction_pct": p.risk_reduction,
            "compliance_milestones": p.compliance_milestones,
            "dependencies": p.dependencies,
            "key_activities": p.key_activities,
        }
