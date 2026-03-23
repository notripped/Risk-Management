"""
Quantum Repeater and Trusted Relay Node Modeling

For QKD distances beyond ~100-150km, repeaters are required.
Two approaches:
1. Trusted relay nodes (classical, require physical security)
2. Quantum repeaters (entanglement-based, device-independent)

Current SOTA:
- Trusted relays: Deployed commercially (China's 2000km+ QKD backbone, UK NQCC)
- Quantum repeaters: Lab demonstrations at <100km, not commercially deployed
- Expected quantum repeater deployment: ~2030-2035

Financial application:
- City-to-city sovereign data links
- Cross-border trading infrastructure
- Submarine cable replacement for APAC/EU links
"""

import numpy as np
from dataclasses import dataclass
from typing import Optional


@dataclass
class RepeaterNode:
    node_id: str
    node_type: str              # "trusted_relay" or "quantum_repeater"
    position_km: float          # Position along the link
    buffer_key_bits: int        # Key storage capacity
    physical_security_level: str  # "standard", "high", "scif"
    operational_cost_usd_per_year: int
    mtbf_hours: float           # Mean time between failures


@dataclass
class RepeaterChainResult:
    total_distance_km: float
    n_segments: int
    repeater_nodes: list
    effective_key_rate_bps: float
    chain_security_level: str   # "trusted" or "device_independent"
    single_point_of_failure: bool
    total_capital_cost_usd: int
    annual_opex_usd: int
    availability_percent: float
    max_segment_distance_km: float


class TrustedRelayDesigner:
    """
    Design optimal trusted relay chains for long-distance QKD links.
    """

    NODE_CAPITAL_COST   = 150_000    # Physical secure node build-out
    NODE_HW_COST        = 200_000    # QKD hardware per node
    ANNUAL_OPEX_PER_NODE = 80_000    # Operations, monitoring, security

    def design_chain(
        self,
        total_distance_km: float,
        target_key_rate_bps: float = 10_000,
        max_segment_km: float      = 80.0,    # Max single-hop QKD range
        hardware_key: str          = "toshiba_qkd",
    ) -> RepeaterChainResult:
        """
        Design an optimal trusted relay chain for a given distance.
        """
        from core.qkd.channel import QKDChannelAnalyzer, ChannelMedium

        if total_distance_km <= max_segment_km:
            # Direct QKD link possible
            analyzer = QKDChannelAnalyzer()
            result = analyzer.analyze(distance_km=total_distance_km)
            return RepeaterChainResult(
                total_distance_km=total_distance_km,
                n_segments=1,
                repeater_nodes=[],
                effective_key_rate_bps=result.secure_key_rate_bps,
                chain_security_level="trusted",
                single_point_of_failure=False,
                total_capital_cost_usd=self.NODE_HW_COST * 2,
                annual_opex_usd=self.ANNUAL_OPEX_PER_NODE * 2,
                availability_percent=99.9,
                max_segment_distance_km=total_distance_km,
            )

        # Calculate number of segments needed
        n_segments    = int(np.ceil(total_distance_km / max_segment_km))
        segment_len   = total_distance_km / n_segments
        n_relay_nodes = n_segments - 1

        # Analyze each segment
        analyzer = QKDChannelAnalyzer()
        segment_result = analyzer.analyze(distance_km=segment_len)
        segment_rate   = segment_result.secure_key_rate_bps

        # Chain bottleneck rate = min segment rate
        effective_rate = segment_rate if segment_result.viable else 0.0

        # Build relay node specs
        relay_nodes = [
            RepeaterNode(
                node_id=f"relay_{i+1}",
                node_type="trusted_relay",
                position_km=(i + 1) * segment_len,
                buffer_key_bits=1_000_000,    # 1Mbit key buffer
                physical_security_level="high",
                operational_cost_usd_per_year=self.ANNUAL_OPEX_PER_NODE,
                mtbf_hours=8760,              # 1 year MTBF
            )
            for i in range(n_relay_nodes)
        ]

        # Cost
        total_nodes   = n_relay_nodes + 2   # Include Alice and Bob endpoints
        capital_cost  = total_nodes * (self.NODE_CAPITAL_COST + self.NODE_HW_COST)
        annual_opex   = total_nodes * self.ANNUAL_OPEX_PER_NODE

        # Availability (series chain — each node must be up)
        node_availability = 0.999   # 99.9% per node
        chain_availability = node_availability ** total_nodes * 100

        return RepeaterChainResult(
            total_distance_km=total_distance_km,
            n_segments=n_segments,
            repeater_nodes=[
                {
                    "node_id": r.node_id,
                    "position_km": r.position_km,
                    "type": r.node_type,
                    "security_level": r.physical_security_level,
                    "annual_opex_usd": r.operational_cost_usd_per_year,
                }
                for r in relay_nodes
            ],
            effective_key_rate_bps=round(effective_rate, 2),
            chain_security_level="trusted",
            single_point_of_failure=True,   # Trusted relay chains have this weakness
            total_capital_cost_usd=capital_cost,
            annual_opex_usd=annual_opex,
            availability_percent=round(chain_availability, 3),
            max_segment_distance_km=round(segment_len, 1),
        )

    def compare_long_distance_options(self, distance_km: float) -> list:
        """Compare different approaches for a long-distance QKD link"""
        options = []

        # Option 1: Trusted relay chain
        chain = self.design_chain(distance_km)
        options.append({
            "approach": "Trusted Relay Chain",
            "feasible_today": True,
            "key_rate_bps": chain.effective_key_rate_bps,
            "n_intermediate_nodes": chain.n_segments - 1,
            "capital_cost_usd": chain.total_capital_cost_usd,
            "annual_opex_usd": chain.annual_opex_usd,
            "security_model": "Classical security at relay nodes — requires physical security",
            "availability_percent": chain.availability_percent,
            "deployment_timeline": "6-18 months",
        })

        # Option 2: Satellite QKD
        if distance_km > 200:
            options.append({
                "approach": "Satellite QKD (LEO)",
                "feasible_today": True,
                "key_rate_bps": 5_000,     # ~5 kbps for typical LEO pass
                "n_intermediate_nodes": 0,
                "capital_cost_usd": 50_000_000,   # Satellite + ground station
                "annual_opex_usd": 2_000_000,
                "security_model": "End-to-end quantum security — no trusted relay needed",
                "availability_percent": 98.0,
                "deployment_timeline": "2-5 years (commercial service)",
                "vendors": ["SES, SpaceQuest, QEYSSat"]
            })

        # Option 3: Quantum repeater (future)
        options.append({
            "approach": "Quantum Repeater (Entanglement-Based)",
            "feasible_today": False,
            "key_rate_bps": 100_000,  # Projected when available
            "n_intermediate_nodes": int(distance_km / 200),
            "capital_cost_usd": 10_000_000,   # Estimated
            "annual_opex_usd": 1_000_000,
            "security_model": "Device-independent — unconditionally secure",
            "availability_percent": 99.0,
            "deployment_timeline": "2030-2035 (research stage)",
            "technology_readiness": "TRL 3-4 (laboratory demonstration)",
        })

        return options
