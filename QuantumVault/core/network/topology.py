"""
QKD Network Topology Modeler for Financial Infrastructure

Models QKD network overlay topology for financial institutions:
- Point-to-point QKD links (office-to-datacenter)
- Mesh and ring topologies (trading floor interconnects)
- Trusted node networks (metropolitan QKD rings)
- Satellite QKD for cross-border links

Provides:
- Key rate estimation across the full network
- Bottleneck analysis
- Trusted node identification and elimination strategy
- Cost modeling for QKD infrastructure deployment
- Network resilience analysis
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class QKDNode:
    node_id: str
    name: str
    location: str
    node_type: str          # "alice", "bob", "trusted_relay", "quantum_repeater"
    latitude: float
    longitude: float
    hardware_profile: str   # Reference to HARDWARE_PROFILES key
    is_trusted: bool        # Trusted nodes must be physically secured
    security_clearance: str # "standard", "high", "critical"


@dataclass
class QKDLink:
    link_id: str
    node_a: str
    node_b: str
    medium: str             # "fiber", "free_space"
    distance_km: float
    fiber_loss_db_per_km: float = 0.20
    additional_loss_db: float   = 3.0   # Connectors, splices
    deployed: bool              = False
    estimated_cost_usd: int     = 0
    secure_key_rate_bps: float  = 0.0   # Computed by analyzer


@dataclass
class NetworkTopology:
    topology_id: str
    institution: str
    nodes: list         # List of QKDNode
    links: list         # List of QKDLink
    topology_type: str  # "star", "ring", "mesh", "hybrid"


@dataclass
class NetworkAnalysisResult:
    topology: NetworkTopology
    total_links: int
    viable_links: int
    bottleneck_links: list
    min_key_rate_bps: float
    avg_key_rate_bps: float
    max_key_rate_bps: float
    trusted_nodes_required: int
    total_infrastructure_cost_usd: int
    annual_key_material_bits: float
    network_resilience_score: float     # 0-100
    recommendations: list
    link_analysis: list


class QKDNetworkModeler:
    """
    Models QKD network topologies over financial institution infrastructure.
    """

    # Cost per km fiber deployment (trenching + fiber)
    FIBER_COST_PER_KM_USD = 50_000
    # QKD hardware cost per node pair
    QKD_NODE_PAIR_COST_USD = 200_000

    def analyze_topology(self, topology: NetworkTopology) -> NetworkAnalysisResult:
        """Full analysis of a QKD network topology"""
        from core.qkd.channel import QKDChannelAnalyzer, ChannelMedium

        analyzer = QKDChannelAnalyzer()
        link_results = []
        viable_count = 0
        bottlenecks  = []
        costs        = []
        key_rates    = []

        for link in topology.links:
            medium = ChannelMedium.FIBER_SMF28 if link.medium == "fiber" else ChannelMedium.FREE_SPACE

            result = analyzer.analyze(
                hardware_key="toshiba_qkd",
                medium=medium,
                distance_km=link.distance_km,
                additional_loss_db=link.additional_loss_db,
            )

            link.secure_key_rate_bps = result.secure_key_rate_bps

            if result.viable:
                viable_count += 1
                key_rates.append(result.secure_key_rate_bps)
            else:
                bottlenecks.append(link.link_id)

            # Cost estimate
            fiber_cost = int(link.distance_km * self.FIBER_COST_PER_KM_USD) if link.medium == "fiber" else 0
            hw_cost    = self.QKD_NODE_PAIR_COST_USD
            total_link_cost = fiber_cost + hw_cost
            link.estimated_cost_usd = total_link_cost
            costs.append(total_link_cost)

            link_results.append({
                "link_id":          link.link_id,
                "node_a":           link.node_a,
                "node_b":           link.node_b,
                "distance_km":      link.distance_km,
                "viable":           result.viable,
                "secure_key_rate_bps": result.secure_key_rate_bps,
                "qber":             result.qber,
                "channel_loss_db":  result.channel_loss_db,
                "total_loss_db":    result.total_loss_db,
                "estimated_cost_usd": total_link_cost,
                "notes":            result.notes,
            })

        # Trusted nodes (security requirement for long-distance topologies)
        trusted_required = sum(1 for n in topology.nodes if n.is_trusted)

        # Network resilience (% links with redundant paths)
        resilience = self._compute_resilience(topology, viable_count)

        # Annual key material
        annual_key_bits = sum(key_rates) * 3600 * 24 * 365 if key_rates else 0

        # Recommendations
        recommendations = self._generate_recommendations(
            topology, bottlenecks, viable_count, key_rates
        )

        return NetworkAnalysisResult(
            topology=topology,
            total_links=len(topology.links),
            viable_links=viable_count,
            bottleneck_links=bottlenecks,
            min_key_rate_bps=min(key_rates) if key_rates else 0,
            avg_key_rate_bps=sum(key_rates) / len(key_rates) if key_rates else 0,
            max_key_rate_bps=max(key_rates) if key_rates else 0,
            trusted_nodes_required=trusted_required,
            total_infrastructure_cost_usd=sum(costs),
            annual_key_material_bits=annual_key_bits,
            network_resilience_score=round(resilience, 1),
            recommendations=recommendations,
            link_analysis=link_results,
        )

    def create_financial_topology(
        self,
        institution: str,
        offices: list,      # List of {"name": str, "city": str, "lat": float, "lon": float}
        topology_type: str = "ring"
    ) -> NetworkTopology:
        """Auto-generate a QKD topology for a financial institution"""

        nodes = [
            QKDNode(
                node_id=f"node_{i}",
                name=office["name"],
                location=office["city"],
                node_type="alice" if i == 0 else "bob",
                latitude=office.get("lat", 51.5 + i * 0.1),
                longitude=office.get("lon", -0.1 + i * 0.1),
                hardware_profile="toshiba_qkd",
                is_trusted=(topology_type == "ring" and i > 0 and i < len(offices) - 1),
                security_clearance="high"
            )
            for i, office in enumerate(offices)
        ]

        links = []
        if topology_type == "ring":
            for i in range(len(nodes)):
                j = (i + 1) % len(nodes)
                dist = self._haversine(
                    nodes[i].latitude, nodes[i].longitude,
                    nodes[j].latitude, nodes[j].longitude
                )
                links.append(QKDLink(
                    link_id=f"link_{i}_{j}",
                    node_a=nodes[i].node_id,
                    node_b=nodes[j].node_id,
                    medium="fiber",
                    distance_km=max(1.0, dist),
                ))
        elif topology_type == "star":
            hub = nodes[0]
            for i in range(1, len(nodes)):
                dist = self._haversine(hub.latitude, hub.longitude, nodes[i].latitude, nodes[i].longitude)
                links.append(QKDLink(
                    link_id=f"link_0_{i}",
                    node_a=hub.node_id,
                    node_b=nodes[i].node_id,
                    medium="fiber",
                    distance_km=max(1.0, dist),
                ))
        elif topology_type == "mesh":
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    dist = self._haversine(nodes[i].latitude, nodes[i].longitude, nodes[j].latitude, nodes[j].longitude)
                    links.append(QKDLink(
                        link_id=f"link_{i}_{j}",
                        node_a=nodes[i].node_id,
                        node_b=nodes[j].node_id,
                        medium="fiber",
                        distance_km=max(1.0, dist),
                    ))

        return NetworkTopology(
            topology_id=f"{institution.lower().replace(' ', '_')}_qkd",
            institution=institution,
            nodes=nodes,
            links=links,
            topology_type=topology_type,
        )

    def _haversine(self, lat1, lon1, lat2, lon2) -> float:
        """Compute great-circle distance in km"""
        R = 6371.0
        phi1, phi2 = np.radians(lat1), np.radians(lat2)
        dphi = np.radians(lat2 - lat1)
        dlam = np.radians(lon2 - lon1)
        a = np.sin(dphi / 2) ** 2 + np.cos(phi1) * np.cos(phi2) * np.sin(dlam / 2) ** 2
        return R * 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))

    def _compute_resilience(self, topology: NetworkTopology, viable: int) -> float:
        if len(topology.links) == 0:
            return 0.0
        base = (viable / len(topology.links)) * 60
        redundancy_bonus = 20 if topology.topology_type in ["ring", "mesh"] else 0
        trusted_penalty  = -10 if any(n.is_trusted for n in topology.nodes) else 0
        return min(100.0, base + redundancy_bonus + trusted_penalty)

    def _generate_recommendations(
        self, topology, bottlenecks, viable, key_rates
    ) -> list:
        recs = []
        if bottlenecks:
            recs.append(f"Install trusted repeater nodes on {len(bottlenecks)} links exceeding QKD range")
        if topology.topology_type == "star":
            recs.append("Consider ring topology for single-point-of-failure elimination")
        if any(n.is_trusted for n in topology.nodes):
            recs.append("Physically secure all trusted relay nodes (tamper-evident enclosures, 24/7 monitoring)")
        if key_rates and min(key_rates) < 1000:
            recs.append("Consider twin-field QKD protocol to extend effective range on low-rate links")
        recs.append("Implement QKD key management system (ETSI GS QKD 014 compliant) to consume key material")
        return recs
