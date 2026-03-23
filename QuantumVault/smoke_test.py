from core.network.topology import QKDNetworkModeler
from core.network.repeater import TrustedRelayDesigner

offices = [
    {"name": "London HQ",    "city": "London",    "lat": 51.5074, "lon": -0.1278},
    {"name": "Frankfurt DC", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"name": "New York",     "city": "New York",  "lat": 40.7128, "lon": -74.006},
]
modeler  = QKDNetworkModeler()
topology = modeler.create_financial_topology("TestBank", offices, "ring")
result   = modeler.analyze_topology(topology)
print(f"Topology OK: viable={result.viable_links}/{result.total_links} "
      f"cost=${result.total_infrastructure_cost_usd:,.0f} "
      f"resilience={result.network_resilience_score:.0f}")
print(f"link keys: {list(result.link_analysis[0].keys())}")

relay = TrustedRelayDesigner()
chain = relay.design_chain(total_distance_km=500.0)
print(f"Repeater OK: segments={len(chain.segments)}")

# Test full suite
import subprocess
r = subprocess.run(["python", "-m", "pytest", "tests/", "-q"], capture_output=True, text=True)
print(r.stdout)
if r.returncode != 0:
    print("STDERR:", r.stderr)
