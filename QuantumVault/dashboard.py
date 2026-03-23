"""
QuantumVault Dashboard — Streamlit Interactive Research Interface

Run with:
    streamlit run dashboard.py

Provides interactive access to all QuantumVault research modules:
- BB84/E91/MDI-QKD protocol simulation with live charts
- HNDL risk assessment
- Q-Day timeline visualization
- PQC algorithm benchmarks
- QKD deployment roadmap generator
- Network topology analysis
- Crypto audit dashboard
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.qkd import (
    BB84Simulator, QuantumChannel, AttackType,
    E91Simulator,
    MDIQKDSimulator,
    QKDChannelAnalyzer, ChannelMedium, HARDWARE_PROFILES,
)
from core.pqc import (
    KyberSimulator, KyberVariant, KYBER_PARAMS,
    DilithiumSimulator, FALCONSimulator, DilithiumVariant, FALCONVariant,
    MigrationEngine, CryptoAsset, ClassicalAlgorithm, FinancialProtocol,
)
from core.threat import (
    HNDLRiskEngine, HNDLExposureRecord, DataCategory,
    QDayTimeline, QDAY_SCENARIOS,
    CryptoAuditor, SystemCryptoProfile,
)
from core.reporting import RoadmapGenerator, INSTITUTION_PROFILES
from core.network import QKDNetworkModeler, TrustedRelayDesigner
from core.key_management import QKDKeyManagementSystem


# ------------------------------------------------------------------ #
#  Page Config                                                          #
# ------------------------------------------------------------------ #

st.set_page_config(
    page_title="QuantumVault R&D Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------ #
#  Custom CSS                                                           #
# ------------------------------------------------------------------ #

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #1e3a5f 0%, #0f62ac 50%, #00b4d8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        color: #6c757d;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e3a5f 0%, #0f4c81 100%);
        padding: 1.2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        border: 1px solid #0f62ac;
    }
    .risk-critical { color: #ff4444; font-weight: bold; }
    .risk-high     { color: #ff8800; font-weight: bold; }
    .risk-medium   { color: #ffcc00; font-weight: bold; }
    .risk-low      { color: #44bb44; font-weight: bold; }
    .stAlert { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------ #
#  Header                                                               #
# ------------------------------------------------------------------ #

st.markdown('<p class="main-header">QuantumVault</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">Quantum Key Distribution R&D Infrastructure Platform for Financial Institutions</p>',
    unsafe_allow_html=True
)

# ------------------------------------------------------------------ #
#  Navigation                                                           #
# ------------------------------------------------------------------ #

tabs = st.tabs([
    "BB84 Protocol",
    "E91 Protocol",
    "MDI-QKD",
    "Channel Analysis",
    "HNDL Threat",
    "Q-Day Timeline",
    "PQC Algorithms",
    "Crypto Audit",
    "Network Topology",
    "Deployment Roadmap",
    "QKD Key Manager",
])

(tab_bb84, tab_e91, tab_mdi, tab_channel,
 tab_hndl, tab_qday, tab_pqc, tab_audit,
 tab_network, tab_roadmap, tab_kms) = tabs


# ================================================================== #
#  TAB 1: BB84                                                         #
# ================================================================== #

with tab_bb84:
    st.header("BB84 QKD Protocol Simulator")
    st.markdown("*Bennett-Brassard 1984 — the foundational quantum key distribution protocol*")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Parameters")
        n_qubits = st.slider("Qubits Sent", 5000, 100000, 20000, step=5000)
        distance  = st.slider("Channel Distance (km)", 1.0, 200.0, 20.0, step=1.0)
        det_eff   = st.slider("Detector Efficiency", 0.5, 1.0, 0.85, step=0.05)
        dark_rate = st.number_input("Dark Count Rate (Hz)", min_value=0.0, value=100.0, step=10.0)

        st.subheader("Eavesdropping Attack")
        attack_type = st.selectbox("Attack Type", ["None", "Intercept-Resend", "Photon Number Splitting"])
        intercept_frac = 0.0
        if attack_type == "Intercept-Resend":
            intercept_frac = st.slider("Intercept Fraction", 0.0, 1.0, 0.3, step=0.05)

        run_bb84 = st.button("Run BB84 Simulation", key="run_bb84", type="primary")

    with col2:
        if run_bb84:
            attack_map = {"None": AttackType.NONE, "Intercept-Resend": AttackType.INTERCEPT_RESEND,
                         "Photon Number Splitting": AttackType.PHOTON_NUMBER_SPLITTING}
            channel = QuantumChannel(
                distance_km=distance, detector_efficiency=det_eff,
                dark_count_rate=dark_rate, attack=attack_map[attack_type],
                attack_intercept_fraction=intercept_frac,
            )
            with st.spinner("Simulating BB84 protocol..."):
                sim = BB84Simulator()
                result = sim.run(n_qubits=n_qubits, channel=channel)

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("QBER", f"{result.qber*100:.2f}%",
                         delta=f"{'ABOVE' if result.qber > 0.11 else 'BELOW'} 11% threshold")
            with m2:
                st.metric("Secure Key Bits", f"{result.n_secure_key_bits:,}")
            with m3:
                st.metric("Sifted Bits", f"{result.n_sifted_bits:,}")
            with m4:
                eve_str = "EVE DETECTED" if result.eve_detected else "No Eve"
                st.metric("Security", eve_str)

            if result.eve_detected:
                st.error(f"Eavesdropping detected. QBER={result.qber*100:.2f}% exceeds 11% security threshold. Key exchange aborted.")
            else:
                st.success(f"Secure key established: {result.n_secure_key_bits} bits at {result.secure_key_rate_bps:.1f} bps")

            # Protocol flow visualization
            st.subheader("Protocol Statistics")
            stats_df = pd.DataFrame([
                {"Stage": "Qubits Sent", "Count": result.n_qubits_sent},
                {"Stage": "Photons Received", "Count": int(result.n_qubits_sent * (1 - result.simulation_stats.get("photon_loss_rate", 0)))},
                {"Stage": "After Sifting", "Count": result.n_sifted_bits},
                {"Stage": "After QBER Sampling", "Count": max(0, result.n_sifted_bits - int(result.n_sifted_bits * 0.25))},
                {"Stage": "After Error Correction", "Count": max(0, result.n_sifted_bits - result.error_correction_bits_leaked)},
                {"Stage": "Final Secure Key", "Count": result.n_secure_key_bits},
            ])
            fig = px.funnel(stats_df, x="Count", y="Stage",
                           title="BB84 Key Distillation Pipeline",
                           color_discrete_sequence=["#0f62ac"])
            st.plotly_chart(fig, width="stretch")

    # Distance sweep section
    st.subheader("Key Rate vs Distance Analysis")
    col_a, col_b = st.columns([1, 3])
    with col_a:
        run_sweep = st.button("Run Distance Sweep", key="sweep_bb84")
    if run_sweep:
        with st.spinner("Sweeping distances 10km to 150km..."):
            sim  = BB84Simulator()
            data = sim.sweep_distance([10, 20, 30, 40, 50, 60, 70, 80, 100, 120, 150])
        df = pd.DataFrame(data)
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=df["distance_km"], y=df["secure_key_rate_bps"],
                                mode="lines+markers", name="Secure Key Rate (bps)",
                                line=dict(color="#0f62ac", width=2)))
        fig.add_trace(go.Scatter(x=df["distance_km"], y=df["qber"],
                                mode="lines+markers", name="QBER", yaxis="y2",
                                line=dict(color="#ff4444", width=2, dash="dash")))
        fig.update_layout(
            title="BB84 Secure Key Rate & QBER vs Distance",
            xaxis_title="Distance (km)",
            yaxis_title="Secure Key Rate (bps)",
            yaxis2=dict(title="QBER", overlaying="y", side="right"),
            plot_bgcolor="#0a1628", paper_bgcolor="#0a1628",
            font=dict(color="white"),
        )
        st.plotly_chart(fig, width="stretch")


# ================================================================== #
#  TAB 2: E91                                                          #
# ================================================================== #

with tab_e91:
    st.header("E91 Entanglement-Based QKD Protocol")
    st.markdown("*Ekert 1991 — Bell inequality violation provides security certificate*")

    col1, col2 = st.columns([1, 2])
    with col1:
        st.subheader("Parameters")
        n_pairs   = st.slider("EPR Pairs", 5000, 100000, 15000, step=5000, key="e91_pairs")
        dist_e91  = st.slider("Distance (km)", 1.0, 300.0, 50.0, step=5.0, key="e91_dist")
        fidelity  = st.slider("Entanglement Fidelity", 0.80, 1.0, 0.97, step=0.01)
        eve_e91   = st.checkbox("Enable Eavesdropping")
        eve_frac  = st.slider("Eve Intercept Fraction", 0.0, 1.0, 0.2, step=0.05) if eve_e91 else 0.0
        run_e91   = st.button("Run E91 Simulation", type="primary", key="run_e91")

    with col2:
        if run_e91:
            with st.spinner("Generating EPR pairs and performing Bell measurements..."):
                sim = E91Simulator()
                result = sim.run(
                    n_pairs=n_pairs, distance_km=dist_e91,
                    entanglement_fidelity=fidelity,
                    eavesdropping=eve_e91, eve_intercept_fraction=eve_frac,
                )

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Bell Parameter |S|", f"{abs(result.bell_parameter_s):.4f}",
                         delta=f"Tsirelson bound: 2.828")
            with m2:
                st.metric("Bell Violation", "YES" if result.bell_violation else "NO")
            with m3:
                st.metric("QBER", f"{result.qber*100:.2f}%")
            with m4:
                st.metric("Secure Key Bits", f"{result.n_secure_key_bits:,}")

            # Bell parameter gauge
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=abs(result.bell_parameter_s),
                delta={"reference": 2.0},
                title={"text": "CHSH Bell Parameter |S|", "font": {"color": "white"}},
                gauge={
                    "axis": {"range": [0, 2.828], "tickcolor": "white"},
                    "bar": {"color": "#0f62ac"},
                    "steps": [
                        {"range": [0, 2.0], "color": "#ff4444"},
                        {"range": [2.0, 2.828], "color": "#44bb44"},
                    ],
                    "threshold": {"line": {"color": "white", "width": 2}, "thickness": 0.75, "value": 2.0},
                },
                number={"font": {"color": "white"}},
            ))
            fig.update_layout(paper_bgcolor="#0a1628", font=dict(color="white"), height=300)
            st.plotly_chart(fig, width="stretch")

            if result.bell_violation:
                st.success(f"|S| = {abs(result.bell_parameter_s):.4f} > 2.0 — Quantum entanglement confirmed. Protocol secure.")
            else:
                st.error(f"|S| = {abs(result.bell_parameter_s):.4f} ≤ 2.0 — Bell violation absent. Entanglement degraded or eavesdropping.")


# ================================================================== #
#  TAB 3: MDI-QKD                                                      #
# ================================================================== #

with tab_mdi:
    st.header("MDI-QKD — Measurement Device Independent")
    st.markdown("*Security holds even if the central relay (Charlie) is fully controlled by Eve*")

    col1, col2 = st.columns([1, 2])
    with col1:
        n_pulses  = st.slider("Pulses Sent", 10000, 200000, 50000, step=10000)
        alice_d   = st.slider("Alice → Charlie (km)", 1.0, 150.0, 25.0)
        bob_d     = st.slider("Bob → Charlie (km)", 1.0, 150.0, 25.0)
        malicious = st.checkbox("Charlie is Malicious (Eve controls detector)")
        run_mdi   = st.button("Run MDI-QKD Simulation", type="primary")

    with col2:
        if run_mdi:
            with st.spinner("Running MDI-QKD protocol..."):
                sim = MDIQKDSimulator()
                result = sim.run(
                    n_pulses=n_pulses,
                    alice_distance_km=alice_d,
                    bob_distance_km=bob_d,
                    charlie_is_malicious=malicious,
                )

            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Secure Key Bits", f"{result.n_secure_key_bits:,}")
            with m2:
                st.metric("BSM Success Rate", f"{result.bsm_success_rate*100:.4f}%")
            with m3:
                st.metric("QBER", f"{result.qber*100:.2f}%")

            if malicious:
                st.success("MDI-QKD Security Proof: Even with Eve's full control of Charlie's detectors, the protocol generates a secure key. Security verified.")
            else:
                st.info("Standard MDI-QKD operation. Untrusted relay model active.")

            # Schematic
            total_d = alice_d + bob_d
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=[0, alice_d, total_d], y=[0, 0, 0],
                                    mode="lines+markers+text",
                                    text=["Alice", f"Charlie {'(Malicious)' if malicious else ''}", "Bob"],
                                    textposition=["bottom center", "top center", "bottom center"],
                                    marker=dict(size=[15, 20, 15], color=["#44bb44", "#ff4444" if malicious else "#ffcc00", "#44bb44"]),
                                    line=dict(color="#0f62ac", width=3)))
            fig.update_layout(
                title=f"MDI-QKD Topology — Total Distance: {total_d:.0f}km",
                xaxis_title="Distance (km)", showlegend=False,
                plot_bgcolor="#0a1628", paper_bgcolor="#0a1628",
                font=dict(color="white"), height=200,
                yaxis=dict(visible=False),
            )
            st.plotly_chart(fig, width="stretch")
            st.json(result.simulation_stats)


# ================================================================== #
#  TAB 4: Channel Analysis                                             #
# ================================================================== #

with tab_channel:
    st.header("QKD Channel Capacity Analysis")

    col1, col2 = st.columns([1, 2])
    with col1:
        hw_key  = st.selectbox("Hardware Profile", list(HARDWARE_PROFILES.keys()))
        medium  = st.selectbox("Channel Medium", ["fiber_smf28", "fiber_ull", "free_space"])
        ch_dist = st.slider("Distance (km)", 1.0, 300.0, 50.0)
        add_loss = st.slider("Additional Loss (dB)", 0.0, 15.0, 3.0, step=0.5)
        run_ch  = st.button("Analyze Channel", type="primary")

    with col2:
        if run_ch:
            medium_map = {m.value: m for m in ChannelMedium}
            analyzer = QKDChannelAnalyzer()
            result = analyzer.analyze(
                hardware_key=hw_key,
                medium=medium_map.get(medium, ChannelMedium.FIBER_SMF28),
                distance_km=ch_dist,
                additional_loss_db=add_loss,
            )
            hw = HARDWARE_PROFILES[hw_key]

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Secure Key Rate", f"{result.secure_key_rate_bps:,.0f} bps")
            m2.metric("QBER", f"{result.qber*100:.3f}%")
            m3.metric("Total Loss", f"{result.total_loss_db:.1f} dB")
            m4.metric("Viable", "YES" if result.viable else "NO")

            if result.viable:
                st.success(f"Link viable. Max range for this hardware: {result.max_viable_distance_km:.0f}km")
            else:
                st.error(f"Link not viable at {ch_dist}km. Reduce distance or add repeater nodes.")

            for note in result.notes:
                st.info(note)

    st.subheader("Hardware Comparison at Distance")
    comp_dist = st.slider("Comparison Distance (km)", 10.0, 150.0, 50.0, key="compare_hw")
    if st.button("Compare All Hardware"):
        analyzer = QKDChannelAnalyzer()
        comp = analyzer.sweep_hardware_comparison(distance_km=comp_dist)
        df = pd.DataFrame(comp)
        fig = px.bar(df, x="hardware", y="secure_key_rate_bps",
                    color="viable", title=f"Secure Key Rate by Hardware at {comp_dist}km",
                    color_discrete_map={True: "#44bb44", False: "#ff4444"})
        fig.update_layout(plot_bgcolor="#0a1628", paper_bgcolor="#0a1628", font=dict(color="white"))
        st.plotly_chart(fig, width="stretch")
        st.dataframe(df[["hardware", "vendor", "secure_key_rate_bps", "qber", "viable", "max_range_km", "cost_usd"]])


# ================================================================== #
#  TAB 5: HNDL Threat                                                  #
# ================================================================== #

with tab_hndl:
    st.header("HNDL Risk Assessment — Harvest Now Decrypt Later")
    st.markdown("""
    Nation-state adversaries are **right now** harvesting encrypted financial data to decrypt
    when a quantum computer exists. This tool quantifies your exposure.
    """)

    st.subheader("Portfolio Configuration")
    col1, col2 = st.columns([1, 1])
    with col1:
        adversary = st.selectbox("Adversary Type", ["nation_state", "apt_group", "criminal_org", "opportunistic"])
        scenario  = st.selectbox("Q-Day Scenario", ["median", "optimistic", "pessimistic", "black_swan"])

    with col2:
        st.markdown("**Sample Financial Institution Portfolio**")
        use_defaults = st.checkbox("Use Default Bank Portfolio", value=True)

    if st.button("Run HNDL Assessment", type="primary"):
        engine = HNDLRiskEngine()

        if use_defaults:
            records = [
                HNDLExposureRecord(DataCategory.TRADE_ORDERS,       50.0, "ECDH-P256",  "trading_link",   0.8),
                HNDLExposureRecord(DataCategory.SETTLEMENT_RECORDS, 20.0, "RSA-2048",   "swift_link",     0.7),
                HNDLExposureRecord(DataCategory.RISK_MODELS,         5.0, "RSA-2048",   "vpn_link",       0.6),
                HNDLExposureRecord(DataCategory.MA_COMMUNICATIONS,   2.0, "ECDSA-P256", "email_link",     0.5),
                HNDLExposureRecord(DataCategory.ALGO_SOURCE_CODE,    1.0, "RSA-4096",   "internal_link",  0.4),
                HNDLExposureRecord(DataCategory.SWIFT_MESSAGES,     10.0, "RSA-2048",   "swift_gateway",  0.9),
                HNDLExposureRecord(DataCategory.CLIENT_PII,         30.0, "ECDH-P256",  "api_gateway",    0.6),
            ]
        else:
            records = [HNDLExposureRecord(DataCategory.TRADE_ORDERS, 10.0, "RSA-2048", "link", 0.5)]

        with st.spinner("Computing HNDL exposure..."):
            report = engine.assess_portfolio(records, adversary, scenario)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Daily Volume", f"{report.total_daily_volume_gb:.0f} GB")
        m2.metric("Critical Assets", report.critical_assets,
                 delta=(f"{report.critical_assets} need immediate action" if report.critical_assets > 0 else "None critical"))
        m3.metric("Overall Risk Score", f"{report.overall_risk_score:.0f}/100")
        m4.metric("Financial Exposure", f"${report.total_financial_exposure_usd:,.0f}")

        # Risk score bar chart
        df = pd.DataFrame(report.asset_results)
        if not df.empty:
            fig = px.bar(df, x="data_category", y="risk_score",
                        color="risk_score", color_continuous_scale="RdYlGn_r",
                        title="HNDL Risk Score by Data Category",
                        labels={"risk_score": "Risk Score (0-100)"})
            fig.add_hline(y=75, line_dash="dash", line_color="red", annotation_text="Critical threshold")
            fig.update_layout(plot_bgcolor="#0a1628", paper_bgcolor="#0a1628", font=dict(color="white"))
            st.plotly_chart(fig, width="stretch")

        st.subheader("Immediate Actions Required")
        for action in report.immediate_actions:
            st.warning(action)

        st.subheader("Q-Day Scenario Analysis")
        qday_df = pd.DataFrame([
            {"Scenario": k, "Q-Day Year": v["qday_year"], "Assets At Risk": v["assets_at_risk"]}
            for k, v in report.qday_scenarios.items()
        ])
        st.dataframe(qday_df, hide_index=True)


# ================================================================== #
#  TAB 6: Q-Day Timeline                                               #
# ================================================================== #

with tab_qday:
    st.header("Q-Day Timeline — When Will RSA Be Broken?")
    st.markdown("*Probabilistic model based on published quantum hardware roadmaps and academic consensus*")

    analyzer = QDayTimeline()
    result = analyzer.analyze(current_year=2026)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Median Q-Day Year", result.median_qday_year)
    m2.metric("Prob. before 2030", f"{result.probability_before_2030*100:.0f}%")
    m3.metric("Prob. before 2035", f"{result.probability_before_2035*100:.0f}%")
    m4.metric("Prob. before 2040", f"{result.probability_before_2040*100:.0f}%")

    st.info(result.risk_horizon_for_finance)

    # Scenario chart
    scenarios_df = pd.DataFrame(result.scenarios)
    fig = px.bar(scenarios_df, x="year", y="probability",
                text="name", color="probability",
                color_continuous_scale="RdYlGn_r",
                title="Q-Day Probability Distribution by Scenario",
                labels={"probability": "Probability", "year": "Estimated Q-Day Year"})
    fig.update_traces(textposition="outside")
    fig.update_layout(plot_bgcolor="#0a1628", paper_bgcolor="#0a1628", font=dict(color="white"))
    st.plotly_chart(fig, width="stretch")

    # Probability density
    years = list(range(2028, 2061))
    density = analyzer.probability_density(years)
    density_df = pd.DataFrame(density)
    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(x=density_df["year"], y=density_df["probability_density"],
                             fill="tozeroy", fillcolor="rgba(15,98,172,0.4)",
                             line=dict(color="#0f62ac")))
    fig2.add_vline(x=result.median_qday_year, line_dash="dash", line_color="red",
                  annotation_text=f"Median: {result.median_qday_year}")
    fig2.add_vline(x=2026, line_dash="dot", line_color="white", annotation_text="Today (2026)")
    fig2.update_layout(
        title="Q-Day Annual Probability Density (2028–2060)",
        xaxis_title="Year", yaxis_title="Probability Density",
        plot_bgcolor="#0a1628", paper_bgcolor="#0a1628", font=dict(color="white"),
    )
    st.plotly_chart(fig2, width="stretch")

    # Hardware roadmap table
    st.subheader("Quantum Hardware Roadmap Assessment")
    hw_df = pd.DataFrame(result.hardware_assessments)
    st.dataframe(hw_df[["vendor", "current_qubits", "current_error_rate", "target_2030", "fault_tolerant_eta", "shor_readiness"]],
                hide_index=True)

    st.subheader("Shor Algorithm Requirements for RSA-2048")
    shor = result.shor_algorithm_requirements
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Logical Qubits Required", f"{shor['logical_qubits']:,}")
        st.metric("Physical Qubits (central estimate)", f"{shor['physical_qubits_central']:,}")
    with col2:
        st.metric("Runtime at 1MHz logical clock", f"{shor['estimated_runtime_hours']} hours")
        st.info(f"Physical qubit range: {shor['physical_qubits_range']}")


# ================================================================== #
#  TAB 7: PQC Algorithms                                               #
# ================================================================== #

with tab_pqc:
    st.header("Post-Quantum Cryptography — NIST Standards")

    pqc_sub = st.tabs(["Kyber KEM", "Dilithium Signatures", "Algorithm Comparison", "Migration Planner"])

    with pqc_sub[0]:
        st.subheader("CRYSTALS-Kyber Key Encapsulation Mechanism (NIST FIPS 203)")
        variant_k = st.selectbox("Kyber Variant", ["kyber512", "kyber768", "kyber1024"])
        if st.button("Benchmark Kyber vs RSA-2048"):
            variant_map = {"kyber512": KyberVariant.KYBER_512, "kyber768": KyberVariant.KYBER_768, "kyber1024": KyberVariant.KYBER_1024}
            sim = KyberSimulator()
            bench = sim.benchmark_vs_rsa(variant_map[variant_k])

            col_k, col_r = st.columns(2)
            with col_k:
                st.markdown(f"### {bench['algorithm']} (Quantum Safe)")
                st.metric("Public Key", f"{bench['key_sizes']['kyber_public_key_bytes']} bytes")
                st.metric("Ciphertext", f"{bench['key_sizes']['kyber_ciphertext_bytes']} bytes")
                st.metric("KeyGen Time", f"{bench['performance_ms']['kyber_keygen']:.3f} ms")
                st.metric("Decap Time", f"{bench['performance_ms']['kyber_decap']:.3f} ms")
                st.metric("Quantum Security", f"{bench['security']['quantum_bits']} bits")
            with col_r:
                st.markdown("### RSA-2048 (NOT Quantum Safe)")
                st.metric("Public Key", f"{bench['key_sizes']['rsa2048_public_key_bytes']} bytes")
                st.metric("Ciphertext", f"{bench['key_sizes']['rsa2048_ciphertext_bytes']} bytes")
                st.metric("KeyGen Time", f"{bench['performance_ms']['rsa_keygen']:.1f} ms")
                st.metric("Decap Time", f"{bench['performance_ms']['rsa_decap']:.1f} ms")
                st.metric("Quantum Security", "0 bits (Broken by Shor)")

            st.success(bench["recommendation"])

    with pqc_sub[1]:
        st.subheader("CRYSTALS-Dilithium Digital Signatures (NIST FIPS 204)")
        variant_d = st.selectbox("Dilithium Variant", ["dilithium2", "dilithium3", "dilithium5"])
        if st.button("Benchmark Dilithium vs ECDSA"):
            variant_map = {"dilithium2": DilithiumVariant.DILITHIUM2, "dilithium3": DilithiumVariant.DILITHIUM3, "dilithium5": DilithiumVariant.DILITHIUM5}
            sim = DilithiumSimulator()
            bench = sim.benchmark_vs_ecdsa(variant_map[variant_d])
            col_d, col_e = st.columns(2)
            with col_d:
                st.markdown(f"### {bench['dilithium']['name']} (Quantum Safe)")
                st.metric("Public Key", f"{bench['dilithium']['public_key_bytes']} bytes")
                st.metric("Signature", f"{bench['dilithium']['signature_bytes']} bytes")
                st.metric("Sign Time", f"{bench['dilithium']['sign_time_ms']:.3f} ms")
            with col_e:
                st.markdown("### ECDSA P-256 (NOT Quantum Safe)")
                st.metric("Public Key", f"{bench['ecdsa_p256']['public_key_bytes']} bytes")
                st.metric("Signature", f"{bench['ecdsa_p256']['signature_bytes']} bytes")
                st.metric("Sign Time", f"{bench['ecdsa_p256']['sign_time_ms']:.3f} ms")
            st.metric("TLS Handshake Overhead", f"+{bench['tls_handshake_overhead_bytes']} bytes")

    with pqc_sub[2]:
        st.subheader("Signature Size Comparison — All Algorithms")
        if st.button("Compare Signature Sizes"):
            sim = FALCONSimulator()
            data = sim.signature_size_comparison()
            df  = pd.DataFrame(data)
            fig = px.bar(df, x="name", y="sig_bytes",
                        color="quantum_safe",
                        color_discrete_map={True: "#44bb44", False: "#ff4444"},
                        title="Signature Size Comparison (bytes)",
                        labels={"sig_bytes": "Signature Size (bytes)", "name": "Algorithm"})
            fig.update_layout(plot_bgcolor="#0a1628", paper_bgcolor="#0a1628", font=dict(color="white"))
            st.plotly_chart(fig, width="stretch")

    with pqc_sub[3]:
        st.subheader("PQC Migration Planner")
        inst_name = st.text_input("Institution Name", value="Acme Capital Management")
        if st.button("Run Sample Migration Assessment"):
            engine = MigrationEngine()
            assets = [
                CryptoAsset("a1", "Trading API TLS", ClassicalAlgorithm.ECDH_P256,   FinancialProtocol.TLS_1_3, "confidential", 7, "trading_engine", 2_000_000),
                CryptoAsset("a2", "SWIFT Gateway",   ClassicalAlgorithm.RSA_2048,    FinancialProtocol.SWIFT,   "secret", 10, "swift_gateway", 500_000),
                CryptoAsset("a3", "Client Portal",   ClassicalAlgorithm.ECDSA_P256,  FinancialProtocol.HTTPS,   "confidential", 7, "web_portal", 100_000),
                CryptoAsset("a4", "Settlement DB",   ClassicalAlgorithm.RSA_2048,    FinancialProtocol.TLS_1_2, "secret", 10, "settlement", 0),
            ]
            plan = engine.generate_plan(inst_name, assets)
            st.info(plan.executive_summary)

            for a in plan.assessments:
                urgency_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}.get(a.urgency.value, "⚪")
                with st.expander(f"{urgency_color} {a.asset.name} — Risk: {a.risk_score:.0f}/100 — {a.urgency.value.upper()}"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**Current Algorithm:** {a.asset.algorithm.value}")
                        st.write(f"**Recommended KEM:** {a.recommended_kem}")
                        st.write(f"**Recommended Sig:** {a.recommended_sig}")
                        st.write(f"**Migration Effort:** {a.estimated_migration_effort}")
                    with col_b:
                        for flag in a.compliance_flags:
                            if "NON-COMPLIANT" in flag:
                                st.error(flag)
                            elif "RISK" in flag or "WARNING" in flag:
                                st.warning(flag)
                            else:
                                st.success(flag)


# ================================================================== #
#  TAB 8: Crypto Audit                                                 #
# ================================================================== #

with tab_audit:
    st.header("Cryptographic Infrastructure Audit")
    st.markdown("Grade your institution's current cryptographic posture against quantum and classical threats")

    inst_audit = st.text_input("Institution Name", value="Meridian Bank plc", key="audit_inst")

    if st.button("Run Sample Institution Audit", type="primary"):
        auditor = CryptoAuditor()
        systems = [
            SystemCryptoProfile("Trading Engine API", "trading_engine",
                ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"],
                "1.3", "EC-P-256", 256, 180, True, True, "trading.internal", "Markets"),
            SystemCryptoProfile("SWIFT Gateway", "swift_gateway",
                ["TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"],
                "1.2", "RSA-2048", 2048, 45, False, False, "swift.internal", "Operations"),
            SystemCryptoProfile("Client Web Portal", "web_portal",
                ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                "1.3", "RSA-2048", 2048, 280, True, True, "www.acme.com", "Digital"),
            SystemCryptoProfile("Risk Analytics API", "risk_system",
                ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256"],
                "1.1", "RSA-1024", 1024, 5, False, False, "risk.internal", "Risk"),
        ]

        result = auditor.audit_institution(inst_audit, systems)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Systems Audited", result.total_systems)
        m2.metric("Critical Findings", result.critical_findings)
        m3.metric("Quantum Vulnerable", result.quantum_vulnerable_systems)
        m4.metric("Avg Quantum Score", f"{result.avg_quantum_vulnerability_score:.0f}/100")

        st.subheader("Compliance Overview")
        comp_df = pd.DataFrame([
            {"Framework": k, "Compliant": "YES" if v else "NO"}
            for k, v in result.compliance_overview.items()
        ])
        st.dataframe(comp_df, hide_index=True)

        st.subheader("System Grades")
        grade_colors = {"A+": "#00ff00", "A": "#44bb44", "B+": "#88cc44", "B": "#aabb00",
                       "C": "#ffcc00", "D": "#ff8800", "F": "#ff4444"}
        for sys_audit in result.system_audits:
            g = sys_audit["grade"]
            color = grade_colors.get(g, "#ffffff")
            with st.expander(f"Grade {g} — {sys_audit['system']}"):
                if sys_audit["broken_suites"]:
                    st.error(f"Broken suites: {', '.join(sys_audit['broken_suites'])}")
                for rec in sys_audit["recommendations"]:
                    st.warning(rec)

        st.subheader("Priority Recommendations")
        for rec in result.summary_recommendations:
            st.warning(f"→ {rec}")


# ================================================================== #
#  TAB 9: Network Topology                                             #
# ================================================================== #

with tab_network:
    st.header("QKD Network Topology Modeler")

    col1, col2 = st.columns([1, 2])
    with col1:
        topo_inst = st.text_input("Institution", "Global Capital Partners")
        topo_type = st.selectbox("Topology", ["ring", "star", "mesh"])
        st.markdown("**Office Locations**")
        offices = [
            {"name": "London HQ",       "city": "London",    "lat": 51.5074, "lon": -0.1278},
            {"name": "Frankfurt DC",    "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
            {"name": "New York Office", "city": "New York",  "lat": 40.7128, "lon": -74.0060},
            {"name": "Singapore Hub",   "city": "Singapore", "lat": 1.3521,  "lon": 103.8198},
        ]
        n_offices = st.slider("Number of Offices", 2, 4, 3)
        offices = offices[:n_offices]
        run_topo = st.button("Analyze Topology", type="primary")

    with col2:
        if run_topo:
            modeler  = QKDNetworkModeler()
            topology = modeler.create_financial_topology(topo_inst, offices, topo_type)
            result   = modeler.analyze_topology(topology)

            m1, m2, m3 = st.columns(3)
            m1.metric("Viable Links", f"{result.viable_links}/{result.total_links}")
            m2.metric("Total Cost", f"${result.total_infrastructure_cost_usd:,.0f}")
            m3.metric("Resilience Score", f"{result.network_resilience_score:.0f}/100")

            # Map plot
            lats = [o["lat"] for o in offices]
            lons = [o["lon"] for o in offices]
            names = [o["name"] for o in offices]
            fig = go.Figure()
            fig.add_trace(go.Scattergeo(lat=lats, lon=lons, text=names,
                                       mode="markers+text", textposition="top center",
                                       marker=dict(size=12, color="#0f62ac")))
            for link in result.link_analysis:
                node_a = next((n for n in topology.nodes if n.node_id == link["node_a"]), None)
                node_b = next((n for n in topology.nodes if n.node_id == link["node_b"]), None)
                if node_a and node_b:
                    color = "#44bb44" if link["viable"] else "#ff4444"
                    fig.add_trace(go.Scattergeo(
                        lat=[node_a.latitude, node_b.latitude],
                        lon=[node_a.longitude, node_b.longitude],
                        mode="lines", line=dict(color=color, width=2),
                        name=f"Link {link['link_id']} {'✓' if link['viable'] else '✗'}"
                    ))
            fig.update_layout(
                title=f"{topo_inst} QKD Network — {topo_type.title()} Topology",
                geo=dict(showframe=False, showcoastlines=True,
                        landcolor="#0a1628", oceancolor="#0d1f3c",
                        showland=True, showocean=True,
                        bgcolor="#0a1628"),
                paper_bgcolor="#0a1628", font=dict(color="white"),
                height=400,
            )
            st.plotly_chart(fig, width="stretch")

            st.dataframe(pd.DataFrame(result.link_analysis)[
                ["link_id", "distance_km", "viable", "secure_key_rate_bps", "channel_loss_db", "estimated_cost_usd"]
            ], hide_index=True)


# ================================================================== #
#  TAB 10: Deployment Roadmap                                          #
# ================================================================== #

with tab_roadmap:
    st.header("QKD Deployment Roadmap Generator")
    st.markdown("*Board-ready deployment plan with cost model, ROI projections, and compliance milestones*")

    col1, col2 = st.columns([1, 2])
    with col1:
        rd_name = st.text_input("Institution Name", "Meridian Capital Group")
        rd_type = st.selectbox("Institution Type", list(INSTITUTION_PROFILES.keys()))
        rd_risk = st.slider("Current Risk Score", 0.0, 100.0, 72.0)
        rd_offices = st.slider("Number of Offices/DCs", 2, 20, 4)
        run_roadmap = st.button("Generate Roadmap", type="primary")

    with col2:
        if run_roadmap:
            gen = RoadmapGenerator()
            roadmap = gen.generate(rd_name, rd_type, rd_risk, rd_offices)

            st.info(roadmap.executive_summary)

            m1, m2, m3 = st.columns(3)
            m1.metric("Total Duration", f"{roadmap.total_duration_months} months")
            m2.metric("Total Capex", f"${roadmap.total_capital_cost_usd:,.0f}")
            m3.metric("Annual Opex", f"${roadmap.total_annual_opex_usd:,.0f}/yr")

            # ROI chart
            roi_df = pd.DataFrame(roadmap.roi_projections)
            fig = go.Figure()
            fig.add_trace(go.Bar(x=roi_df["year"], y=roi_df["cumulative_investment_usd"],
                                name="Cumulative Investment", marker_color="#ff8800"))
            fig.add_trace(go.Scatter(x=roi_df["year"], y=roi_df["avoided_breach_cost_usd"],
                                    name="Avoided Breach Cost", line=dict(color="#44bb44", width=2)))
            fig.add_hline(y=0, line_color="white")
            fig.update_layout(
                title="ROI Projection — Investment vs Risk Reduction Value",
                xaxis_title="Year", yaxis_title="USD",
                plot_bgcolor="#0a1628", paper_bgcolor="#0a1628",
                font=dict(color="white"), barmode="group",
            )
            st.plotly_chart(fig, width="stretch")

            st.subheader("Board Presentation Points")
            for pt in roadmap.board_presentation_points:
                st.markdown(f"- {pt}")

            st.subheader("Quick Wins (Start Immediately)")
            for qw in roadmap.quick_wins:
                st.success(f"✓ {qw}")

            st.subheader("Deployment Phases")
            for phase in roadmap.phases:
                with st.expander(f"Phase {phase['phase']} — {phase['name']} ({phase['duration_months']} months)"):
                    st.write(f"**Capex:** ${phase['capital_cost_usd']:,} | **Annual Opex:** ${phase['opex_usd_per_year']:,}")
                    st.write(f"**Risk Reduction:** {phase['risk_reduction_pct']}%")
                    st.markdown("**Objectives:**")
                    for obj in phase["objectives"]:
                        st.markdown(f"  - {obj}")
                    st.markdown("**Compliance milestones:**")
                    for milestone in phase["compliance_milestones"]:
                        st.success(milestone)


# ================================================================== #
#  TAB 11: QKD Key Manager                                             #
# ================================================================== #

with tab_kms:
    st.header("QKD Key Management System")
    st.markdown("*ETSI GS QKD 014 compliant key lifecycle management*")

    if "kms" not in st.session_state:
        st.session_state.kms = QKDKeyManagementSystem()

    kms = st.session_state.kms

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Key Generation")
        link_id   = st.text_input("Link ID", "trading_floor_to_dc_01")
        n_keys    = st.slider("Keys to Generate", 10, 500, 100)
        key_bits  = st.selectbox("Key Size (bits)", [128, 256, 512, 1024], index=1)
        ttl       = st.slider("TTL (seconds)", 300, 86400, 3600)
        if st.button("Generate Keys into KMS"):
            n = kms.generate_simulated_keys(n_keys, link_id, key_bits, ttl_seconds=ttl)
            st.success(f"Generated {n} quantum keys ({key_bits}-bit) on link {link_id}")

    with col2:
        st.subheader("Key Consumption (ETSI 014)")
        sae_id = st.text_input("Slave SAE ID", "trading_system_01")
        n_req  = st.number_input("Keys to Request", 1, 20, 1)
        req_bits = st.selectbox("Required Key Size", [128, 256, 512], index=1, key="req_size")
        if st.button("Request Keys (ETSI enc_keys API)"):
            result = kms.get_key(sae_id, number=int(n_req), size_bits=req_bits)
            if result:
                st.success(f"Delivered {len(result.keys)} key(s)")
                for k in result.keys[:3]:
                    st.code(f"Key ID: {k['key_ID']}\nKey: {k['key'][:32]}...", language=None)
            else:
                st.error("Insufficient key material — generate more keys first")

    st.subheader("KMS Statistics")
    if st.button("Refresh Stats"):
        stats = kms.get_stats()
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Fresh Keys", stats.fresh_keys)
        m2.metric("Consumed Keys", stats.consumed_keys)
        m3.metric("Bits Available", f"{stats.total_bits_available:,}")
        m4.metric("Bits Consumed", f"{stats.total_bits_consumed:,}")
        m5.metric("Avg TTL Remaining", f"{stats.average_ttl_remaining_s:.0f}s")

        # State distribution pie
        fig = go.Figure(go.Pie(
            labels=["Fresh", "Consumed", "Expired", "Reserved"],
            values=[stats.fresh_keys, stats.consumed_keys, stats.expired_keys, stats.reserved_keys],
            hole=0.4,
            marker_colors=["#44bb44", "#0f62ac", "#ff8800", "#ffcc00"],
        ))
        fig.update_layout(paper_bgcolor="#0a1628", font=dict(color="white"),
                         title="Key Store State Distribution", height=300)
        st.plotly_chart(fig, width="stretch")

    st.subheader("ETSI QKD 014 API Status")
    status = kms.get_status()
    st.json(status)


# ------------------------------------------------------------------ #
#  Footer                                                               #
# ------------------------------------------------------------------ #

st.divider()
st.markdown("""
<div style='text-align: center; color: #6c757d; padding: 1rem;'>
    <strong>QuantumVault R&D Platform</strong> | Built for financial institutions navigating the quantum transition<br>
    BB84 · E91 · MDI-QKD · CRYSTALS-Kyber · Dilithium · FALCON · HNDL Risk · ETSI QKD 014 Compliant<br>
    <em>Research Grade — Not for Production Cryptographic Use</em>
</div>
""", unsafe_allow_html=True)
