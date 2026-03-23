"""
QuantumVault — QKD R&D Infrastructure Platform
FastAPI Application Entry Point

Quantum Key Distribution + Post-Quantum Cryptography Research Platform
for Financial Institutions.

Start server:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

API Documentation:
    http://localhost:8000/docs      (Swagger UI)
    http://localhost:8000/redoc     (ReDoc)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import os

from api.routes import qkd_router, threat_router, pqc_router, reporting_router


# ------------------------------------------------------------------ #
#  App Initialization                                                   #
# ------------------------------------------------------------------ #

app = FastAPI(
    title="QuantumVault QKD R&D Platform",
    description="""
## QuantumVault — Quantum Key Distribution Infrastructure for Financial Institutions

A research-grade platform simulating, analyzing, and planning QKD infrastructure
deployment for banks, hedge funds, exchanges, and custodians.

### Core Capabilities

**QKD Protocol Simulation**
- BB84: Prepare-and-measure with eavesdropping detection
- E91: Entanglement-based with Bell inequality testing
- MDI-QKD: Measurement Device Independent (detector-attack immune)
- Channel analysis: fiber loss, QBER, key rates, hardware comparison

**Post-Quantum Cryptography**
- CRYSTALS-Kyber KEM (NIST FIPS 203)
- CRYSTALS-Dilithium signatures (NIST FIPS 204)
- FALCON signatures (NIST FIPS 206)
- Migration planning from RSA/ECDSA to PQC

**Threat Modeling**
- HNDL (Harvest Now Decrypt Later) risk assessment
- Q-Day timeline probability distributions
- Cryptographic inventory auditing and grading

**Infrastructure Planning**
- QKD network topology modeling
- Trusted relay chain design
- QKD Key Management System (ETSI GS QKD 014 compliant)
- Deployment roadmap with ROI projections

### Monetization Tiers
| Tier | Price | Features |
|------|-------|---------|
| Research | $1,000/mo | API access, 50 simulations/day |
| Platform | $8,000/mo | Unlimited, dashboard, KMS |
| Enterprise | $50,000/yr | White-label, SLA, custom integrations |
    """,
    version="1.0.0",
    contact={
        "name": "QuantumVault R&D",
        "url": "https://quantumvault.io",
        "email": "research@quantumvault.io",
    },
    license_info={
        "name": "Proprietary",
        "url": "https://quantumvault.io/license",
    },
    docs_url="/docs",
    redoc_url="/redoc",
)

# ------------------------------------------------------------------ #
#  CORS Middleware                                                       #
# ------------------------------------------------------------------ #

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # In production: restrict to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
#  Routers                                                              #
# ------------------------------------------------------------------ #

app.include_router(qkd_router)
app.include_router(threat_router)
app.include_router(pqc_router)
app.include_router(reporting_router)

# ------------------------------------------------------------------ #
#  Health & Root Endpoints                                               #
# ------------------------------------------------------------------ #

_start_time = time.time()

@app.get("/", tags=["Health"], summary="QuantumVault Platform Root")
def root():
    return {
        "platform": "QuantumVault QKD R&D Infrastructure",
        "version": "1.0.0",
        "status": "operational",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "endpoints": {
            "swagger_ui": "/docs",
            "redoc":      "/redoc",
            "health":     "/health",
            "qkd":        "/api/v1/qkd",
            "threat":     "/api/v1/threat",
            "pqc":        "/api/v1/pqc",
            "reporting":  "/api/v1",
        },
        "quick_start": {
            "run_bb84": "POST /api/v1/qkd/bb84/simulate",
            "hndl_risk": "POST /api/v1/threat/hndl/assess",
            "qday_timeline": "GET /api/v1/threat/qday/timeline",
            "kyber_benchmark": "POST /api/v1/pqc/kyber/benchmark",
            "deployment_roadmap": "POST /api/v1/roadmap/generate",
        }
    }


@app.get("/health", tags=["Health"], summary="Health Check")
def health():
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "modules": {
            "qkd_bb84": "operational",
            "qkd_e91": "operational",
            "qkd_mdi": "operational",
            "qkd_channel": "operational",
            "pqc_kyber": "operational",
            "pqc_dilithium": "operational",
            "threat_hndl": "operational",
            "threat_qday": "operational",
            "crypto_auditor": "operational",
            "network_modeler": "operational",
            "kms_etsi014": "operational",
            "roadmap_generator": "operational",
        }
    }


@app.get("/api/v1/capabilities", tags=["Platform"], summary="Full Platform Capability Matrix")
def capabilities():
    """Return the complete capability matrix of the QuantumVault platform"""
    return {
        "qkd_protocols": {
            "bb84": {
                "description": "Bennett-Brassard 1984 — Industry standard QKD protocol",
                "attacks_simulated": ["intercept_resend", "photon_number_splitting"],
                "features": ["QBER analysis", "Privacy amplification", "Error correction", "Key rate vs distance"],
            },
            "e91": {
                "description": "Ekert 1991 — Entanglement-based with Bell inequality security proof",
                "features": ["CHSH Bell parameter", "Eavesdropping detection", "Fidelity modeling"],
            },
            "mdi_qkd": {
                "description": "Measurement Device Independent — immune to all detector side-channel attacks",
                "features": ["Untrusted relay", "Malicious Charlie simulation", "BSM analysis"],
            },
        },
        "pqc_algorithms": {
            "standardized_2024": ["CRYSTALS-Kyber (FIPS 203)", "CRYSTALS-Dilithium (FIPS 204)", "FALCON (FIPS 206)", "SPHINCS+ (FIPS 205)"],
            "hybrid_schemes": ["X25519Kyber768", "P384Kyber1024"],
            "migration_supported": ["RSA-2048", "RSA-4096", "ECDH-P256", "ECDH-P384", "ECDSA-P256", "DH-2048"],
        },
        "threat_models": {
            "hndl": "Harvest-Now-Decrypt-Later risk quantification with financial impact",
            "qday": "Probabilistic Q-Day timeline based on hardware roadmaps",
            "crypto_audit": "Institution-wide cipher suite grading and compliance checking",
        },
        "financial_protocols_covered": ["TLS 1.3", "SWIFT", "FIX 4.4/5.0", "FpML", "ISO 20022", "HTTPS"],
        "compliance_frameworks": ["NIST SP 800-208", "CNSA 2.0", "DORA", "PCI-DSS 4.0", "FIPS 140-3", "ETSI GS QKD 014"],
        "data_categories": ["Trade orders", "Settlement records", "Client PII", "Risk models", "SWIFT messages", "M&A communications", "Algo source code"],
    }


# ------------------------------------------------------------------ #
#  Entry Point                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
