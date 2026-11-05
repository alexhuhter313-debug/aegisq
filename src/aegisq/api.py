"""AEGISQ v2 API — Full REST + WebSocket interface with AI bridge."""
import json, os, asyncio, logging, numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import Counter

from aegisq.config import DetectionConfig
from aegisq.detector.data_generator import DataGenerator
from aegisq.detector.engine import AEGISQDetector, AlertEngine
from aegisq.detector.reporter import generate_report
from aegisq.copilot.assistant import SecurityCopilot
from aegisq.fortress.defense import TarpitServer
from aegisq.fortress.offense import PhantomDNSExfil
from aegisq.nexus.probe import NexusProbe
from aegisq.crypto.pqc import PQCProvider

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("aegisq-api")

detector = None
copilot = SecurityCopilot()
nexus = NexusProbe()
pqc = PQCProvider()
connected_clients: set[WebSocket] = set()
last_report = {"status": "pending", "total_flows": 0, "alerts_raised": 0, "detection_rate": 0, "false_positives": 0}

@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector
    logger.info("AEGISQ API starting...")
    config = DetectionConfig()
    X, y, _ = DataGenerator.generate(config.n_normal, config.n_attack)
    detector = AEGISQDetector(config).fit(X)
    logger.info(f"Detector trained on {len(X)} samples")
    yield
    logger.info("Shutting down.")

app = FastAPI(title="AEGISQ API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "service": "aegisq-detector"}

@app.post("/detect")
async def detect(data: dict = None):
    if data and "features" in data:
        features = np.array(data["features"])
        if features.ndim == 1:
            features = features.reshape(1, -1)
        scores = detector.predict(features).tolist()
        return {"anomaly_scores": scores, "threshold": detector.config.anomaly_threshold}
    return await run_pipeline_endpoint()

@app.get("/report")
async def get_report():
    global last_report
    return last_report

@app.post("/pipeline")
async def run_pipeline_endpoint():
    global last_report
    logger.info("Running detection pipeline...")
    config = DetectionConfig()
    X, y, _ = DataGenerator.generate(config.n_normal, config.n_attack)
    scores = detector.predict(X)
    alerts = AlertEngine.analyze(scores, y, config)
    last_report = generate_report(alerts, len(X), int(np.sum(y)))
    await broadcast({"type": "report_update", "data": last_report})
    return last_report

@app.post("/copilot/query")
async def copilot_query(data: dict):
    query = data.get("query", "")
    if not query:
        return {"error": "query required"}
    result = copilot.analyze(query)
    return {"query": query, "response": result.response, "confidence": result.confidence, "sources": result.sources}

@app.post("/fortress/defense/start")
async def fortress_defense_start(data: dict = None):
    host = data.get("host", "0.0.0.0") if data else "0.0.0.0"
    port = data.get("port", 2525) if data else 2525
    server = TarpitServer(host, port)
    return {"status": "started", "host": host, "port": port, "module": "tarpit"}

@app.post("/fortress/offense/dns-exfil")
async def fortress_dns_exfil(data: dict):
    domain = data.get("domain", "internal-update.com")
    payload = data.get("payload", "")
    exfil = PhantomDNSExfil(domain)
    result = exfil.exfiltrate(payload)
    return {"domain": domain, "result": result}

@app.post("/nexus/scan")
async def nexus_scan(data: dict):
    target = data.get("target", "")
    if not target:
        return {"error": "target required"}
    result = nexus.scan(target)
    return {"target": target, "findings": result}

@app.get("/nexus/status")
async def nexus_status():
    return {"status": "ready", "modules": ["dns", "port", "http", "ssl"]}

@app.get("/crypto/status")
async def crypto_status():
    return {"provider": "PQCProvider", "algorithms": ["dilithium", "kyber", "sphincs"], "ready": True}

@app.post("/crypto/generate-keys")
async def crypto_generate_keys(data: dict = None):
    algorithm = data.get("algorithm", "dilithium") if data else "dilithium"
    keys = pqc.generate_keypair(algorithm)
    return {"algorithm": algorithm, "public_key": keys.public_key.hex(), "key_id": keys.key_id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    logger.info(f"WebSocket connected ({len(connected_clients)} total)")
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "ping":
                await websocket.send_json({"type": "pong"})
            elif msg.get("action") == "get_report":
                await websocket.send_json({"type": "report", "data": last_report})
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        logger.info(f"WebSocket disconnected ({len(connected_clients)} remaining)")

async def broadcast(message: dict):
    dead = set()
    for ws in connected_clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.add(ws)
    connected_clients -= dead

def serve():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
