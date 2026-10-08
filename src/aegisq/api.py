"""REST API."""
from fastapi import FastAPI; import numpy as np
from aegisq.detector.data_generator import DataGenerator
from aegisq.detector.engine import AEGISQDetector,AlertEngine
from aegisq.detector.reporter import generate_report
from aegisq.config import DetectionConfig
app=FastAPI(title="AEGISQ API",version="2.0.0"); detector=None
@app.on_event("startup")
def startup():
    global detector
    config=DetectionConfig();X,_,_=DataGenerator.generate(config.n_normal,config.n_attack)
    detector=AEGISQDetector(config).fit(X)
@app.get("/health")
def health():return {"status":"ok","version":"2.0.0"}
@app.post("/detect")
def detect(data:dict):
    features=np.array(data.get("features",[]))
    if features.ndim==1:features=features.reshape(1,-1)
    return {"anomaly_scores":detector.predict(features).tolist(),"threshold":detector.config.anomaly_threshold}
def serve():
    import uvicorn;uvicorn.run(app,host="0.0.0.0",port=8000)
