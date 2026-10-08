from dataclasses import dataclass
@dataclass
class DetectionConfig:
    n_features:int=24; n_normal:int=5000; n_attack:int=200
    anomaly_threshold:float=0.3; severity_critical:float=0.9; severity_high:float=0.7; severity_medium:float=0.5
    ae_encoding_dim:int=8; ae_epochs:int=50; ae_lr:float=0.001; rand_seed:int=42
