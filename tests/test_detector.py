import numpy as np
from aegisq.detector.autoencoder import Autoencoder
def test_autoencoder():
    ae=Autoencoder(24,8);X=np.random.randn(100,24)
    ae.fit(X,epochs=5,verbose=False);s=ae.anomaly_score(X)
    assert s.shape==(100,)and np.all(s>=0)
