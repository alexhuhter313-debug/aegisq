"""NumPy Autoencoder for anomaly detection."""
import numpy as np
class Autoencoder:
    def __init__(self,input_dim,encoding_dim,lr=0.001):
        self.input_dim,self.encoding_dim,self.lr=input_dim,encoding_dim,lr
        s=np.sqrt(2.0/input_dim);self.W1=np.random.randn(input_dim,encoding_dim)*s;self.b1=np.zeros(encoding_dim)
        s2=np.sqrt(2.0/encoding_dim);self.W2=np.random.randn(encoding_dim,input_dim)*s2;self.b2=np.zeros(input_dim)
    def _relu(self,x):return np.maximum(0,x)
    def _sigmoid(self,x):return 1/(1+np.exp(-np.clip(x,-500,500)))
    def encode(self,x):return self._relu(x@self.W1+self.b1)
    def decode(self,h):return self._sigmoid(h@self.W2+self.b2)
    def forward(self,x):return self.decode(self.encode(x))
    def train_step(self,x):
        h=self.encode(x);xr=self.decode(h);err=xr-x
        self.W2-=self.lr*(h.T@err/len(x));self.b2-=self.lr*err.mean(0)
        dh=err@self.W2.T*(h>0);self.W1-=self.lr*(x.T@dh/len(x));self.b1-=self.lr*dh.mean(0)
    def fit(self,X,epochs=50,batch_size=64,verbose=True):
        for ep in range(epochs):
            perm=np.random.permutation(len(X));Xs=X[perm];loss=0
            for i in range(0,len(X),batch_size):
                b=Xs[i:i+batch_size];self.train_step(b);loss+=np.mean((self.forward(b)-b)**2)*len(b)
            if verbose and (ep+1)%10==0:print(f"  Epoch {ep+1}/{epochs} — MSE: {loss/len(X):.6f}")
    def anomaly_score(self,X):return np.mean((X-self.forward(X))**2,axis=1)
