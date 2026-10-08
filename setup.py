"""AEGISQ."""
from setuptools import setup, find_packages
setup(name="aegisq",version="2.0.0",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.10",install_requires=["numpy>=1.24","fastapi>=0.104","uvicorn>=0.24","pydantic>=2.0"],entry_points={"console_scripts":["aegisq=aegisq.cli:main"]})
