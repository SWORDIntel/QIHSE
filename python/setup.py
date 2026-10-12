"""
QIHSE Python package setup.
"""

from setuptools import setup, find_packages

setup(
    name="qihse",
    version="0.1.0",
    description="Python bindings for QIHSE vector database",
    license="SWORD Restricted Source Licence (SRSL-1.0)",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["numpy"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
)
