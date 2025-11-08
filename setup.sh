#!/bin/bash

# Exit on error
set -e

# Update pip and setuptools
python -m pip install --upgrade pip setuptools wheel

# Install system dependencies if on Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then
        apt-get update && apt-get install -y --no-install-recommends $(cat packages.txt)
    fi
fi

# Install Python dependencies with specific PyTorch version for CPU
pip install torch>=2.1.0 torchvision>=0.16.0 torchaudio>=2.1.0 --index-url https://download.pytorch.org/whl/cpu

# Install remaining requirements
pip install -r requirements.txt