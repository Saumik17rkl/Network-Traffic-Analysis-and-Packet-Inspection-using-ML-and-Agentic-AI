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
pip install torch==2.0.1+cpu torchvision==0.15.2+cpu torchaudio==2.0.2 --index-url https://download.pytorch.org/whl/cpu

# Install remaining requirements
grep -v '^torch' requirements.txt > requirements_clean.txt
pip install -r requirements_clean.txt

# Clean up
rm -f requirements_clean.txt
