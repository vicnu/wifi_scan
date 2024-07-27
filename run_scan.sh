#!/bin/bash

echo "Starting script..."

# Check if the virtual environment exists
if [ ! -d "myenv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv myenv
  source myenv/bin/activate
  echo "Installing packages..."
  pip install scapy netifaces requests
else
  # Activate the virtual environment
  source myenv/bin/activate
fi

echo "Running Python script with elevated privileges..."
# Run the Python script with sudo, ensuring the virtual environment is activated
sudo myenv/bin/python3 scan_network.py "$@"
