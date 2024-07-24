#!/bin/bash

# Update system package index
sudo apt update

# Install Python3 and pip3 if not installed
sudo apt install -y python3 python3-pip

# Install required Python packages
pip3 install -r src/requirements.txt

# Copy the detection script to /usr/local/bin (optional, for easy access)
sudo cp detection.py /usr/local/bin/detection.py

# Make the script executable
sudo chmod +x /home/ta2024/detection.py

echo "Installation completed. You can run the detection script using: sudo python3 /user/local/bin/detection.py"
