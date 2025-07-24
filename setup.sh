#!/bin/bash

# Update package lists
sudo apt-get update

# Install required system packages
sudo apt-get install -y nmap whatweb dnsenum sublist3r theharvester httpx

# Install Python dependencies
pip install -r requirements.txt
