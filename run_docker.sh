#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if the autorecon image exists
if ! docker images | grep -q "autorecon"
then
    echo "autorecon Docker image not found. Building the image..."
    docker build -t autorecon .
fi

# Run the autorecon container in interactive mode
echo "Running autorecon container..."
docker run -it --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/results:/app/results" \
  -v "$(pwd)/logs:/app/logs" \
  autorecon