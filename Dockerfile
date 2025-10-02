FROM kalilinux/kali-rolling

# Set working directory
WORKDIR /app

# Install Go (required for installing tools from ProjectDiscovery)
RUN apt-get update && \
    apt-get install -y golang-go

# Set Go environment variables
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

# Install required system packages (excluding httpx which needs to be installed differently)
RUN apt-get update && \
    apt-get install -y nmap whatweb dnsenum sublist3r theharvester python3 python3-pip curl python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Install httpx from ProjectDiscovery
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Copy the application files
COPY . .

# Install Python dependencies with --break-system-packages for Kali compatibility
RUN pip3 install --break-system-packages -r requirements.txt

# Create necessary directories
RUN mkdir -p results logs reports

# Set executable permissions
RUN chmod +x setup.sh

# Set up Kali tools
RUN echo "source /etc/profile" >> ~/.bashrc

# Set the default command
CMD ["python3", "scanner.py"]