#!/bin/bash

# Check if the current directory is CSV-Analyse
if [ "$(basename "$PWD")" != "CSV-Analyse-ToPDF" ]; then
    echo "Error: This script must be run from the CSV-Analyse directory."
    exit 1
fi

# Check if nmap_to_pdf.py exists in the current directory
if [ ! -f "nmap_to_pdf.py" ]; then
    echo "Error: nmap_to_pdf.py not found in the CSV-Analyse directory."
    exit 1
fi

# Check if DejaVuSans.ttf exists in the current directory
if [ ! -f "DejaVuSans.ttf" ]; then
    echo "Error: DejaVuSans.ttf font file not found in the CSV-Analyse directory."
    exit 1
fi

# Function to display a spinner while a task runs
show_spinner() {
    local pid=$1
    local message=$2
    local spinner_chars="|/-\\"
    local i=0
    local delay=0.3

    # Hide cursor
    tput civis

    # Display spinner until the process (pid) completes
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r%s [%c]" "$message" "${spinner_chars:i%${#spinner_chars}:1}"
        ((i++))
        sleep "$delay"
    done

    # Clear the spinner line
    printf "\r%-*s\r" "$(tput cols)" ""

    # Restore cursor
    tput cnorm
}

# Prompt for company name
while true; do
    read -p "Enter the company name: " company_name
    if [ ${#company_name} -le 32 ]; then
        break
    else
        echo "Error: Company name must be 32 characters or less. Please try again."
    fi
done

# Prompt for IP address or range
read -p "Enter the IP address or range to scan (use nmap format): " ip_input

# Make .py file executable
sudo chmod +x nmap_to_pdf.py

# Update package list and install needed packages
echo "Updating package list..."
sudo apt update &> /dev/null &
APT_UPDATE_PID=$!
show_spinner "$APT_UPDATE_PID" "Updating package list"
wait "$APT_UPDATE_PID" || { echo "Failed to update package list. Check internet or repository settings."; exit 1; }

# Install needed packages
echo "Installing nmap, python3, python3-pip, and dependencies..."
sudo apt install -y nmap python3 python3-pip python3-venv libpng-dev libfreetype6-dev python3-matplotlib &> /dev/null &
APT_INSTALL_PID=$!
show_spinner "$APT_INSTALL_PID" "Installing packages"
wait "$APT_INSTALL_PID" || { echo "Failed to install packages. Check apt configuration."; exit 1; }

# Check if python3-fpdf is available and install it; if not, use a virtual environment
echo "Checking for python3-fpdf..."
if apt-cache show python3-fpdf > /dev/null 2>&1; then
    echo "Installing python3-fpdf..."
    sudo apt install -y python3-fpdf &> /dev/null &
    FPDF_INSTALL_PID=$!
    show_spinner "$FPDF_INSTALL_PID" "Installing python3-fpdf"
    wait "$FPDF_INSTALL_PID" || { echo "Failed to install python3-fpdf."; exit 1; }
    USE_VENV=0
else
    echo "python3-fpdf not found in apt repositories. Setting up a virtual environment..."
    # Create virtual environment (typically fast, no spinner needed)
    VENV_DIR="/tmp/nmap_scan_venv"
    sudo python3 -m venv "$VENV_DIR" || { echo "Failed to create virtual environment."; exit 1; }
    source "$VENV_DIR/bin/activate"
    # Install Python dependencies in virtual environment
    echo "Installing Python dependencies (fpdf, matplotlib)..."
    pip3 install fpdf matplotlib &> /dev/null &
    PIP_INSTALL_PID=$!
    show_spinner "$PIP_INSTALL_PID" "Installing Python dependencies"
    wait "$PIP_INSTALL_PID" || { echo "Failed to install Python packages in virtual environment."; exit 1; }
    USE_VENV=1
fi

# Update Nmap scripts to ensure vuln scripts are available
echo "Updating Nmap scripts..."
sudo nmap --script-updatedb &> /dev/null &
NMAP_SCRIPT_PID=$!
show_spinner "$NMAP_SCRIPT_PID" "Updating Nmap scripts"
wait "$NMAP_SCRIPT_PID" || echo "Warning: Failed to update Nmap scripts. Some vuln scripts may be missing."

# Do the scan and write to nmap_output.txt (DO NOT CHANGE NAME)
echo "Running Nmap scan on $ip_input..."
sudo nmap -sS -sU -sV -O -p T:1-65535,U:53,67,68,69,123,137,161,500,514,520,1900,4500 -Pn --script vuln -oN nmap_output.txt $ip_input &> /dev/null &
NMAP_PID=$!
show_spinner "$NMAP_PID" "Running Nmap scan"
wait "$NMAP_PID" || { echo "Nmap scan failed. Check IP input or Nmap installation."; exit 1; }

# Run the Python script (in virtual environment if used, else with system Python)
echo "Generating PDF report with nmap_to_pdf.py..."
if [ "$USE_VENV" -eq 1 ]; then
    sudo "$VENV_DIR/bin/python3" ./nmap_to_pdf.py "$company_name" 2> /dev/null &
    PYTHON_PID=$!
    show_spinner "$PYTHON_PID" "Generating PDF report"
    wait "$PYTHON_PID" || { echo "Failed to run Python script in virtual environment."; deactivate; exit 1; }
    deactivate
else
    sudo python3 ./nmap_to_pdf.py "$company_name" 2> /dev/null &
    PYTHON_PID=$!
    show_spinner "$PYTHON_PID" "Generating PDF report"
    wait "$PYTHON_PID" || { echo "Failed to run Python script. Check nmap_to_pdf.py and dependencies."; exit 1; }
fi

# Clean up virtual environment if used
if [ "$USE_VENV" -eq 1 ]; then
    sudo rm -rf "$VENV_DIR"
fi

# Change ownership of output files for user access
sudo chown "$USER" nmap_output.txt nmap_report_*.pdf 2> /dev/null || echo "Warning: Could not change ownership of output files."

# Place in output-dir
sudo mkdir output &> /dev/null
sudo mv nmap_output.txt output/
sudo mv nmap_report_*.pdf output/

echo "Scan and report generation completed. Files can be found in output dir."
