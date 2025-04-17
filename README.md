# Nmap to PDF Report Generator

This project generates a formatted PDF report from Nmap scan output, including a title page with a company logo, a reference page for CVE information, a summary page with scan statistics and charts (split into multiple charts if more than 32 IPs are scanned), and detailed sections for each scanned host. The goal is to make Nmap scan results easier to read and understand.

## Prerequisites

A Debian-based Linux distribution.

All required components (Nmap, Python 3, and Python libraries like `fpdf` and `matplotlib`) are automatically installed by `script.sh` when executed. The script **must be run from within the** `CSV-Analyse-ToPDF` **project directory** to ensure proper file paths and access to included resources like `DejaVuSans.ttf` and `logo.png`.

## Files in the Folder

- `DejaVuSans.ttf`: A TrueType font file used in the PDF for better text rendering and Unicode support.
- `logo.png`: The logo image displayed on the title page of the PDF. Replace with your own company's logo if desired.
- `script.sh`: A shell script that installs dependencies, runs the Nmap scan, and generates the PDF report.
- `nmap_to_pdf.py`: A Python script that processes the Nmap output and generates the PDF report.
- `output/`: A directory created by `script.sh` to store the scan output (`nmap_output.txt`) and the generated PDF report (`nmap_report_Company_Name.pdf`).

## Usage Instructions

1. **Navigate to the** `CSV-Analyse-ToPDF` **Directory**:

   - Ensure you are in the `CSV-Analyse-ToPDF` directory containing `script.sh`, `nmap_to_pdf.py`, `DejaVuSans.ttf`, and `logo.png`. For example:

     ```bash
     cd /path/to/CSV-Analyse-ToPDF
     ```

2. **Run the Script**:

   - Execute `script.sh` with the target IP addresses or network range (in Nmap format) as an argument. The script will:

     - Check that it’s running in the `CSV-Analyse-ToPDF` directory.
     - Verify the presence of `nmap_to_pdf.py` and `DejaVuSans.ttf`.
     - Prompt for a company name (32 characters or less).
     - Install dependencies (Nmap, Python 3, `fpdf`, `matplotlib`, etc.), using a virtual environment if `python3-fpdf` is unavailable via `apt`.
     - Run an Nmap scan with vulnerability scripts and save output to `nmap_output.txt`.
     - Generate the PDF report using `nmap_to_pdf.py`.
     - Move output files to the `output/` directory.

   - Example:

     ```bash
     ./script.sh 192.168.1.0/24
     ```

   - Follow the prompts to enter the company name and IP address/range.

3. **Access the Output**:

   - The scan output (`nmap_output.txt`) and PDF report (`nmap_report_Company_Name.pdf`) will be placed in the `output/` directory.

## Important Notes

- **Run from** `CSV-Analyse-ToPDF` **Directory**: The script enforces execution from the `CSV-Analyse-ToPDF` directory to ensure access to `DejaVuSans.ttf`, `logo.png`, and `nmap_to_pdf.py`.
- **Automatic Dependency Installation**: `script.sh` installs all required dependencies, including Nmap, Python 3, and Python libraries. Internet access and `sudo` permissions are required.
- **Company Name Length**: The company name must be 32 characters or less, as enforced by `script.sh`.
- **Output Directory**: All output files are moved to the `output/` directory, which is created by the script.
- **Virtual Environment**: If `python3-fpdf` is not available via `apt`, a temporary virtual environment is created in `/tmp/nmap_scan_venv` and deleted after use.

## Customization

- **Logo**: Replace `logo.png` with your own image file. Ensure it’s named `logo.png` or update `nmap_to_pdf.py` to reference the correct filename.

- **Font**: The PDF uses DejaVu Sans. To use a different font, replace `DejaVuSans.ttf` and update `nmap_to_pdf.py` to load the new font.

- **Nmap Options**: Modify the Nmap command in `script.sh` to change scan parameters (e.g., ports, scripts). The current command is:

  ```bash
  nmap -sS -sU -sV -O -p T:1-65535,U:53,67,68,69,123,137,161,500,514,520,1900,4500 -Pn --script vuln
  ```

## Troubleshooting

- **Script Fails with Directory Error**:

  - Verify that `nmap_to_pdf.py` and `DejaVuSans.ttf` are present.

- **Permission Issues**:

  - Ensure `script.sh` is executable:

    ```bash
    chmod +x script.sh
    ```

  - The script requires `sudo` for installing packages and running Nmap. Ensure you have appropriate permissions.

- **Dependency Installation Fails**:

  - Check internet connectivity and `apt` configuration.
  - Review console output for specific errors during `apt` or `pip` installations.

- **PDF Generation Fails**:

  - Verify that `nmap_output.txt` was created in the `output/` directory and contains valid Nmap output.
  - Ensure `DejaVuSans.ttf` and `logo.png` are in the `CSV-Analyse-ToPDF` directory.

- **Output Files Missing**:

  - Check the `output/` directory for `nmap_output.txt` and `nmap_report_*.pdf`.
  - Ensure the script completed without errors (e.g., invalid IP input or Nmap failure).
