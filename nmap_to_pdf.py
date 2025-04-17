import sys
from fpdf import FPDF
import re
import matplotlib.pyplot as plt
import io
import os
import math

# Function to sanitize company name for filename
def sanitize_filename(name):
    # Replace spaces with underscores and remove/replace special characters
    sanitized = re.sub(r'[^a-zA-Z0-9\s-]', '_', name.strip())
    sanitized = sanitized.replace(' ', '_')
    # Limit length to avoid overly long filenames (optional)
    return sanitized[:50]  # Truncate to 50 characters for safety

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        # Add DejaVu Sans font for Unicode support
        self.add_font('DejaVu', '', 'DejaVuSans.ttf')

    def header(self):
        pass  # No default header

    def footer(self):
        self.set_y(-20)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(128)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

    def add_title_page(self, company_name, logo_path="logo.png"):
        self.add_page()
        if logo_path and os.path.exists(logo_path):
            self.image(logo_path, x=60, y=50, w=90)
        self.set_font("DejaVu", "", 24)
        self.set_y(150)
        self.cell(0, 10, "Vulnerability Report", ln=True, align="C")
        self.set_font("DejaVu", "", 16)
        self.ln(10)
        self.cell(0, 10, f"for {company_name}", ln=True, align="C")

    def add_reference_page(self):
        self.add_page()
        self.set_font("DejaVu", "", 18)
        self.cell(0, 10, "Reference Information", ln=True, align="C")
        self.ln(10)

        self.set_font("DejaVu", "", 12)
        self.multi_cell(0, 10,
            "All CVEs listed in this report can be looked up in more detail at the following official databases:",
            align="C"
        )
        self.ln(10)

        self.set_font("DejaVu", "", 12)
        self.set_text_color(0, 0, 255)

        self.cell(0, 10, "National Vulnerability Database (NVD)", ln=True, align="C", link="https://nvd.nist.gov/vuln/search")
        self.cell(0, 10, "Vulners CVE Database", ln=True, align="C", link="https://vulners.com/")

        self.set_text_color(0)  # Reset color

    def add_summary_page(self, summary_data, cve_per_ip):
        self.add_page()
        self.set_font("DejaVu", "", 18)
        self.cell(0, 10, "Scan Summary", ln=True, align="C")
        self.ln(10)

        self.set_font("DejaVu", "", 12)
        lines = [
            f"Total Hosts Scanned: {summary_data['total_hosts']}",
            f"Total Unique Ports Open: {summary_data['total_ports']}",
            f"Total CVEs Found: {summary_data['total_cves']}",
            ""
        ]

        for line in lines:
            self.cell(0, 10, line, ln=True, align="C")
        self.ln(10)

        # Create severity bar chart
        plt.figure(figsize=(6, 4))
        severities = ['Critical', 'High', 'Medium', 'Low']
        counts = [summary_data['severity'][sev] for sev in severities]
        colors = ['#FF0000', '#FF4500', '#FFA500', '#008000']
        
        bars = plt.bar(severities, counts, color=colors)
        plt.title('Severity Breakdown')
        plt.xlabel('Severity')
        plt.ylabel('Number of CVEs')
        plt.grid(True, axis='y', linestyle='--', alpha=0.7)
        
        # Add value labels on top of bars
        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), va='bottom')
        
        # Save severity plot to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        buf.seek(0)
        
        # Add severity plot to PDF on same page
        self.image(buf, x=30, y=self.get_y(), w=150)
        plt.close()
        buf.close()

        # Create CVEs per IP bar charts (multiple if needed)
        ips = list(cve_per_ip.keys())
        cve_counts = list(cve_per_ip.values())
        max_ips_per_chart = 32
        num_charts = math.ceil(len(ips) / max_ips_per_chart)

        for chart_idx in range(num_charts):
            self.add_page()
            self.set_font("DejaVu", "", 18)
            self.cell(0, 10, f"CVEs per IP Address (Part {chart_idx + 1}/{num_charts})", ln=True, align="C")
            self.ln(10)

            # Slice the data for the current chart
            start_idx = chart_idx * max_ips_per_chart
            end_idx = min((chart_idx + 1) * max_ips_per_chart, len(ips))
            current_ips = ips[start_idx:end_idx]
            current_counts = cve_counts[start_idx:end_idx]

            plt.figure(figsize=(6, 4))
            bars = plt.bar(current_ips, current_counts, color='#4682B4')
            plt.title(f'CVEs per IP Address (Part {chart_idx + 1})')
            plt.xlabel('IP Address')
            plt.ylabel('Number of CVEs')
            plt.grid(True, axis='y', linestyle='--', alpha=0.7)
            plt.xticks(rotation=45, ha='right')
            
            # Add value labels on top of bars
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), va='bottom')
            
            # Save IP plot to buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
            buf.seek(0)
            
            # Add IP plot to PDF
            self.image(buf, x=30, y=self.get_y(), w=150)
            plt.close()
            buf.close()

    def add_host_section(self, ip, ports_data):
        self.add_page()
        self.set_font("DejaVu", "", 18)
        self.cell(0, 10, ip, ln=True, align="C")

        for port, lines in ports_data.items():
            self.set_font("DejaVu", "", 14)
            self.cell(0, 10, f"Port {port}", ln=True, align="C")
            self.ln(5)

            # Collect CVEs with score
            cve_data = []
            for line in lines:
                match = re.search(r"(CVE-\d{4}-\d{4,7}|CNVD-\d{4}-\d+|1337DAY-ID-\d+|EDB-ID:\d+)\s+([\d.]+)", line)
                if match:
                    cve = match.group(1)
                    score = float(match.group(2))
                    if score >= 9.0:
                        severity = "Critical"
                    elif score >= 7.0:
                        severity = "High"
                    elif score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                    cve_data.append((cve, score, severity))

            # Table
            if cve_data:
                self.set_font("DejaVu", "", 12)
                page_width = self.w - 2 * self.l_margin
                col_widths = [page_width * 0.1, page_width * 0.4, page_width * 0.25, page_width * 0.25]

                # Center table
                x_start = (self.w - sum(col_widths)) / 2
                self.set_x(x_start)
                self.cell(col_widths[0], 10, "Check", border=1, align="C")
                self.cell(col_widths[1], 10, "CVE", border=1, align="C")
                self.cell(col_widths[2], 10, "Score", border=1, align="C")
                self.cell(col_widths[3], 10, "Severity", border=1, ln=True, align="C")

                self.set_font("DejaVu", "", 12)
                for cve, score, severity in cve_data:
                    self.set_x(x_start)
                    # Draw checkbox (empty square)
                    self.cell(col_widths[0], 10, chr(0x2610), border=1, align="C")  # Unicode ballot box
                    self.cell(col_widths[1], 10, cve, border=1, align="C")
                    self.cell(col_widths[2], 10, str(score), border=1, align="C")
                    self.cell(col_widths[3], 10, severity, border=1, ln=True, align="C")
                self.ln(15)  # Increased spacing after table
            else:
                self.set_font("DejaVu", "", 12)
                self.cell(0, 10, "No CVEs found on this port.", ln=True, align="C")
                self.ln(15)  # Increased spacing after no-CVE message

def parse_nmap_output(filename):
    hosts = {}
    current_ip = None
    current_port = None

    with open(filename, "r") as file:
        for line in file:
            ip_match = re.match(r"Nmap scan report for (.+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
                hosts[current_ip] = {}
                current_port = None
                continue

            port_match = re.match(r"(\d+/tcp|\d+/udp)\s+open\s+.*", line)
            if port_match and current_ip:
                current_port = port_match.group(1)
                hosts[current_ip][current_port] = []
                continue

            if current_ip and current_port:
                hosts[current_ip][current_port].append(line.strip())
    return hosts

# === Main execution ===
if __name__ == "__main__":
    # Check for company name argument
    if len(sys.argv) < 2:
        print("Error: Company name must be provided as a command-line argument.")
        print("Usage: python3 nmap_to_pdf_v3.py <company_name>")
        sys.exit(1)

    company_name = sys.argv[1]
    sanitized_company_name = sanitize_filename(company_name)

    pdf = PDF()
    pdf.set_margins(left=20, top=20, right=20)  # Increased margins
    pdf.set_auto_page_break(auto=True, margin=20)  # Increased bottom margin

    pdf.add_title_page(company_name)
    pdf.add_reference_page()

    parsed_data = parse_nmap_output("nmap_output.txt")

    # Prepare summary data
    unique_ports = set()
    total_cves = 0
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    cve_per_ip = {}

    for ip, ports in parsed_data.items():
        cve_per_ip[ip] = 0
        for port, lines in ports.items():
            unique_ports.add(port)
            for line in lines:
                match = re.search(r"(CVE-\d{4}-\d{4,7}|CNVD-\d{4}-\d+|1337DAY-ID-\d+|EDB-ID:\d+)\s+([\d.]+)", line)
                if match:
                    score = float(match.group(2))
                    total_cves += 1
                    cve_per_ip[ip] += 1
                    if score >= 9.0:
                        severity_count["Critical"] += 1
                    elif score >= 7.0:
                        severity_count["High"] += 1
                    elif score >= 4.0:
                        severity_count["Medium"] += 1
                    else:
                        severity_count["Low"] += 1

    summary = {
        "total_hosts": len(parsed_data),
        "total_ports": len(unique_ports),
        "total_cves": total_cves,
        "severity": severity_count
    }

    pdf.add_summary_page(summary, cve_per_ip)

    # Add report content
    for ip, ports in parsed_data.items():
        pdf.add_host_section(ip, ports)

    pdf.output(f"nmap_report_{sanitized_company_name}.pdf")
