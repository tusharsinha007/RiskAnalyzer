# Cybersecurity Risk Analyzer

A comprehensive desktop application for network security scanning, vulnerability assessment, and risk analysis.

![Cybersecurity Risk Analyzer](resources/lock_icon.png)

## Overview

The Cybersecurity Risk Analyzer is a Java-based desktop application designed to help security professionals and system administrators identify, assess, and mitigate security risks in their network infrastructure. The application provides a user-friendly interface for conducting network scans, vulnerability assessments, and generating detailed security reports.

## Application Screenshots

### Main Dashboard
![Main Dashboard](resources/lock_icon.png)
*The main dashboard provides an overview of system security status, recent scans, and detected vulnerabilities.*

### Network Scanning Interface
![Network Scanner](resources/lock_icon.png)
*The network scanning interface allows users to specify target hosts, port ranges, and scan parameters.*

### Vulnerability Assessment
![Vulnerability Assessment](resources/lock_icon.png)
*The vulnerability assessment view displays detected vulnerabilities with severity ratings and remediation recommendations.*

### Risk Analysis Report
![Risk Analysis](resources/lock_icon.png)
*The risk analysis report provides a comprehensive view of security risks with prioritization based on impact and likelihood.*

## Features

- **Network Scanning**: Scan individual hosts or IP ranges for open ports and running services
- **Vulnerability Assessment**: Identify potential security vulnerabilities based on detected services
- **Risk Analysis**: Evaluate and prioritize security risks based on severity and potential impact
- **VirusTotal Integration**: Scan files and URLs using the VirusTotal API
- **Comprehensive Reporting**: Generate detailed reports of scan results and recommended actions
- **User-Friendly Interface**: Intuitive dashboard with visual representations of security status

## System Requirements

- Java Runtime Environment (JRE) 8 or higher
- Windows, macOS, or Linux operating system
- Internet connection for VirusTotal API integration
- Minimum 4GB RAM recommended
- Administrator privileges for certain scanning features

## Installation

1. Ensure you have Java 8 or higher installed on your system
2. Download the latest release from the releases page
3. Extract the ZIP file to your preferred location
4. Run the application by double-clicking the JAR file or using the command:
   ```
   java -jar CyberSecurityRiskAnalyzer.jar
   ```

## Usage

### Quick Start

1. Launch the application
2. Enter the target host or IP address in the "Host" field
3. Click "Quick Scan" for a basic assessment or configure port ranges for a more detailed scan
4. View results in the Results tab
5. Export reports as needed

![Quick Start Guide](resources/lock_icon.png)
*Step-by-step guide for performing a quick security scan*

### API Key Configuration

For VirusTotal integration:
1. Obtain an API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Enter your API key in the settings panel
3. Save your configuration

![API Configuration](resources/lock_icon.png)
*VirusTotal API key configuration interface*

## Workflow Diagram

![Workflow Diagram](resources/lock_icon.png)
*This diagram illustrates the typical workflow for conducting a complete security assessment using the application.*

## Project Structure

- `CyberSecurityDesktopApp.java` - Main application class with GUI components
- `CyberSecurityRiskAnalyzer.java` - Core functionality for risk analysis
- `NetworkScanner.java` - Network scanning implementation
- `VirusTotalScanner.java` - Integration with VirusTotal API
- `VulnerabilityDatabase.java` - Database of known vulnerabilities
- `RiskAssessmentEngine.java` - Risk evaluation and prioritization
- `NetworkScannerAPI.java` - API for network scanning operations
- `JSONUtil.java` - Utilities for JSON processing
- `IconLoader.java` - Utility for loading application icons
- `data/` - Directory containing vulnerability databases
- `resources/` - Directory containing application resources

## Development

### Building from Source

1. Clone the repository
2. Ensure you have JDK 8 or higher installed
3. Compile the source files:
   ```
   javac *.java
   ```
4. Run the application:
   ```
   java CyberSecurityDesktopApp
   ```

### Architecture Diagram

![Architecture Diagram](resources/lock_icon.png)
*High-level architecture diagram showing the main components and their interactions*

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NIST Cybersecurity Framework
- CWE (Common Weakness Enumeration)
- CVE (Common Vulnerabilities and Exposures)
- VirusTotal API

## Disclaimer

This tool is intended for legitimate security testing and assessment purposes only. Always ensure you have proper authorization before scanning any systems or networks. The developers are not responsible for any misuse or damage caused by this application. 