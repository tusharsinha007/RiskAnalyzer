import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;

/**
 * Risk Assessment Engine for the Cybersecurity Risk Analyzer.
 * This class integrates with NetworkScanner and VirusTotalScanner to identify
 * real security risks based on network scan results and threat intelligence.
 */
public class RiskAssessmentEngine {
    private VulnerabilityDatabase vulnDb;
    private VirusTotalScanner vtScanner;
    
    /**
     * Constructor that initializes the risk assessment engine with necessary components
     * 
     * @param apiKey The VirusTotal API key for threat intelligence
     */
    public RiskAssessmentEngine(String apiKey) {
        this.vulnDb = VulnerabilityDatabase.getInstance();
        this.vtScanner = new VirusTotalScanner(apiKey);
    }
    
    /**
     * Assesses security risks based on open ports and services
     * 
     * @param host The target host (IP or hostname)
     * @param startPort The first port to scan
     * @param endPort The last port to scan
     * @return List of identified security risks
     */
    public List<SecurityRisk> assessNetworkRisks(String host, int startPort, int endPort) {
        List<SecurityRisk> risks = new ArrayList<>();
        
        try {
            // Perform actual port scan
            List<NetworkScanner.ScanResult> scanResults = NetworkScanner.scanPortRange(host, startPort, endPort);
            
            // Analyze each open port for security risks
            for (NetworkScanner.ScanResult result : scanResults) {
                if (result.isOpen) {
                    // Check for known vulnerable services
                    List<SecurityRisk> serviceRisks = assessServiceRisk(host, result.port, result.service);
                    risks.addAll(serviceRisks);
                }
            }
            
            // Check if the host IP is associated with known threats
            try {
                List<VirusTotalScanner.ScanResult> vtResults = vtScanner.scanIP(host);
                for (VirusTotalScanner.ScanResult vtResult : vtResults) {
                    // Convert VirusTotal results to security risks
                    SecurityRisk risk = new SecurityRisk(
                        vtResult.getId(),
                        mapSeverity(vtResult.getSeverity()),
                        "Threat Intelligence: " + vtResult.getDescription(),
                        vtResult.getRemediation(),
                        "Threat Intelligence"
                    );
                    risks.add(risk);
                }
            } catch (IOException e) {
                System.err.println("Error scanning IP with VirusTotal: " + e.getMessage());
            }
            
        } catch (Exception e) {
            System.err.println("Error during network risk assessment: " + e.getMessage());
        }
        
        return risks;
    }
    
    /**
     * Assesses security risks for a specific service running on a port
     * 
     * @param host The target host
     * @param port The port number
     * @param service The identified service
     * @return List of security risks associated with the service
     */
    private List<SecurityRisk> assessServiceRisk(String host, int port, String service) {
        List<SecurityRisk> risks = new ArrayList<>();
        
        // Map of high-risk services and their associated vulnerabilities
        Map<String, List<String>> highRiskServices = new HashMap<>();
        highRiskServices.put("Telnet", List.of("Clear-text authentication", "No encryption"));
        highRiskServices.put("FTP", List.of("Clear-text authentication", "Insecure file transfer"));
        highRiskServices.put("SMB", List.of("Potential for EternalBlue vulnerability", "File sharing exposure"));
        highRiskServices.put("RDP", List.of("Potential for BlueKeep vulnerability", "Brute force attacks"));
        
        // Check if this is a known high-risk service
        if (service != null) {
            for (Map.Entry<String, List<String>> entry : highRiskServices.entrySet()) {
                if (service.contains(entry.getKey())) {
                    // For each vulnerability associated with this service
                    for (String vulnerability : entry.getValue()) {
                        SecurityRisk risk = new SecurityRisk(
                            "SERVICE-" + port + "-" + entry.getKey(),
                            service.contains("Telnet") || service.contains("FTP") ? 
                                SecurityRisk.Severity.HIGH : SecurityRisk.Severity.MEDIUM,
                            vulnerability + " on port " + port + " (" + service + ")",
                            "Disable " + entry.getKey() + " service or replace with a secure alternative",
                            "Network Service"
                        );
                        risks.add(risk);
                    }
                }
            }
        }
        
        // Check for uncommon ports running common services (potential backdoors)
        Map<String, List<Integer>> commonServicePorts = new HashMap<>();
        commonServicePorts.put("HTTP", List.of(80, 8080, 8000));
        commonServicePorts.put("HTTPS", List.of(443, 8443));
        commonServicePorts.put("SSH", List.of(22));
        commonServicePorts.put("FTP", List.of(21));
        
        if (service != null) {
            for (Map.Entry<String, List<Integer>> entry : commonServicePorts.entrySet()) {
                if (service.contains(entry.getKey()) && !entry.getValue().contains(port)) {
                    SecurityRisk risk = new SecurityRisk(
                        "UNCOMMON-PORT-" + port,
                        SecurityRisk.Severity.MEDIUM,
                        entry.getKey() + " service running on uncommon port " + port,
                        "Verify this is an intended configuration and not a backdoor",
                        "Unusual Configuration"
                    );
                    risks.add(risk);
                }
            }
        }
        
        // Query vulnerability database for known vulnerabilities
        List<VulnerabilityDatabase.Vulnerability> vulns = vulnDb.searchVulnerabilities(service);
        for (VulnerabilityDatabase.Vulnerability vuln : vulns) {
            SecurityRisk risk = new SecurityRisk(
                vuln.getId(),
                mapSeverity(vuln.getSeverity()),
                vuln.getDescription() + " affecting " + service + " on port " + port,
                vuln.getRemediation(),
                "Known Vulnerability"
            );
            risks.add(risk);
        }
        
        return risks;
    }
    
    /**
     * Maps severity strings to SecurityRisk.Severity enum values
     * 
     * @param severityStr The severity string
     * @return The corresponding Severity enum value
     */
    private SecurityRisk.Severity mapSeverity(String severityStr) {
        if (severityStr == null) return SecurityRisk.Severity.MEDIUM;
        
        switch (severityStr.toUpperCase()) {
            case "CRITICAL":
                return SecurityRisk.Severity.CRITICAL;
            case "HIGH":
                return SecurityRisk.Severity.HIGH;
            case "MEDIUM":
                return SecurityRisk.Severity.MEDIUM;
            case "LOW":
                return SecurityRisk.Severity.LOW;
            default:
                return SecurityRisk.Severity.MEDIUM;
        }
    }
    
    /**
     * Class representing a security risk identified by the risk assessment engine
     */
    public static class SecurityRisk {
        private String id;
        private Severity severity;
        private String description;
        private String remediation;
        private String category;
        
        public enum Severity {
            CRITICAL, HIGH, MEDIUM, LOW
        }
        
        public SecurityRisk(String id, Severity severity, String description, String remediation, String category) {
            this.id = id;
            this.severity = severity;
            this.description = description;
            this.remediation = remediation;
            this.category = category;
        }
        
        public String getId() {
            return id;
        }
        
        public Severity getSeverity() {
            return severity;
        }
        
        public String getSeverityString() {
            return severity.toString();
        }
        
        public String getDescription() {
            return description;
        }
        
        public String getRemediation() {
            return remediation;
        }
        
        public String getCategory() {
            return category;
        }
        
        @Override
        public String toString() {
            return severity + " Risk: " + description + " (" + id + ")";
        }
    }
}