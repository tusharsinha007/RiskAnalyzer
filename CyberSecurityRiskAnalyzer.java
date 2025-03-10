import javax.swing.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;

/**
 * Main class for the Cybersecurity Risk Analyzer application.
 * This application scans systems for vulnerabilities and provides security recommendations
 * based on industry standards like NIST and CIS.
 */
public class CyberSecurityRiskAnalyzer {
    private RiskAssessmentEngine riskEngine;
    private String virusTotalApiKey;
    
    /**
     * Constructor for the core functionality without UI components
     */
    public CyberSecurityRiskAnalyzer() {
        // Default constructor - API key will be set later
    }
    
    /**
     * Constructor with VirusTotal API key
     * 
     * @param apiKey The VirusTotal API key
     */
    public CyberSecurityRiskAnalyzer(String apiKey) {
        this.virusTotalApiKey = apiKey;
        this.riskEngine = new RiskAssessmentEngine(apiKey);
    }
    
    /**
     * Sets the VirusTotal API key
     * 
     * @param apiKey The VirusTotal API key
     */
    public void setVirusTotalApiKey(String apiKey) {
        this.virusTotalApiKey = apiKey;
        this.riskEngine = new RiskAssessmentEngine(apiKey);
    }
    
    /**
     * Starts a new security scan on a target host
     * 
     * @param host The target host (IP or hostname)
     * @param startPort The first port to scan
     * @param endPort The last port to scan
     * @return List of identified security risks
     */
    public List<RiskAssessmentEngine.SecurityRisk> startNewScan(String host, int startPort, int endPort) {
        System.out.println("Starting new security scan on " + host + "...");
        
        if (riskEngine == null) {
            if (virusTotalApiKey == null || virusTotalApiKey.isEmpty()) {
                System.err.println("VirusTotal API key not set. Some threat intelligence features will be disabled.");
                riskEngine = new RiskAssessmentEngine("dummy-key");
            } else {
                riskEngine = new RiskAssessmentEngine(virusTotalApiKey);
            }
        }
        
        // Perform the actual risk assessment
        List<RiskAssessmentEngine.SecurityRisk> risks = riskEngine.assessNetworkRisks(host, startPort, endPort);
        
        // Log the results
        System.out.println("Scan completed. Found " + risks.size() + " potential security risks.");
        for (RiskAssessmentEngine.SecurityRisk risk : risks) {
            System.out.println(risk.toString());
        }
        
        return risks;
    }
    
    /**
     * Performs a quick scan with default port range
     * 
     * @param host The target host (IP or hostname)
     * @return List of identified security risks
     */
    public List<RiskAssessmentEngine.SecurityRisk> quickScan(String host) {
        // Quick scan of common ports
        return startNewScan(host, 1, 1024);
    }
    
    public static void main(String[] args) {
        // Launch the desktop application
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            CyberSecurityDesktopApp app = new CyberSecurityDesktopApp();
            app.setVisible(true);
            
            System.out.println("Cybersecurity Risk Analyzer Desktop Application started.");
        });
    }
}