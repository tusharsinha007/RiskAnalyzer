import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Utility class for interacting with the VirusTotal API.
 * This class provides methods to scan IP addresses, domains, and URLs using VirusTotal's API.
 * Simplified for the core functionality needed by the application.
 */
public class VirusTotalScanner {
    private static final String API_URL = "https://www.virustotal.com/api/v3/";
    private String apiKey;
    
    /**
     * Constructor that takes a VirusTotal API key.
     * 
     * @param apiKey The VirusTotal API key
     */
    public VirusTotalScanner(String apiKey) {
        this.apiKey = apiKey;
    }
    
    /**
     * Scans an IP address using VirusTotal API.
     * 
     * @param ipAddress The IP address to scan
     * @return A list of scan results
     * @throws IOException If there's an error with the HTTP connection
     */
    public List<ScanResult> scanIP(String ipAddress) throws IOException {
        String endpoint = "ip_addresses/" + ipAddress;
        String response = sendRequest(endpoint, "GET", null);
        return parseResponse(response);
    }
    
    /**
     * Scans a domain using VirusTotal API.
     * 
     * @param domain The domain to scan
     * @return A list of scan results
     * @throws IOException If there's an error with the HTTP connection
     */
    public List<ScanResult> scanDomain(String domain) throws IOException {
        String endpoint = "domains/" + domain;
        String response = sendRequest(endpoint, "GET", null);
        return parseResponse(response);
    }
    
    /**
     * Scans a URL using VirusTotal API.
     * 
     * @param url The URL to scan
     * @return A list of scan results
     * @throws IOException If there's an error with the HTTP connection
     */
    public List<ScanResult> scanURL(String url) throws IOException {
        // Submit the URL for analysis
        String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8.toString());
        String submitEndpoint = "urls";
        String urlParam = "url=" + encodedUrl;
        
        String response = sendRequest(submitEndpoint, "POST", urlParam);
        return parseResponse(response);
    }
    
    /**
     * Sends an HTTP request to the VirusTotal API.
     * 
     * @param endpoint The API endpoint
     * @param method The HTTP method (GET or POST)
     * @param body The request body for POST requests
     * @return The response from the API as a string
     * @throws IOException If there's an error with the HTTP connection
     */
    private String sendRequest(String endpoint, String method, String body) throws IOException {
        URL url = new URL(API_URL + endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("x-apikey", apiKey);
        connection.setRequestProperty("Accept", "application/json");
        
        if (method.equals("POST") && body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
        }
        
        int responseCode = connection.getResponseCode();
        if (responseCode >= 400) {
            throw new IOException("HTTP error code: " + responseCode);
        }
        
        StringBuilder response = new StringBuilder();
        try (Scanner scanner = new Scanner(connection.getInputStream(), StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
            }
        }
        
        return response.toString();
    }
    
    /**
     * Parses the JSON response from VirusTotal API and converts it to a list of scan results.
     * This implementation extracts actual data from the VirusTotal API response.
     * 
     * @param jsonResponse The JSON response from the API
     * @return A list of scan results
     */
    private List<ScanResult> parseResponse(String jsonResponse) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            // Check if the response contains data
            if (jsonResponse == null || jsonResponse.isEmpty()) {
                results.add(new ScanResult(
                    "VT-ERROR",
                    "Medium",
                    "Empty response from VirusTotal API",
                    "Check your API key and internet connection"
                ));
                return results;
            }
            
            // Check for error response using our JSONUtil
            if (JSONUtil.hasError(jsonResponse)) {
                String errorMsg = JSONUtil.getErrorMessage(jsonResponse);
                if (errorMsg == null) {
                    errorMsg = "Error from VirusTotal API";
                }
                
                results.add(new ScanResult(
                    "VT-ERROR",
                    "Medium",
                    errorMsg,
                    "Check your API key and request parameters"
                ));
                return results;
            }
            
            // Extract data from the response
            String dataObject = JSONUtil.getJSONObject(jsonResponse, "data");
            if (dataObject == null) {
                results.add(new ScanResult(
                    "VT-ERROR",
                    "Medium",
                    "Invalid response format from VirusTotal API",
                    "Check the VirusTotal API documentation for response format changes"
                ));
                return results;
            }
            
            // Extract attributes object
            String attributesObject = JSONUtil.getJSONObject(dataObject, "attributes");
            if (attributesObject == null) {
                results.add(new ScanResult(
                    "VT-ERROR",
                    "Medium",
                    "Missing attributes in VirusTotal API response",
                    "Check the VirusTotal API documentation for response format changes"
                ));
                return results;
            }
            
            // Extract last_analysis_stats object which contains detection counts
            String statsObject = JSONUtil.getJSONObject(attributesObject, "last_analysis_stats");
            
            // Check for malicious indicators
            int maliciousCount = 0;
            int suspiciousCount = 0;
            
            if (statsObject != null) {
                maliciousCount = JSONUtil.getInt(statsObject, "malicious");
                suspiciousCount = JSONUtil.getInt(statsObject, "suspicious");
            }
            
            // Determine severity based on malicious and suspicious counts
            String severity;
            String description;
            String remediation;
            
            if (maliciousCount > 5) {
                severity = "Critical";
                description = "High threat detected: " + maliciousCount + " security vendors flagged this as malicious";
                remediation = "Immediately block this IP/domain and investigate any connections";
            } else if (maliciousCount > 0) {
                severity = "High";
                description = "Threat detected: " + maliciousCount + " security vendors flagged this as malicious";
                remediation = "Block this IP/domain and investigate any connections";
            } else if (suspiciousCount > 0) {
                severity = "Medium";
                description = "Suspicious activity detected: " + suspiciousCount + " security vendors flagged this as suspicious";
                remediation = "Monitor this IP/domain and consider blocking if not business-critical";
            } else {
                severity = "Low";
                description = "No threats detected by VirusTotal";
                remediation = "No action required, but continue monitoring";
            }
            
            // Add the main result
            String id = JSONUtil.getString(dataObject, "id");
            if (id == null) {
                id = "VT-" + System.currentTimeMillis();
            }
            
            results.add(new ScanResult(
                id,
                severity,
                description,
                remediation
            ));
            
            // Extract last_analysis_results which contains vendor-specific detections
            String analysisResults = JSONUtil.getJSONObject(attributesObject, "last_analysis_results");
            if (analysisResults != null) {
                // Use our utility to extract vendor data
                Map<String, String> vendorResults = JSONUtil.extractSecurityVendors(attributesObject);
                
                // Add results from major security vendors if they detected something
                for (Map.Entry<String, String> entry : vendorResults.entrySet()) {
                    String vendor = entry.getKey();
                    String category = entry.getValue();
                    
                    if (category != null && (category.equalsIgnoreCase("malicious") || 
                                             category.equalsIgnoreCase("suspicious"))) {
                        results.add(new ScanResult(
                            "VT-" + vendor,
                            "High",
                            vendor + " detected a threat: " + category,
                            "Review the specific threat details in the VirusTotal dashboard"
                        ));
                    }
                }
            }
            
        } catch (Exception e) {
            // If anything goes wrong with parsing, add an error result
            results.add(new ScanResult(
                "VT-PARSE-ERROR",
                "Medium",
                "Error parsing VirusTotal response: " + e.getMessage(),
                "Check the VirusTotal API documentation for response format changes"
            ));
        }
        
        // If no results were added, add a default result
        if (results.isEmpty()) {
            results.add(new ScanResult(
                "VT-SCAN",
                "Low",
                "VirusTotal scan completed with no significant findings",
                "No action required"
            ));
        }
        
        return results;
    }
    
    /**
     * Inner class to represent a scan result from VirusTotal.
     */
    public static class ScanResult {
        private String id;
        private String severity;
        private String description;
        private String remediation;
        
        public ScanResult(String id, String severity, String description, String remediation) {
            this.id = id;
            this.severity = severity;
            this.description = description;
            this.remediation = remediation;
        }
        
        public String getId() {
            return id;
        }
        
        public String getSeverity() {
            return severity;
        }
        
        public String getDescription() {
            return description;
        }
        
        public String getRemediation() {
            return remediation;
        }
    }
}