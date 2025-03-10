import java.io.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;

/**
 * REST API for the Network Scanner module.
 * This class provides HTTP endpoints for the frontend to access the NetworkScanner functionality.
 */
public class NetworkScannerAPI {
    private static final int PORT = 8090;
    private static HttpServer server;
    private static CyberSecurityRiskAnalyzer analyzer;
    
    /**
     * Send HTTP response
     */
    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Start the API server
     */
    public static void startServer() throws IOException {
        // Initialize with default constructor, API key will be set from main method
        analyzer = new CyberSecurityRiskAnalyzer();
        server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // Create context for network scanning endpoint
        server.createContext("/api/scan/network", new NetworkScanHandler());
        
        // Create context for VirusTotal scanning endpoint
        server.createContext("/api/scan/virustotal", new VirusTotalScanHandler());
        
        // Create context for vulnerability assessment endpoint
        server.createContext("/api/scan/vulnerability", new VulnerabilityAssessmentHandler());
        
        // Set executor
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        
        System.out.println("Network Scanner API server started on port " + PORT);
    }
    
    /**
     * Stop the API server
     */
    public static void stopServer() {
        if (server != null) {
            server.stop(0);
            System.out.println("Network Scanner API server stopped");
        }
    }
    
    /**
     * Handler for VirusTotal scan requests
     */
    static class VirusTotalScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // Set CORS headers
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type,Authorization");
                
                // Handle OPTIONS request for CORS preflight
                if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                
                // Only accept POST requests
                if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                    sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}\n");
                    return;
                }
                
                // Parse request body
                String requestBody = readRequestBody(exchange);
                Map<String, String> params = parseJsonRequest(requestBody);
                
                // Extract scan parameters
                String targetType = params.getOrDefault("targetType", "ip");
                String target = params.getOrDefault("target", "");
                String apiKey = params.getOrDefault("apiKey", "");
                
                if (target.isEmpty()) {
                    sendResponse(exchange, 400, "{\"error\":\"Target is required\"}\n");
                    return;
                }
                
                if (apiKey.isEmpty()) {
                    sendResponse(exchange, 400, "{\"error\":\"API key is required\"}\n");
                    return;
                }
                
                // Create a VirusTotal scanner with the provided API key
                VirusTotalScanner scanner = new VirusTotalScanner(apiKey);
                
                // Perform the scan based on target type
                List<VirusTotalScanner.ScanResult> results;
                switch (targetType.toLowerCase()) {
                    case "url":
                        results = scanner.scanURL(target);
                        break;
                    case "domain":
                        results = scanner.scanDomain(target);
                        break;
                    case "ip":
                    default:
                        results = scanner.scanIP(target);
                        break;
                }
                
                // Convert results to JSON
                String responseJson = formatVirusTotalResultsAsJson(results);
                
                // Send response
                sendResponse(exchange, 200, responseJson);
                
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, "{\"error\":\"Internal server error: " + e.getMessage() + "\"}\n");
            }
        }
        
        /**
         * Format VirusTotal scan results as JSON
         */
        private String formatVirusTotalResultsAsJson(List<VirusTotalScanner.ScanResult> results) {
            int maliciousCount = 0;
            int suspiciousCount = 0;
            
            // Count malicious and suspicious results
            for (VirusTotalScanner.ScanResult result : results) {
                if (result.getSeverity().equalsIgnoreCase("Critical") || 
                    result.getSeverity().equalsIgnoreCase("High")) {
                    maliciousCount++;
                } else if (result.getSeverity().equalsIgnoreCase("Medium")) {
                    suspiciousCount++;
                }
            }
            
            StringBuilder json = new StringBuilder();
            json.append("{\"malicious\":" + maliciousCount + ",");
            json.append("\"suspicious\":" + suspiciousCount + ",");
            json.append("\"detections\":[");
            
            // Add detection details
            for (int i = 0; i < results.size(); i++) {
                VirusTotalScanner.ScanResult result = results.get(i);
                json.append("{\"engine\":\"VirusTotal\",");
                json.append("\"result\":\"" + result.getSeverity() + "\",");
                json.append("\"category\":\"" + result.getDescription() + "\"");
                json.append("}");
                
                if (i < results.size() - 1) {
                    json.append(",");
                }
            }
            
            json.append("]}");
            return json.toString();
        }
        
        /**
         * Read the request body as a string
         */
        private String readRequestBody(HttpExchange exchange) throws IOException {
            try (InputStream inputStream = exchange.getRequestBody();
                 ByteArrayOutputStream result = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                
                return result.toString(StandardCharsets.UTF_8.name());
            }
        }
        
        /**
         * Parse JSON request into a map
         */
        private Map<String, String> parseJsonRequest(String json) {
            Map<String, String> result = new HashMap<>();
            
            // Simple JSON parsing - in a real app, use a proper JSON library
            if (json.startsWith("{") && json.endsWith("}")) {
                // Remove braces
                json = json.substring(1, json.length() - 1);
                
                // Split by commas not inside quotes
                String[] pairs = json.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
                
                for (String pair : pairs) {
                    // Split by colon not inside quotes
                    String[] keyValue = pair.split(":(?=([^\"]*\"[^\"]*\")*[^\"]*$)", 2);
                    if (keyValue.length == 2) {
                        String key = keyValue[0].trim();
                        String value = keyValue[1].trim();
                        
                        // Remove quotes if present
                        if (key.startsWith("\"") && key.endsWith("\"")) {
                            key = key.substring(1, key.length() - 1);
                        }
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        
                        result.put(key, value);
                    }
                }
            }
            
            return result;
        }
        
        /**
         * Send HTTP response
         */
        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }
    
    /**
     * Handler for vulnerability assessment requests
     */
    static class VulnerabilityAssessmentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // Set CORS headers
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type,Authorization");
                
                // Handle OPTIONS request for CORS preflight
                if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                
                // Only accept POST requests
                if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                    sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}\n");
                    return;
                }
                
                // Parse request body
                String requestBody = readRequestBody(exchange);
                Map<String, String> params = parseJsonRequest(requestBody);
                
                // Extract assessment parameters
                String target = params.getOrDefault("target", "");
                String assessmentType = params.getOrDefault("assessmentType", "all");
                
                if (target.isEmpty()) {
                    sendResponse(exchange, 400, "{\"error\":\"Target is required\"}\n");
                    return;
                }
                
                // Get the vulnerability database
                VulnerabilityDatabase vulnDb = VulnerabilityDatabase.getInstance();
                
                // Get vulnerabilities based on assessment type
                List<VulnerabilityDatabase.Vulnerability> vulnerabilities = new ArrayList<>();
                
                switch (assessmentType.toLowerCase()) {
                    case "cve":
                        vulnerabilities = vulnDb.getCVEVulnerabilities("web_server");
                        break;
                    case "cwe":
                        vulnerabilities = vulnDb.getCWEVulnerabilities("injection");
                        break;
                    case "nist":
                        vulnerabilities = vulnDb.getNISTVulnerabilities("access_control");
                        break;
                    case "all":
                    default:
                        vulnerabilities = vulnDb.searchVulnerabilities(target);
                        break;
                }
                
                // Convert results to JSON
                String responseJson = formatVulnerabilitiesAsJson(vulnerabilities);
                
                // Send response
                sendResponse(exchange, 200, responseJson);
                
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, "{\"error\":\"Internal server error: " + e.getMessage() + "\"}\n");
            }
        }
        
        /**
         * Format vulnerabilities as JSON
         */
        private String formatVulnerabilitiesAsJson(List<VulnerabilityDatabase.Vulnerability> vulnerabilities) {
            StringBuilder json = new StringBuilder();
            json.append("{\"vulnerabilities\":[");
            
            for (int i = 0; i < vulnerabilities.size(); i++) {
                VulnerabilityDatabase.Vulnerability vuln = vulnerabilities.get(i);
                json.append("{\"id\":\"" + vuln.getId() + "\",");
                json.append("\"description\":\"" + vuln.getDescription() + "\",");
                json.append("\"severity\":\"" + vuln.getSeverity() + "\",");
                json.append("\"category\":\"" + String.join(", ", vuln.getTags()) + "\",");
                json.append("\"remediation\":\"" + vuln.getRemediation() + "\"");
                json.append("}");
                
                if (i < vulnerabilities.size() - 1) {
                    json.append(",");
                }
            }
            
            json.append("]}");
            return json.toString();
        }
        
        /**
         * Read the request body as a string
         */
        private String readRequestBody(HttpExchange exchange) throws IOException {
            try (InputStream inputStream = exchange.getRequestBody();
                 ByteArrayOutputStream result = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                
                return result.toString(StandardCharsets.UTF_8.name());
            }
        }
        
        /**
         * Parse JSON request into a map
         */
        private Map<String, String> parseJsonRequest(String json) {
            Map<String, String> result = new HashMap<>();
            
            // Simple JSON parsing - in a real app, use a proper JSON library
            if (json.startsWith("{") && json.endsWith("}")) {
                // Remove braces
                json = json.substring(1, json.length() - 1);
                
                // Split by commas not inside quotes
                String[] pairs = json.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
                
                for (String pair : pairs) {
                    // Split by colon not inside quotes
                    String[] keyValue = pair.split(":(?=([^\"]*\"[^\"]*\")*[^\"]*$)", 2);
                    if (keyValue.length == 2) {
                        String key = keyValue[0].trim();
                        String value = keyValue[1].trim();
                        
                        // Remove quotes if present
                        if (key.startsWith("\"") && key.endsWith("\"")) {
                            key = key.substring(1, key.length() - 1);
                        }
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        
                        result.put(key, value);
                    }
                }
            }
            
            return result;
        }
        
        /**
         * Send HTTP response
         */
        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }
    
    /**
     * Handler for network scan requests
     */
    static class NetworkScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // Set CORS headers
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type,Authorization");
                
                // Handle OPTIONS request for CORS preflight
                if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                
                // Only accept POST requests
                if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                    sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}\n");
                    return;
                }
                
                // Parse request body
                String requestBody = readRequestBody(exchange);
                Map<String, String> params = parseJsonRequest(requestBody);
                
                // Extract scan parameters
                String host = params.getOrDefault("host", "127.0.0.1");
                int startPort = Integer.parseInt(params.getOrDefault("startPort", "1"));
                int endPort = Integer.parseInt(params.getOrDefault("endPort", "1024"));
                String scanType = params.getOrDefault("scanType", "standard");
                
                // Perform the scan based on scan type
                String responseJson;
                if (scanType.equalsIgnoreCase("syn") && NetworkScanner.isRunningAsAdmin()) {
                    responseJson = performSynScan(host, startPort, endPort);
                } else {
                    responseJson = performStandardScan(host, startPort, endPort);
                }
                
                // Send response
                sendResponse(exchange, 200, responseJson);
                
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, "{\"error\":\"Internal server error: " + e.getMessage() + "\"}\n");
            }
        }
        
        /**
         * Perform a standard TCP connect scan
         */
        private String performStandardScan(String host, int startPort, int endPort) {
            try {
                // Use the NetworkScanner to perform the actual scan
                List<NetworkScanner.ScanResult> scanResults = NetworkScanner.scanPortRange(host, startPort, endPort);
                
                // Get security risks from the risk analyzer
                List<RiskAssessmentEngine.SecurityRisk> risks = analyzer.startNewScan(host, startPort, endPort);
                
                // Convert results to JSON
                return formatScanResultsAsJson(scanResults, risks);
                
            } catch (Exception e) {
                e.printStackTrace();
                return "{\"error\":\"Scan failed: " + e.getMessage() + "\"}\n";
            }
        }
        
        /**
         * Perform a SYN scan (requires admin privileges)
         */
        private String performSynScan(String host, int startPort, int endPort) {
            try {
                // Use the NetworkScanner to perform a SYN scan
                List<NetworkScanner.ScanResult> scanResults = NetworkScanner.synScan(host, startPort, endPort);
                
                // Get security risks from the risk analyzer
                List<RiskAssessmentEngine.SecurityRisk> risks = analyzer.startNewScan(host, startPort, endPort);
                
                // Convert results to JSON
                return formatScanResultsAsJson(scanResults, risks);
                
            } catch (Exception e) {
                e.printStackTrace();
                return "{\"error\":\"SYN scan failed: " + e.getMessage() + "\"}\n";
            }
        }
        
        /**
         * Format scan results as JSON
         */
        private String formatScanResultsAsJson(List<NetworkScanner.ScanResult> scanResults, 
                                             List<RiskAssessmentEngine.SecurityRisk> risks) {
            StringBuilder json = new StringBuilder();
            json.append("{\"ports\":[");
            
            // Add port scan results
            for (int i = 0; i < scanResults.size(); i++) {
                NetworkScanner.ScanResult result = scanResults.get(i);
                json.append("{\"port\":" + result.port + ",");
                json.append("\"service\":\"" + (result.service != null ? result.service : "Unknown") + "\",");
                json.append("\"status\":\"Open\",");
                json.append("\"notes\":\"" + (result.notes != null ? result.notes : "") + "\"");
                json.append("}");
                
                if (i < scanResults.size() - 1) {
                    json.append(",");
                }
            }
            
            json.append("],\"risks\":[");
            
            // Add security risks
            for (int i = 0; i < risks.size(); i++) {
                RiskAssessmentEngine.SecurityRisk risk = risks.get(i);
                json.append("{\"id\":\"" + risk.getId() + "\",");
                json.append("\"description\":\"" + risk.getDescription() + "\",");
                json.append("\"severity\":\"" + risk.getSeverity() + "\",");
                json.append("\"category\":\"" + risk.getCategory() + "\",");
                json.append("\"recommendation\":\"" + risk.getRemediation() + "\"");
                json.append("}");
                
                if (i < risks.size() - 1) {
                    json.append(",");
                }
            }
            
            json.append("]}");
            return json.toString();
        }
        
        /**
         * Read the request body as a string
         */
        private String readRequestBody(HttpExchange exchange) throws IOException {
            try (InputStream inputStream = exchange.getRequestBody();
                 ByteArrayOutputStream result = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                
                return result.toString(StandardCharsets.UTF_8.name());
            }
        }
        
        /**
         * Parse JSON request into a map
         */
        private Map<String, String> parseJsonRequest(String json) {
            Map<String, String> result = new HashMap<>();
            
            // Simple JSON parsing (in a real app, use a proper JSON library)
            if (json != null && !json.isEmpty()) {
                // Remove curly braces
                json = json.trim();
                if (json.startsWith("{")) {
                    json = json.substring(1);
                }
                if (json.endsWith("}")) {
                    json = json.substring(0, json.length() - 1);
                }
                
                // Split by commas not inside quotes
                String[] pairs = json.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
                
                for (String pair : pairs) {
                    // Split by colon not inside quotes
                    String[] keyValue = pair.split(":(?=([^\"]*\"[^\"]*\")*[^\"]*$)", 2);
                    if (keyValue.length == 2) {
                        String key = keyValue[0].trim();
                        String value = keyValue[1].trim();
                        
                        // Remove quotes
                        if (key.startsWith("\"") && key.endsWith("\"")) {
                            key = key.substring(1, key.length() - 1);
                        }
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        
                        result.put(key, value);
                    }
                }
            }
            
            return result;
        }
        

    }
    
    /**
     * Main method to start the API server
     */
    public static void main(String[] args) {
        try {
            // Start the API server
            startServer();
            
            // If API key is provided as argument, configure it
            if (args.length > 0) {
                analyzer.setVirusTotalApiKey(args[0]);
                System.out.println("VirusTotal API key configured.");
            }
            
            System.out.println("Press Ctrl+C to stop the server");
        } catch (Exception e) {
            System.err.println("Failed to start server: " + e.getMessage());
            e.printStackTrace();
        }
    }
}