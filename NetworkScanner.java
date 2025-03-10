import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Network Scanner module for the Cybersecurity Risk Analyzer.
 * This class provides methods to scan networks for open ports, services,
 * and potential vulnerabilities using Java's networking libraries.
 */
public class NetworkScanner {
    private static final int TIMEOUT = 1000; // Connection timeout in milliseconds
    private static final Map<Integer, String> COMMON_SERVICES = initCommonServices();
    
    /**
     * Scan a single port on a target host
     * @param host The target host (IP or hostname)
     * @param port The port to scan
     * @return ScanResult object containing port status and service information
     */
public static ScanResult scanPort(String host, int port) {
        ScanResult result = new ScanResult(port);
        
        try {
            // Create socket with timeout
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            
            // If we get here, the port is open
            result.isOpen = true;
            
            // Try to identify the service
            result.service = identifyService(host, port, socket);
            
            socket.close();
        } catch (ConnectException e) {
            // Connection refused - port is closed
            result.isOpen = false;
        } catch (SocketTimeoutException e) {
            // Connection timed out - port might be filtered
            result.isOpen = false;
            result.notes = "Timed out - port may be filtered";
        } catch (Exception e) {
            // Other exceptions
            result.isOpen = false;
            result.notes = "Error: " + e.getMessage();
        }
        
        return result;
    }
    
    /**
     * Scan a range of ports on a target host
     * @param host The target host (IP or hostname)
     * @param startPort The first port to scan
     * @param endPort The last port to scan
     * @return List of ScanResult objects for open ports
     */
    public static List<ScanResult> scanPortRange(String host, int startPort, int endPort) {
        List<ScanResult> results = new ArrayList<>();
        
        for (int port = startPort; port <= endPort; port++) {
            ScanResult result = scanPort(host, port);
            if (result.isOpen) {
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Scan a range of ports on a target host using multiple threads
     * @param host The target host (IP or hostname)
     * @param startPort The first port to scan
     * @param endPort The last port to scan
     * @param threads Number of threads to use
     * @return List of ScanResult objects for open ports
     */
    public static List<ScanResult> scanPortRangeParallel(String host, int startPort, int endPort, int threads) 
            throws InterruptedException, ExecutionException {
        List<ScanResult> results = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<ScanResult>> futures = new ArrayList<>();
        
        // Submit tasks to executor
        for (int port = startPort; port <= endPort; port++) {
            final int currentPort = port;
            futures.add(executor.submit(() -> scanPort(host, currentPort)));
        }
        
        // Collect results
        for (Future<ScanResult> future : futures) {
            ScanResult result = future.get();
            if (result.isOpen) {
                results.add(result);
            }
        }
        
        executor.shutdown();
        return results;
    }
    
    /**
     * Perform a SYN scan (requires admin privileges)
     * This method attempts to perform a SYN scan using available system tools
     * and falls back to a regular port scan if not possible
     * 
     * @param host The target host (IP or hostname)
     * @param startPort The first port to scan
     * @param endPort The last port to scan
     * @return List of ScanResult objects for open ports
     */
    public static List<ScanResult> synScan(String host, int startPort, int endPort) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            // Check if we're running with admin privileges
            boolean isAdmin = isRunningAsAdmin();
            
            if (isAdmin) {
                // On Windows, try to use built-in nmap if available
                if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                    results = attemptNmapScan(host, startPort, endPort);
                    if (!results.isEmpty()) {
                        return results;
                    }
                }
            }
            
            // If we couldn't perform a true SYN scan, fall back to regular scan
            System.out.println("SYN scan requires admin privileges and native libraries.");
            System.out.println("Falling back to regular TCP connect scan.");
            
            // Use our parallel scanner for better performance
            return scanPortRangeParallel(host, startPort, endPort, 10);
            
        } catch (Exception e) {
            System.err.println("Error during SYN scan: " + e.getMessage());
            ScanResult errorResult = new ScanResult(-1);
            errorResult.notes = "Error during scan: " + e.getMessage();
            results.add(errorResult);
            return results;
        }
    }
    
    /**
     * Check if the application is running with administrator privileges
     */
    public static boolean isRunningAsAdmin() {
        try {
            ProcessBuilder pb;
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                pb = new ProcessBuilder("net", "session");
            } else {
                pb = new ProcessBuilder("id", "-u");
            }
            
            Process process = pb.start();
            int exitCode = process.waitFor();
            
            // On Windows, exit code 0 means admin privileges
            // On Unix, output of "id -u" is 0 for root
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Attempt to use nmap for SYN scanning if available
     */
    private static List<ScanResult> attemptNmapScan(String host, int startPort, int endPort) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            // Build the nmap command for SYN scan
            ProcessBuilder pb = new ProcessBuilder(
                "nmap", "-sS", "-p", startPort + "-" + endPort, host
            );
            
            Process process = pb.start();
            Scanner scanner = new Scanner(process.getInputStream());
            
            // Parse nmap output
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                
                // Look for port lines like "80/tcp open http"
                if (line.contains("/tcp") && line.contains("open")) {
                    try {
                        String[] parts = line.trim().split("\\s+");
                        String portStr = parts[0].split("/")[0];
                        int port = Integer.parseInt(portStr);
                        
                        ScanResult result = new ScanResult(port);
                        result.isOpen = true;
                        
                        // If service info is available
                        if (parts.length > 2) {
                            result.service = parts[2];
                        } else {
                            result.service = COMMON_SERVICES.getOrDefault(port, "Unknown service");
                        }
                        
                        results.add(result);
                    } catch (Exception e) {
                        // Skip lines that don't parse correctly
                    }
                }
            }
            
            scanner.close();
            process.waitFor();
            
        } catch (Exception e) {
            // Nmap not available or error running it
            System.out.println("Nmap not available: " + e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Perform a service detection scan on open ports
     * @param host The target host (IP or hostname)
     * @param openPorts List of open ports to check
     * @return List of ScanResult objects with service information
     */
    public static List<ScanResult> detectServices(String host, List<Integer> openPorts) {
        List<ScanResult> results = new ArrayList<>();
        
        for (int port : openPorts) {
            ScanResult result = scanPort(host, port);
            if (result.isOpen) {
                results.add(result);
            }
        }
        
        return results;
    }
    
    /**
     * Try to identify the service running on a port
     */
    private static String identifyService(String host, int port, Socket socket) {
        // First check common port mappings
        if (COMMON_SERVICES.containsKey(port)) {
            return COMMON_SERVICES.get(port);
        }
        
        // For some protocols, we can try to get a banner
        try {
            // Set a short timeout for banner grabbing
            socket.setSoTimeout(500);
            
            // Try to read the first line from the service
            Scanner scanner = new Scanner(socket.getInputStream());
            String banner = scanner.hasNextLine() ? scanner.nextLine() : null;
            scanner.close();
            
            if (banner != null && !banner.isEmpty()) {
                return "Unknown service (Banner: " + banner + ")";
            }
        } catch (Exception e) {
            // Ignore exceptions during banner grabbing
        }
        
        return "Unknown service";
    }
    
    /**
     * Initialize the map of common port to service mappings
     */
    private static Map<Integer, String> initCommonServices() {
        Map<Integer, String> services = new HashMap<>();
        
        // Add common services
        services.put(20, "FTP Data");
        services.put(21, "FTP Control");
        services.put(22, "SSH");
        services.put(23, "Telnet");
        services.put(25, "SMTP");
        services.put(53, "DNS");
        services.put(80, "HTTP");
        services.put(110, "POP3");
        services.put(115, "SFTP");
        services.put(135, "RPC");
        services.put(139, "NetBIOS");
        services.put(143, "IMAP");
        services.put(443, "HTTPS");
        services.put(445, "SMB");
        services.put(993, "IMAPS");
        services.put(995, "POP3S");
        services.put(1433, "MSSQL");
        services.put(1521, "Oracle");
        services.put(3306, "MySQL");
        services.put(3389, "RDP");
        services.put(5432, "PostgreSQL");
        services.put(5900, "VNC");
        services.put(8080, "HTTP Proxy");
        services.put(8443, "HTTPS Alt");
        
        return services;
    }
    
    /**
     * Perform a traceroute to the target host
     * @param host The target host (IP or hostname)
     * @param maxHops Maximum number of hops to trace
     * @return List of hops with timing information
     */
    public static List<String> traceroute(String host, int maxHops) {
        List<String> results = new ArrayList<>();
        
        try {
            InetAddress target = InetAddress.getByName(host);
            results.add("Tracing route to " + host + " [" + target.getHostAddress() + "]\n");
            
            for (int ttl = 1; ttl <= maxHops; ttl++) {
                String hopResult = traceHop(host, ttl);
                results.add(hopResult);
                
                // If we've reached the destination, stop
                if (hopResult.contains(target.getHostAddress())) {
                    break;
                }
            }
        } catch (Exception e) {
            results.add("Error: " + e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Trace a single hop using the system's ping command
     * This is a workaround since Java doesn't support setting TTL directly
     */
    private static String traceHop(String host, int ttl) {
        try {
            // Build the ping command with TTL
            ProcessBuilder pb;
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                pb = new ProcessBuilder("ping", "-n", "1", "-w", "1000", "-i", String.valueOf(ttl), host);
            } else {
                pb = new ProcessBuilder("ping", "-c", "1", "-W", "1", "-t", String.valueOf(ttl), host);
            }
            
            Process process = pb.start();
            Scanner scanner = new Scanner(process.getInputStream());
            
            StringBuilder output = new StringBuilder();
            while (scanner.hasNextLine()) {
                output.append(scanner.nextLine()).append("\n");
            }
            scanner.close();
            
            process.waitFor();
            return ttl + ": " + output.toString().trim();
        } catch (Exception e) {
            return ttl + ": Error: " + e.getMessage();
        }
    }
    
    /**
     * Class to hold the result of a port scan
     */
    public static class ScanResult {
        public int port;
        public boolean isOpen;
        public String service;
        public String notes;
        
        public ScanResult(int port) {
            this.port = port;
            this.isOpen = false;
            this.service = null;
            this.notes = null;
        }
        
        @Override
        public String toString() {
            return "Port " + port + ": " + (isOpen ? "Open" : "Closed") + 
                   (service != null ? " - " + service : "") + 
                   (notes != null ? " (" + notes + ")" : "");
        }
    }
}