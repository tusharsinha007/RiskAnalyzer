import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;

/**
 * Main class for the Cybersecurity Risk Analyzer Desktop Application.
 * This class provides a Swing-based GUI for the cybersecurity risk analysis functionality.
 */
public class CyberSecurityDesktopApp extends JFrame {
    private CyberSecurityRiskAnalyzer analyzer;
    private JTextField hostField;
    private JTextField startPortField;
    private JTextField endPortField;
    private JTextField apiKeyField;
    private JTextArea resultsArea;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JProgressBar scanProgressBar;
    private JTabbedPane tabbedPane;
    private JPanel dashboardPanel;
    private JPanel scanPanel;
    private JPanel resultsPanel;
    private JPanel vulnerabilityPanel;
    
    /**
     * Constructor - initializes the GUI components
     */
    public CyberSecurityDesktopApp() {
        // Initialize the analyzer
        analyzer = new CyberSecurityRiskAnalyzer();
        
        // Set up the main frame
        setTitle("Cybersecurity Risk Analyzer");
        setSize(900, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        // Set application icon - using the custom icon from resources
        setIconImage(IconLoader.loadIconAsImage("resources/Screenshot 2025-03-10 182008.ico"));
        
        // Create the tabbed pane
        tabbedPane = new JTabbedPane();
        
        // Create the panels for each tab
        createDashboardPanel();
        createScanPanel();
        createResultsPanel();
        createVulnerabilityPanel();
        
        // Add the panels to the tabbed pane
        tabbedPane.addTab("Dashboard", new JScrollPane(dashboardPanel));
        tabbedPane.addTab("Network Scan", new JScrollPane(scanPanel));
        tabbedPane.addTab("Scan Results", new JScrollPane(resultsPanel));
        tabbedPane.addTab("Vulnerability Assessment", new JScrollPane(vulnerabilityPanel));
        
        // Add the tabbed pane to the frame
        add(tabbedPane, BorderLayout.CENTER);
        
        // Create the menu bar
        createMenuBar();
    }
    
    /**
     * Creates the menu bar
     */
    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        
        // File menu
        JMenu fileMenu = new JMenu("File");
        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exitItem);
        
        // Scan menu
        JMenu scanMenu = new JMenu("Scan");
        JMenuItem quickScanItem = new JMenuItem("Quick Scan");
        quickScanItem.addActionListener(e -> performQuickScan());
        JMenuItem fullScanItem = new JMenuItem("Full Scan");
        fullScanItem.addActionListener(e -> performFullScan());
        scanMenu.add(quickScanItem);
        scanMenu.add(fullScanItem);
        
        // Help menu
        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> showAboutDialog());
        helpMenu.add(aboutItem);
        
        // Add menus to menu bar
        menuBar.add(fileMenu);
        menuBar.add(scanMenu);
        menuBar.add(helpMenu);
        
        // Set the menu bar
        setJMenuBar(menuBar);
    }
    
    /**
     * Creates the dashboard panel
     */
    private void createDashboardPanel() {
        dashboardPanel = new JPanel(new BorderLayout());
        dashboardPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Dashboard header
        JPanel headerPanel = new JPanel(new BorderLayout());
        JLabel headerLabel = new JLabel("Security Dashboard");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        JButton startScanBtn = new JButton("Start New Scan");
        startScanBtn.addActionListener(e -> tabbedPane.setSelectedIndex(1)); // Switch to scan tab
        headerPanel.add(headerLabel, BorderLayout.WEST);
        headerPanel.add(startScanBtn, BorderLayout.EAST);
        dashboardPanel.add(headerPanel, BorderLayout.NORTH);
        
        // Dashboard content - summary cards
        JPanel cardsPanel = new JPanel(new GridLayout(2, 2, 15, 15));
        
        // Card 1 - Network Security
        JPanel card1 = createSummaryCard("Network Security", "0", "Open Ports");
        cardsPanel.add(card1);
        
        // Card 2 - Vulnerabilities
        JPanel card2 = createSummaryCard("Vulnerabilities", "0", "Detected");
        cardsPanel.add(card2);
        
        // Card 3 - Threat Intelligence
        JPanel card3 = createSummaryCard("Threat Intelligence", "0", "Threats");
        cardsPanel.add(card3);
        
        // Card 4 - Risk Score
        JPanel card4 = createSummaryCard("Risk Score", "N/A", "Overall");
        cardsPanel.add(card4);
        
        dashboardPanel.add(cardsPanel, BorderLayout.CENTER);
    }
    
    /**
     * Creates a summary card for the dashboard
     */
    private JPanel createSummaryCard(String title, String count, String subtitle) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        
        JLabel countLabel = new JLabel(count);
        countLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        countLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        JLabel subtitleLabel = new JLabel(subtitle);
        subtitleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(countLabel, BorderLayout.CENTER);
        contentPanel.add(subtitleLabel, BorderLayout.SOUTH);
        
        card.add(titleLabel, BorderLayout.NORTH);
        card.add(contentPanel, BorderLayout.CENTER);
        
        return card;
    }
    
    /**
     * Creates the scan panel
     */
    private void createScanPanel() {
        scanPanel = new JPanel(new BorderLayout());
        scanPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Scan header
        JLabel headerLabel = new JLabel("Network Scan");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        scanPanel.add(headerLabel, BorderLayout.NORTH);
        
        // Scan form
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Scan Configuration"),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Host field
        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(new JLabel("Target Host:"), gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        hostField = new JTextField("localhost");
        formPanel.add(hostField, gbc);
        
        // Start port field
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Start Port:"), gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        startPortField = new JTextField("1");
        formPanel.add(startPortField, gbc);
        
        // End port field
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("End Port:"), gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        endPortField = new JTextField("1024");
        formPanel.add(endPortField, gbc);
        
        // VirusTotal API key field
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("VirusTotal API Key:"), gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        apiKeyField = new JTextField();
        formPanel.add(apiKeyField, gbc);
        
        // Scan buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton quickScanButton = new JButton("Quick Scan");
        quickScanButton.addActionListener(e -> performQuickScan());
        JButton fullScanButton = new JButton("Full Scan");
        fullScanButton.addActionListener(e -> performFullScan());
        
        buttonPanel.add(quickScanButton);
        buttonPanel.add(fullScanButton);
        
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        formPanel.add(buttonPanel, gbc);
        
        // Progress bar
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        scanProgressBar = new JProgressBar(0, 100);
        scanProgressBar.setStringPainted(true);
        scanProgressBar.setString("Ready");
        formPanel.add(scanProgressBar, gbc);
        
        scanPanel.add(formPanel, BorderLayout.CENTER);
    }
    
    /**
     * Creates the results panel
     */
    private void createResultsPanel() {
        resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Results header
        JLabel headerLabel = new JLabel("Scan Results");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        resultsPanel.add(headerLabel, BorderLayout.NORTH);
        
        // Results table
        String[] columnNames = {"ID", "Severity", "Description", "Remediation", "Category"};
        tableModel = new DefaultTableModel(columnNames, 0);
        resultsTable = new JTable(tableModel);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setAutoCreateRowSorter(true);
        
        // Set column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(300);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(120);
        
        JScrollPane scrollPane = new JScrollPane(resultsTable);
        resultsPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Export button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton exportButton = new JButton("Export Results");
        exportButton.addActionListener(e -> exportResults());
        buttonPanel.add(exportButton);
        resultsPanel.add(buttonPanel, BorderLayout.SOUTH);
    }
    
    /**
     * Creates the vulnerability panel
     */
    private void createVulnerabilityPanel() {
        vulnerabilityPanel = new JPanel(new BorderLayout());
        vulnerabilityPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Vulnerability header
        JLabel headerLabel = new JLabel("Vulnerability Assessment");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        vulnerabilityPanel.add(headerLabel, BorderLayout.NORTH);
        
        // Vulnerability content
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Risk Resolution"),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        // Create risk categories
        JPanel riskCategoriesPanel = new JPanel();
        riskCategoriesPanel.setLayout(new BoxLayout(riskCategoriesPanel, BoxLayout.Y_AXIS));
        
        // Critical risk category
        JPanel criticalPanel = createRiskCategory("Critical Risk Resolution");
        riskCategoriesPanel.add(criticalPanel);
        
        // Add some sample risk items
        criticalPanel.add(createRiskItem(
            "SQL Injection",
            "Flaws that allow attackers to inject SQL commands into input fields, potentially accessing or modifying database data.",
            new String[] {
                "Implement prepared statements with parameterized queries",
                "Use input validation and sanitization",
                "Apply least privilege database accounts",
                "Use stored procedures",
                "Implement Web Application Firewall (WAF)"
            }
        ));
        
        // High risk category
        JPanel highPanel = createRiskCategory("High Risk Resolution");
        riskCategoriesPanel.add(highPanel);
        
        // Add some sample risk items
        highPanel.add(createRiskItem(
            "Broken Authentication",
            "Flaws in authentication mechanisms that allow attackers to compromise passwords, keys, or session tokens.",
            new String[] {
                "Implement multi-factor authentication (MFA)",
                "Use secure password hashing algorithms (bcrypt, Argon2)",
                "Enforce strong password policies",
                "Implement account lockout mechanisms",
                "Use secure session management with proper timeout settings"
            }
        ));
        
        // Medium risk category
        JPanel mediumPanel = createRiskCategory("Medium Risk Resolution");
        riskCategoriesPanel.add(mediumPanel);
        
        // Add some sample risk items
        mediumPanel.add(createRiskItem(
            "Cross-Site Scripting (XSS)",
            "Vulnerabilities that allow attackers to inject client-side scripts into web pages viewed by other users.",
            new String[] {
                "Implement Content Security Policy (CSP)",
                "Use output encoding for the correct context",
                "Sanitize user input",
                "Use modern frameworks that automatically escape XSS",
                "Validate and sanitize HTML input"
            }
        ));
        
        // Add the risk categories to the content panel
        JScrollPane scrollPane = new JScrollPane(riskCategoriesPanel);
        contentPanel.add(scrollPane, BorderLayout.CENTER);
        
        vulnerabilityPanel.add(contentPanel, BorderLayout.CENTER);
    }
    
    /**
     * Creates a risk category panel
     */
    private JPanel createRiskCategory(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        return panel;
    }
    
    /**
     * Creates a risk item panel
     */
    private JPanel createRiskItem(String title, String description, String[] resolutionSteps) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Title
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(titleLabel);
        
        // Description
        JLabel descLabel = new JLabel("<html><b>Description:</b> " + description + "</html>");
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(descLabel);
        
        // Resolution steps
        JLabel resolutionLabel = new JLabel("<html><b>Resolution Steps:</b></html>");
        resolutionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(resolutionLabel);
        
        // Add resolution steps as a list
        JPanel stepsPanel = new JPanel();
        stepsPanel.setLayout(new BoxLayout(stepsPanel, BoxLayout.Y_AXIS));
        stepsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        for (int i = 0; i < resolutionSteps.length; i++) {
            JLabel stepLabel = new JLabel("<html>" + (i + 1) + ". " + resolutionSteps[i] + "</html>");
            stepLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            stepsPanel.add(stepLabel);
        }
        
        panel.add(stepsPanel);
        
        return panel;
    }
    
    /**
     * Performs a quick scan with default port range
     */
    private void performQuickScan() {
        String host = hostField.getText();
        String apiKey = apiKeyField.getText();
        
        if (!apiKey.isEmpty()) {
            analyzer.setVirusTotalApiKey(apiKey);
        }
        
        // Update UI
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setString("Scanning...");
        
        // Run scan in background thread
        SwingWorker<List<RiskAssessmentEngine.SecurityRisk>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<RiskAssessmentEngine.SecurityRisk> doInBackground() throws Exception {
                return analyzer.quickScan(host);
            }
            
            @Override
            protected void done() {
                try {
                    List<RiskAssessmentEngine.SecurityRisk> risks = get();
                    updateResults(risks);
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setValue(100);
                    scanProgressBar.setString("Scan completed");
                    
                    // Switch to results tab
                    tabbedPane.setSelectedIndex(2);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(CyberSecurityDesktopApp.this,
                        "Error during scan: " + e.getMessage(),
                        "Scan Error",
                        JOptionPane.ERROR_MESSAGE);
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setValue(0);
                    scanProgressBar.setString("Scan failed");
                }
            }
        };
        
        worker.execute();
    }
    
    /**
     * Performs a full scan with user-specified port range
     */
    private void performFullScan() {
        String host = hostField.getText();
        String apiKey = apiKeyField.getText();
        int startPort, endPort;
        
        try {
            startPort = Integer.parseInt(startPortField.getText());
            endPort = Integer.parseInt(endPortField.getText());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                "Please enter valid port numbers",
                "Input Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (!apiKey.isEmpty()) {
            analyzer.setVirusTotalApiKey(apiKey);
        }
        
        // Update UI
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setString("Scanning...");
        
        // Run scan in background thread
        SwingWorker<List<RiskAssessmentEngine.SecurityRisk>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<RiskAssessmentEngine.SecurityRisk> doInBackground() throws Exception {
                return analyzer.startNewScan(host, startPort, endPort);
            }
            
            @Override
            protected void done() {
                try {
                    List<RiskAssessmentEngine.SecurityRisk> risks = get();
                    updateResults(risks);
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setValue(100);
                    scanProgressBar.setString("Scan completed");
                    
                    // Switch to results tab
                    tabbedPane.setSelectedIndex(2);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(CyberSecurityDesktopApp.this,
                        "Error during scan: " + e.getMessage(),
                        "Scan Error",
                        JOptionPane.ERROR_MESSAGE);
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setValue(0);
                    scanProgressBar.setString("Scan failed");
                }
            }
        };
        
        worker.execute();
    }
    
    /**
     * Updates the results table with scan results
     */
    private void updateResults(List<RiskAssessmentEngine.SecurityRisk> risks) {
        // Clear existing results
        tableModel.setRowCount(0);
        
        // Add new results
        for (RiskAssessmentEngine.SecurityRisk risk : risks) {
            tableModel.addRow(new Object[] {
                risk.getId(),
                risk.getSeverity(),
                risk.getDescription(),
                risk.getRemediation(),
                risk.getCategory()
            });
        }
        
        // Update dashboard counts
        updateDashboardCounts(risks);
    }
    
    /**
     * Updates the dashboard counts based on scan results
     */
    private void updateDashboardCounts(List<RiskAssessmentEngine.SecurityRisk> risks) {
        int openPorts = 0;
        int vulnerabilities = risks.size();
        int threats = 0;
        
        // Count threats (critical and high severity risks)
        for (RiskAssessmentEngine.SecurityRisk risk : risks) {
            if (risk.getCategory().contains("Threat Intelligence")) {
                threats++;
            }
        }
        
        // Update dashboard cards
        JPanel cardsPanel = (JPanel) dashboardPanel.getComponent(1);
        
        // Update open ports count
        JPanel card1 = (JPanel) cardsPanel.getComponent(0);
        JPanel contentPanel1 = (JPanel) card1.getComponent(1);
        JLabel countLabel1 = (JLabel) contentPanel1.getComponent(0);
        countLabel1.setText(String.valueOf(openPorts));
        
        // Update vulnerabilities count
        JPanel card2 = (JPanel) cardsPanel.getComponent(1);
        JPanel contentPanel2 = (JPanel) card2.getComponent(1);
        JLabel countLabel2 = (JLabel) contentPanel2.getComponent(0);
        countLabel2.setText(String.valueOf(vulnerabilities));
        
        // Update threats count
        JPanel card3 = (JPanel) cardsPanel.getComponent(2);
        JPanel contentPanel3 = (JPanel) card3.getComponent(1);
        JLabel countLabel3 = (JLabel) contentPanel3.getComponent(0);
        countLabel3.setText(String.valueOf(threats));
        
        // Calculate risk score (simple algorithm)
        int riskScore = 0;
        if (vulnerabilities > 0) {
            riskScore = Math.min(100, (vulnerabilities * 10) + (threats * 20));
        }
        
        // Update risk score
        JPanel card4 = (JPanel) cardsPanel.getComponent(3);
        JPanel contentPanel4 = (JPanel) card4.getComponent(1);
        JLabel countLabel4 = (JLabel) contentPanel4.getComponent(0);
        countLabel4.setText(String.valueOf(riskScore));
    }
    
    /**
     * Exports the scan results to a file
     */
    private void exportResults() {
        // TODO: Implement export functionality
        JOptionPane.showMessageDialog(this,
            "Export functionality will be implemented in a future version.",
            "Not Implemented",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Shows the about dialog
     */
    private void showAboutDialog() {
        JOptionPane.showMessageDialog(this,
            "Cybersecurity Risk Analyzer v1.0\n" +
            "A desktop application for scanning and analyzing cybersecurity risks.\n\n" +
            "Developed by Tushar\n" +
            "© 2023 Cybersecurity Risk Analyzer Team",
            "About",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Main method - entry point for the application
     */
    public static void main(String[] args) {
        // Set look and feel to system default
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Create and show the application
        SwingUtilities.invokeLater(() -> {
            CyberSecurityDesktopApp app = new CyberSecurityDesktopApp();
            app.setVisible(true);
        });
    }
}