package com.nsec.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.awt.*;
import java.util.List;


public class UI_Main {
    private JPanel superContainer;
    private JPanel ipLoggerContainer;
    private JLabel lbl_nif;
    private JComboBox<String> combo_nifLogger;
    private JButton btn_startIpLog;
    private JButton btn_stopIpLog;
    private JTable tbl_logs;
    private JTabbedPane tabbed_modules;
    private JPanel tab_ipLogger;
    private JPanel tab_portScanner;
    private JPanel portScannerContainer;
    private JSpinner spin_startPort;
    private JSpinner spin_endPort;
    private JLabel lbl_endPort;
    private JLabel lbl_startPort;
    private JButton btn_portScan;
    private JTable tbl_portScan;
    private JScrollPane scrl_logs;
    private JPanel tab_networkDiscovery;
    private JComboBox<String> combo_nifDiscovery;
    private JLabel lbl_nif2;
    private JButton btn_startDiscovery;
    private JTable tbl_discovery;
    private JPanel tab_encryptedChat;
    private JTextField txt_peerIP;
    private JPanel encryptedChatContainer;
    private JButton btn_connect;
    private JLabel lbl_enterIp;
    private JTextPane txtAr_chat;
    private JLabel lbl_connDisconn;
    private JLabel lbl_status;
    private JTextField txt_message;
    private JButton btn_send;
    private DefaultTableModel ip_tableModel;
    private DefaultTableModel port_tableModel;
    private DefaultTableModel discovery_tableModel;

    public UI_Main() {
        JFrame frame = new JFrame("N-Sec: Network Security Suite");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(superContainer);
        populateComboBoxWithNif(combo_nifLogger);
        populateComboBoxWithNif(combo_nifDiscovery);
        btn_stopIpLog.setEnabled(false);
        frame.setMinimumSize(new Dimension(1050, 800));
        frame.pack();
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < tabbed_modules.getTabCount(); i++) {
                Icon icon = tabbed_modules.getIconAt(i);
                String title = tabbed_modules.getTitleAt(i);

                JLabel label = new JLabel(title, icon, JLabel.CENTER);
                label.setHorizontalTextPosition(SwingConstants.CENTER);   // center the text
                label.setVerticalTextPosition(SwingConstants.BOTTOM);     // text below the icon
                label.setHorizontalAlignment(SwingConstants.CENTER);// center label itself
                label.setFont(label.getFont().deriveFont(16f));

                tabbed_modules.setTabComponentAt(i, label);
            }
        });
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

    }

    public JComboBox<String> getNifComboBoxLogger() {
        return combo_nifLogger;
    }
    public JComboBox<String> getNifComboBoxDiscovery() {
        return combo_nifDiscovery;
    }

    public JButton getIPLogStartButton() {
        return btn_startIpLog;
    }

    public JButton getIPLogStopButton() { return btn_stopIpLog; }

    public int getDeviceIndex(JComboBox<String> combo_nif) { return combo_nif.getSelectedIndex();}

    public DefaultTableModel getIp_tableModel() { return ip_tableModel; }

    public DefaultTableModel getDiscovery_tableModel(){ return discovery_tableModel; }

    public DefaultTableModel getPort_tableModel(){ return port_tableModel;}

    public JButton getPortScanButton(){ return btn_portScan; }

    public JButton getDiscoveryButton(){ return btn_startDiscovery; }

    private void populateComboBoxWithNif(JComboBox<String> combo) {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            if (devices == null || devices.isEmpty()) {
                System.err.println("NO NETWORK INTERFACES FOUND!");
                return;
            }
            for (PcapNetworkInterface device : devices) {
                combo.addItem(device.getDescription());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int[] getPortRange(){
        int[] range = {(int) spin_startPort.getValue(), (int) spin_endPort.getValue()};
        return range;
    }

    private void createUIComponents() {
        // Properly initialize JTable and DefaultTableModel
        String[] ip_columns = {"Timestamp", "Direction", "Source IP", "Destination IP", "Port"};
        String[] port_columns = {"IP","Port","Service"};
        String[] discover_columns = {"IP", "MAC", "Device Name", "Vendor"};
        ip_tableModel = new DefaultTableModel(ip_columns, 0);
        tbl_logs = new JTable(ip_tableModel);
        port_tableModel = new DefaultTableModel(port_columns, 0);
        tbl_portScan = new JTable(port_tableModel);
        discovery_tableModel = new DefaultTableModel(discover_columns, 0);
        tbl_discovery = new JTable(discovery_tableModel);
    }
}