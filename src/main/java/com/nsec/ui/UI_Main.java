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
    private JComboBox<String> combo_nif;
    private JButton btn_start;
    private JButton btn_stop;
    private JTable tbl_logs;
    private JTabbedPane tabbedPane1;
    private JPanel tab_ipLogger;
    private JPanel tab_portScanner;
    private JPanel portScannerContainer;
    private JSpinner spin_startPort;
    private JSpinner spin_endPort;
    private JLabel lbl_endPort;
    private JLabel lbl_startPort;
    private JButton btn_scan;
    private JTable tbl_portScan;
    private JScrollPane scrl_logs;
    private DefaultTableModel ip_tableModel;
    private DefaultTableModel port_tableModel;

    public UI_Main() {
        JFrame frame = new JFrame("N-Sec: Network Security Suite");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(superContainer);
        populateComboBoxWithNif(combo_nif);
        btn_stop.setEnabled(false);
        frame.setMinimumSize(new Dimension(500, 400));
        frame.pack();
        frame.setVisible(true);
    }

    public JComboBox<String> getComboBox() {
        return combo_nif;
    }

    public JButton getStartButton() {
        return btn_start;
    }

    public JButton getStopButton() {
        return btn_stop;
    }

    public int getDeviceIndex() {
        return combo_nif.getSelectedIndex();
    }

    public DefaultTableModel getIp_tableModel() {
        return ip_tableModel;
    }

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

    private void createUIComponents() {
        // Properly initialize JTable and DefaultTableModel
        String[] ip_columns = {"Timestamp", "Direction", "Source IP", "Destination IP", "Port"};
        String[] port_columns = {"IP","Port","Service"};
        ip_tableModel = new DefaultTableModel(ip_columns, 0);
        tbl_logs = new JTable(ip_tableModel);
        port_tableModel = new DefaultTableModel(port_columns, 0);
        tbl_portScan = new JTable(port_tableModel);
    }
}
