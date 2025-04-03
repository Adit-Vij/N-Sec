package com.nsec;

import com.formdev.flatlaf.FlatDarkLaf;
import com.nsec.discovery.NetworkDiscovery;
import com.nsec.logger.IPLogger;
import com.nsec.logger.SnifferThread;
import com.nsec.portscanner.PortScanner;
import com.nsec.ui.UI_Main;

import javax.swing.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class Main {
    public static void main(String[] args) {
        // IP Logger
        IPLogger logger = new IPLogger();
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }
        final SnifferThread[] st = {new SnifferThread(logger, 0)};
        System.setProperty("sun.java2d.dpiaware", "true"); // Set DPI Awareness
        UI_Main ui = new UI_Main();

        ui.getIPLogStartButton().addActionListener(e -> {
            if (st[0] != null && st[0].isAlive()) {
                try {
                    st[0].join(); // Ensure previous thread is completely stopped
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }

            // Create and start a new sniffing thread
            st[0] = new SnifferThread(logger, ui.getDeviceIndex(ui.getNifComboBoxLogger()));
            st[0].tableModel = ui.getIp_tableModel();
            st[0].start();

            // Update UI state
            ui.getNifComboBoxLogger().setEnabled(false);
            ui.getIPLogStartButton().setEnabled(false);
            ui.getIPLogStopButton().setEnabled(true);
        });

        ui.getIPLogStopButton().addActionListener(e -> {
            if (st[0] != null) {
                st[0].stopSniffing();
                try {
                    st[0].join(); // Ensure thread stops completely
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }

            // Enable start button after stopping
            ui.getIPLogStartButton().setEnabled(true);
            ui.getNifComboBoxLogger().setEnabled(true);
            ui.getIPLogStopButton().setEnabled(false);
        });

        // Port Scanner - create a single instance
        AtomicBoolean scanRunning = new AtomicBoolean(false);
        final PortScanner[] portScanner = {null}; // Using array to allow modification in lambda

        ui.getPortScanButton().addActionListener(e -> {
            if (!scanRunning.get()) { // Start Scan
                int[] range = ui.getPortRange();
                if (range[0] > range[1]) {
                    JOptionPane.showMessageDialog(null, "Start Port Cannot be Greater Than End Port!", "Warning", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if (range[0] == range[1]) {
                    JOptionPane.showMessageDialog(null, "Start Port Cannot be Equal to End Port!", "Warning", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // Update UI
                ui.getPortScanButton().setText("Stop");
                scanRunning.set(true);

                // Create a new port scanner with completion callback
                portScanner[0] = new PortScanner("127.0.0.1", range[0], range[1], ui.getPort_tableModel()) {
                    @Override
                    protected void onScanComplete() {
                        SwingUtilities.invokeLater(() -> {
                            ui.getPortScanButton().setText("Start");
                            scanRunning.set(false);
                        });
                    }
                };

                portScanner[0].startScan();
            } else { // Stop Scan
                if (portScanner[0] != null) {
                    portScanner[0].stopScan();
                }
                ui.getPortScanButton().setText("Start");
                scanRunning.set(false);
            }
        });

        //Network Discovery
        NetworkDiscovery discovery = new NetworkDiscovery(ui.getDiscovery_tableModel(),() ->
                SwingUtilities.invokeLater(() -> ui.getDiscoveryButton().setText("Start")));
        ui.getDiscoveryButton().addActionListener(e ->{
            if(!discovery.isRunning()){
                discovery.discoverDevices();
                ui.getDiscoveryButton().setText("Stop");
            } else {
                discovery.stopDiscovery();
                ui.getDiscoveryButton().setText("Start");
            }
        });
    }
}