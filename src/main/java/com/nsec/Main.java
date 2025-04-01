package com.nsec;

import com.formdev.flatlaf.FlatDarkLaf;
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
            st[0] = new SnifferThread(logger, ui.getDeviceIndex());
            st[0].tableModel = ui.getIp_tableModel();
            st[0].start();

            // Update UI state
            ui.getNifComboBox().setEnabled(false);
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
            ui.getNifComboBox().setEnabled(true);
            ui.getIPLogStopButton().setEnabled(false);
        });

        // Port Scanner
        AtomicBoolean scanToggle = new AtomicBoolean(false); // True if Scan is Running

        ui.getPortScanButton().addActionListener(e -> {
            int[] range = ui.getPortRange();
            if (range[0] > range[1]) {
                JOptionPane.showMessageDialog(null, "Start Port Cannot be Greater Than End Port!", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (range[0] == range[1]) {
                JOptionPane.showMessageDialog(null, "Start Port Cannot be Equal to End Port!", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (!scanToggle.get()) { // Start Scan
                PortScanner portScanner = new PortScanner(
                        "127.0.0.1",
                        range[0],
                        range[1],
                        ui.getPort_tableModel()
                );

                ui.getPortScanButton().setText("Stop");
                scanToggle.set(true);
                portScanner.startScan();
            } else { // Stop Scan
                scanToggle.set(false);
                ui.getPortScanButton().setText("Start");
            }
        });
    }
}
