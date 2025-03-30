package com.nsec;
import com.formdev.flatlaf.FlatDarkLaf;
import com.nsec.logger.IPLogger;
import com.nsec.logger.SnifferThread;
import com.nsec.ui.UI_Main;

import javax.swing.*;

public class Main {
    public static void main(String[] args) {
        IPLogger logger = new IPLogger();
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }
        final SnifferThread[] st = {new SnifferThread(logger, 0)};
        System.setProperty("sun.java2d.dpiaware", "true"); // Set DPI Awareness
        UI_Main ui = new UI_Main();
        ui.getStartButton().addActionListener(e -> {
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
            ui.getComboBox().setEnabled(false);
            ui.getStartButton().setEnabled(false);
            ui.getStopButton().setEnabled(true);
        });
        ui.getStopButton().addActionListener(e -> {
            if (st[0] != null) {
                st[0].stopSniffing();
                try {
                    st[0].join(); // Ensure thread stops completely
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }

            // Enable start button after stopping
            ui.getStartButton().setEnabled(true);
            ui.getComboBox().setEnabled(true);
            ui.getStopButton().setEnabled(false);
        });

    }
}