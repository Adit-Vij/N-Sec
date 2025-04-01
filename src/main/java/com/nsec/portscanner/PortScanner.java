package com.nsec.portscanner;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class PortScanner {
    private final String ip;
    private final JLabel lbl_status;
    private int start_port;
    private int end_port;
    private ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;
    private final DefaultTableModel tableModel;
    private final JProgressBar progressBar;

    public PortScanner(String ip, int start_port, int end_port, DefaultTableModel tableModel, JProgressBar progressBar, JLabel statusLabel) {
        this.ip = ip;
        this.start_port = start_port;
        this.end_port = end_port;
        this.tableModel = tableModel;
        this.progressBar = progressBar;
        this.lbl_status = statusLabel;
    }

    public void setRange(int start, int end) {
        start_port = start;
        end_port = end;
    }

    public void startScan() {
        if (running.get()) {
            JOptionPane.showMessageDialog(null, "Scan already in progress!", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        running.set(true);
        executor = Executors.newFixedThreadPool(THREAD_COUNT);
        int totalPorts = end_port - start_port + 1;
        AtomicInteger scannedPorts = new AtomicInteger(0);

        // Reset UI
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);  // Clear previous results
            progressBar.setValue(0);
            progressBar.setMaximum(totalPorts);
            progressBar.setStringPainted(true);
            lbl_status.setText("Scanning...");
        });

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                for (int port = start_port; port <= end_port; port++) {
                    if (!running.get()) break; // Stop if scanning is canceled
                    final int p = port;
                    executor.execute(() -> {
                        if (PortChecker.isPortOpen(ip, p)) {
                            String detectedService = PortChecker.detectService(ip, p);

                            // Update table
                            SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{ip, p, detectedService}));
                        }

                        // Update progress bar
                        int progress = scannedPorts.incrementAndGet();
                        SwingUtilities.invokeLater(() -> progressBar.setValue(progress));
                    });
                }

                executor.shutdown(); // Wait for tasks to complete
                while (!executor.isTerminated()) {
                    try {
                        Thread.sleep(100); // Allow background tasks to finish
                    } catch (InterruptedException ignored) {}
                }

                return null;
            }

            @Override
            protected void done() {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(progressBar.getMaximum());
                    lbl_status.setText(running.get() ? "Scan Complete" : "Scan Stopped");
                    running.set(false);
                });
            }
        }.execute();
    }

    public void stopScan() {
        if (!running.get()) {
            JOptionPane.showMessageDialog(null, "No scan is running.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        running.set(false);
        executor.shutdownNow();
        SwingUtilities.invokeLater(() -> lbl_status.setText("Scan Stopped"));
    }
}
