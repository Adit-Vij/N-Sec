package com.nsec.portscanner;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PortScanner {
    private final String ip;
    private int start_port;
    private int end_port;
    private ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;
    private final DefaultTableModel tableModel;

    public PortScanner(String ip, int start_port, int end_port, DefaultTableModel tableModel) {
        this.ip = ip;
        this.start_port = start_port;
        this.end_port = end_port;
        this.tableModel = tableModel;
    }

    public void setRange(int start, int end) {
        start_port = start;
        end_port = end;
    }

    // This method is called when scan completes - override in subclasses
    protected void onScanComplete() {
        // Default empty implementation
    }

    public void startScan() {
        if (running.get()) {
            JOptionPane.showMessageDialog(null, "Scan already in progress!", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        running.set(true);
        executor = Executors.newFixedThreadPool(THREAD_COUNT);

        // Reset UI
        SwingUtilities.invokeLater(() -> tableModel.setRowCount(0));

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                for (int port = start_port; port <= end_port; port++) {
                    if (!running.get()) break;
                    final int p = port;

                    executor.submit(() -> {
                        if (PortChecker.isPortOpen(ip, p)) {
                            String detectedService = PortChecker.detectService(ip, p);
                            SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{ip, p, detectedService}));
                        }
                    });
                }
                executor.shutdown();
                try {
                    executor.awaitTermination(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return null;
            }

            @Override
            protected void done() {
                running.set(false);
                // Notify that scan is complete
                onScanComplete();
            }
        }.execute();
    }

    public void stopScan() {
        if (!running.get()) {
            JOptionPane.showMessageDialog(null, "No scan is running.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        running.set(false);
        if (executor != null) {
            executor.shutdownNow();
        }

        // Notify that scan was manually stopped
        onScanComplete();
    }
}