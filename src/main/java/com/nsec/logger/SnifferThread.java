package com.nsec.logger;

import org.pcap4j.core.PcapHandle;
import javax.swing.table.DefaultTableModel;

public class SnifferThread extends Thread {
    private final IPLogger logger;
    public DefaultTableModel tableModel;
    public int deviceIndex;
    private volatile boolean running = true;
    private PcapHandle handle; // Store handle for stopping sniffing

    public SnifferThread(IPLogger logger, int deviceIndex) {
        this.logger = logger;
        this.deviceIndex = deviceIndex;
    }

    @Override
    public void run() {
        running = true;
        logger.startSniffing(deviceIndex, tableModel, this); // Handle is set inside startSniffing()
    }

    public void stopSniffing() {
        running = false;
        if (handle != null) {
            try {
                handle.breakLoop(); // Stop packet capture
                handle.close();     // Close the handle
                System.out.println("Sniffing stopped.");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public boolean isRunning() {
        return running;
    }

    public void setHandle(PcapHandle handle) {
        this.handle = handle;
    }
}
