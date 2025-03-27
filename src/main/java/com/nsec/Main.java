package com.nsec;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.nsec.logger.IPLogger;
import com.nsec.ui.UI_Main;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class Main {
    public static void main(String[] args) {
        IPLogger logger = new IPLogger();
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }
        SnifferThread st = new SnifferThread(logger, 0);
        System.setProperty("sun.java2d.dpiaware", "true"); // Set DPI Awareness
        UI_Main ui = new UI_Main();
        ui.getStartButton().addActionListener(e->{
            st.deviceIndex = ui.getDeviceIndex();
            st.tableModel = ui.getTableModel();
            ui.getComboBox().setEnabled(false);
            st.start();
            ui.getStartButton().setEnabled(false);
            ui.getStopButton().setEnabled(true);
        });
        ui.getStopButton().addActionListener(e->{
            st.interrupt();
            if(st.isAlive()){
                ui.getStartButton().setEnabled(false);
                ui.getComboBox().setEnabled(true);
                ui.getStopButton().setEnabled(true);
            }
        });
    }
}
class SnifferThread extends  Thread{
    IPLogger logger;
    public DefaultTableModel tableModel;
    protected int deviceIndex;
    SnifferThread(IPLogger logger, int deviceIndex){
        this.logger = logger;
        this.deviceIndex = deviceIndex;
    }
    @Override
    public void run() {
        logger.startSniffing(deviceIndex,tableModel);
    }
}