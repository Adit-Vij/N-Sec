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
    String[] columns = {"Timestamp", "Direction", "Source IP", "Destination IP", "Port"};
    DefaultTableModel tableModel = new DefaultTableModel(columns,0);


    public UI_Main(){
        JFrame frame = new JFrame("N-Sec: Network Security Suite");
        frame.add(superContainer);
        tbl_logs = new JTable(tableModel);
        tbl_logs.setModel(tableModel);
        tableModel.fireTableDataChanged();
        tbl_logs.repaint();
        populateComboBoxWithNif(combo_nif);
        btn_stop.setEnabled(false);
        frame.setMinimumSize(new Dimension(500,400));
        frame.setVisible(true);
    }
    public JComboBox<String> getComboBox(){
        return combo_nif;
    }
    public JButton getStartButton(){
        return btn_start;
    }
    public JButton getStopButton(){
        return btn_stop;
    }
    public int getDeviceIndex(){
        return combo_nif.getSelectedIndex();
    }
    public DefaultTableModel getTableModel(){
        return tableModel;
    }
    private void populateComboBoxWithNif(JComboBox<String>combo){
        try{
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            if(devices == null || devices.isEmpty() ) {
                System.err.println("NO NETWORK INTERFACES FOUND!");
                return;
            }
            for (PcapNetworkInterface device: devices){
                combo.addItem(device.getDescription());
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
