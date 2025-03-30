package com.nsec.logger;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IpPacket;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class IPLogger {
    private static final String LOG_FILE = "packet_log.txt";
    public PcapHandle startSniffing(int device_index, DefaultTableModel tableModel, SnifferThread thread) {
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(device_index);
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;

            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            thread.setHandle(handle);  // Store handle in the thread before looping

            System.out.println("Started Sniffing on: " + nif.getName());

            handle.loop(-1, (PacketListener) packet -> {
                if (thread.isRunning()) {
                    processPacket(packet, tableModel);
                } else {
                    try {
                        handle.breakLoop(); // Stop capturing when thread stops
                    } catch (NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                }
            });

            return handle;  // This will never execute until sniffing stops (problematic)

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Return null in case of failure
    }

    private void processPacket(Packet packet, DefaultTableModel tableModel){
        // Extracts the IP and TCP headers from the packet
        // Ignores packet types like UDP, ARP, etc. for now...
        IpPacket ipPacket = packet.get(IpPacket.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);

        if(ipPacket!=null&&tcpPacket!=null) {
            String srcIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIP = ipPacket.getHeader().getDstAddr().getHostAddress();
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            if(isLocalAddress(dstIP)){
                log("INBOUND",srcIP,dstIP,srcPort,tableModel);
            }else{
                log("OUTBOUND",dstIP,srcIP,dstPort,tableModel);
            }
        }// Processes Packet Only If Packet Has Both IP and TCP Headers

    }
    private boolean isLocalAddress(String ip){
        try{InetAddress addr = InetAddress.getByName(ip);
        return addr.isSiteLocalAddress() || addr.isLoopbackAddress();
        }catch (Exception e){
            e.getStackTrace();
            return false;
        }
    }// Checks if The IP is a Local Address or Not

    private void log(String direction, String sourceIP, String destIP, int port, DefaultTableModel tableModel){
        LocalDateTime timestamp = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        String formattedTime = timestamp.format(formatter);
        String logEntry = String.format("%s | %s | Src: %s | Dest: %s | Port: %d", formattedTime, direction, sourceIP, destIP, port);
        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {
            writer.write(logEntry + "\n");
            System.out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Failed to write log");
        }
        if (tableModel != null) {
            SwingUtilities.invokeLater(() -> {
                tableModel.addRow(new Object[]{formattedTime, direction, sourceIP, destIP, port});
                tableModel.fireTableRowsInserted(tableModel.getRowCount() - 1, tableModel.getRowCount() - 1);
            });}

    }
}
