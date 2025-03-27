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

public class IPLogger {
    private static final String LOG_FILE = "C:\\Users\\adit2\\Desktop\\packet_log.txt";
    public void startSniffing(int device_index, DefaultTableModel tableModel){
        try{
            int index = 0;
            for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
                System.out.println(index++ + ": " + dev.getName() + " - " + dev.getDescription());
            }
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(device_index); // Get The Device from Available Network Interfaces
            int snapLen = 65536; // Max Bytes to Capture from Each Packet
            PcapNetworkInterface.PromiscuousMode mode =  PcapNetworkInterface.PromiscuousMode.PROMISCUOUS; // Capture All Traffic
            int timeout = 10; // Buffer Timeout in Milliseconds

            PcapHandle handle = nif.openLive(snapLen, mode, timeout); // Open Capture Handle on nif
            System.out.println("Started Sniffing on: "+nif.getName());

            handle.loop(-1, (PacketListener)packet -> processPacket(packet, tableModel)); //Start Indefinite Capture and Call processPacket
        }catch(Exception e){
            e.printStackTrace();
        }
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
        String logEntry = String.format("%s | %s | Src: %s | Dest: %s | Port: %d", timestamp, direction, sourceIP, destIP, port);
        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {
            writer.write(logEntry + "\n");
            System.out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Failed to write log");
        }
        if (tableModel != null) {
            SwingUtilities.invokeLater(() -> {
                tableModel.addRow(new Object[]{timestamp.toString(), direction, sourceIP, destIP, port});
                System.out.println("Row added: " + timestamp);
                tableModel.fireTableRowsInserted(tableModel.getRowCount() - 1, tableModel.getRowCount() - 1);
            });}

    }
}
