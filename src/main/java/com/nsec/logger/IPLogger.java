package com.nsec.logger;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IpPacket;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Enumeration;

public class IPLogger {
    private static final String LOG_FILE = "packet_log.txt";

    public PcapHandle startSniffing(int deviceIndex, DefaultTableModel tableModel, SnifferThread thread) {
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(deviceIndex);
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;

            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            thread.setHandle(handle);

            System.out.println("Started sniffing on: " + nif.getName());

            handle.loop(-1, (PacketListener) packet -> {
                if (thread.isRunning()) {
                    processPacket(packet, tableModel);
                } else {
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }
                }
            });

            return handle;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private void processPacket(Packet packet, DefaultTableModel tableModel) {
        IpPacket ipPacket = packet.get(IpPacket.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);

        if (ipPacket != null && tcpPacket != null) {
            String srcIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIP = ipPacket.getHeader().getDstAddr().getHostAddress();
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

            if (isLocalAddress(srcIP)) {
                // OUTBOUND: from local to external
                log("OUTBOUND", srcIP, dstIP, dstPort, tableModel);
            } else if (isLocalAddress(dstIP)) {
                // INBOUND: from external to local
                log("INBOUND", srcIP, dstIP, srcPort, tableModel);
            } else {
                // Unknown or non-local traffic (optional)
                log("UNKNOWN", srcIP, dstIP, srcPort, tableModel);
            }
        }
    }

    private boolean isLocalAddress(String ip) {
        try {
            InetAddress target = InetAddress.getByName(ip);
            if (target.isLoopbackAddress() || target.isSiteLocalAddress()) {
                return true;
            }

            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface netInterface = interfaces.nextElement();
                Enumeration<InetAddress> addresses = netInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr.getHostAddress().equals(target.getHostAddress())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private void log(String direction, String sourceIP, String destIP, int port, DefaultTableModel tableModel) {
        LocalDateTime timestamp = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        String formattedTime = timestamp.format(formatter);

        String logEntry = String.format("%s | %s | Src: %s | Dest: %s | Port: %d",
                formattedTime, direction, sourceIP, destIP, port);

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
            });
        }
    }
}
