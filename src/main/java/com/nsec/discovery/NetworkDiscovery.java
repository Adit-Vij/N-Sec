package com.nsec.discovery;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public class NetworkDiscovery {
    private final MacVendorLookup macVendorLookup;
    private final DefaultTableModel tableModel;
    private volatile boolean running = false;
    private final Runnable onComplete;

    public NetworkDiscovery(DefaultTableModel discovery_tableModel, Runnable onComplete) {
        this.macVendorLookup = new MacVendorLookup();
        this.tableModel = discovery_tableModel;
        this.onComplete = onComplete;
    }

    public void discoverDevices() {
        if (running) {
            System.out.println("Discovery already in progress...");
            return;
        }

        running = true;

        new Thread(() -> {
            try {
                String localSubnet = getLocalSubnet();
                List<String> ipAddresses = getIPsInSubnet(localSubnet);

                for (String ip : ipAddresses) {
                    if (!running) break; // Check if the scan was stopped

                    String macAddress = getMacAddress(ip);
                    if (macAddress != null) {
                        String deviceName = getDeviceName(ip);
                        String vendor = macVendorLookup.getVendor(macAddress);
                        addToTable(ip, macAddress, vendor, deviceName);
                        System.out.println("Discovered: " + ip + " - " + macAddress + " - " + vendor + " - " + deviceName);
                    }
                }
            } catch (IOException e) {
                System.err.println("Error discovering devices: " + e.getMessage());
            } finally {
                running = false;
                if (onComplete != null) {
                    onComplete.run();
                }// Reset flag when scan completes or stops
            }
        }).start();
    }

    public void stopDiscovery() {
        running = false;
        System.out.println("Stopping discovery...");
    }

    private void addToTable(String ip, String mac, String vendor, String deviceName) {
        SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{ip, mac, deviceName, vendor}));
    }

    private String getLocalSubnet() throws IOException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface netInterface = interfaces.nextElement();
            if (!netInterface.isUp() || netInterface.isLoopback() || netInterface.isVirtual()) continue;

            for (InterfaceAddress addr : netInterface.getInterfaceAddresses()) {
                InetAddress ip = addr.getAddress();
                if (ip instanceof Inet4Address) {
                    int subnetPrefix = addr.getNetworkPrefixLength();
                    return getSubnetFromIp(ip.getHostAddress(), subnetPrefix);
                }
            }
        }
        throw new IOException("No valid network interface found.");
    }

    private String getSubnetFromIp(String ip, int subnetPrefix) {
        String[] octets = ip.split("\\.");
        int hostBits = 32 - subnetPrefix;
        int subnetMask = 0xFFFFFFFF << hostBits;
        int ipInt = (Integer.parseInt(octets[0]) << 24) |
                (Integer.parseInt(octets[1]) << 16) |
                (Integer.parseInt(octets[2]) << 8) |
                Integer.parseInt(octets[3]);

        int networkAddress = ipInt & subnetMask;
        return ((networkAddress >> 24) & 0xFF) + "." +
                ((networkAddress >> 16) & 0xFF) + "." +
                ((networkAddress >> 8) & 0xFF) + ".";
    }

    private List<String> getIPsInSubnet(String subnet) {
        return java.util.stream.IntStream.range(1, 255)
                .mapToObj(i -> subnet + i)
                .collect(Collectors.toList());
    }

    private String getMacAddress(String ip) {
        try {
            Process p = Runtime.getRuntime().exec("arp -a " + ip);
            try (Scanner scanner = new Scanner(p.getInputStream())) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (line.contains(ip)) {
                        return extractMac(line);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error getting MAC address for " + ip);
        }
        return null;
    }

    private String extractMac(String arpLine) {
        String[] tokens = arpLine.split("\\s+");
        for (String token : tokens) {
            if (token.matches("([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")) {
                return token.toUpperCase().replaceAll("[:-]", "");
            }
        }
        return null;
    }

    private String getDeviceName(String ip) {
        String deviceName = getNetBIOSName(ip);
        if (deviceName == null) deviceName = getReverseDNSName(ip);
        return (deviceName != null) ? deviceName : "Unknown Device";
    }

    private String getNetBIOSName(String ip) {
        try {
            Process p = Runtime.getRuntime().exec("nbtstat -A " + ip);
            try (Scanner scanner = new Scanner(p.getInputStream())) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (line.contains("<00>")) {
                        return line.split("\\s+")[0];
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("NetBIOS lookup failed for " + ip);
        }
        return null;
    }

    private String getReverseDNSName(String ip) {
        try {
            return InetAddress.getByName(ip).getCanonicalHostName();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public boolean isRunning() {
        return running;
    }
}
