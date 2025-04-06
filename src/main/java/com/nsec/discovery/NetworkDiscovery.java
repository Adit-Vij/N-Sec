package com.nsec.discovery;

import org.pcap4j.core.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.net.*;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class NetworkDiscovery {
    private final MacVendorLookup macVendorLookup;
    private final DefaultTableModel tableModel;
    private volatile boolean running = false;
    private final Runnable onComplete;
    private PcapNetworkInterface selectedInterface;
    private final JComboBox<String> combo;
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;

    public NetworkDiscovery(DefaultTableModel discoveryTableModel, Runnable onComplete, JComboBox<String> combo) {
        this.macVendorLookup = new MacVendorLookup();
        this.tableModel = discoveryTableModel;
        this.onComplete = onComplete;
        this.combo = combo;
    }

    public void discoverDevices(int deviceIndex) {
        if (running) {
            System.out.println("Discovery already in progress...");
            return;
        }

        running = true;
        SwingUtilities.invokeLater(() -> tableModel.setRowCount(0));

        new Thread(() -> {
            ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

            try {
                this.selectedInterface = getSelectedInterface(deviceIndex);
                if (selectedInterface == null) {
                    System.err.println("No valid network interface selected.");
                    return;
                }

                System.out.println("Selected Network Interface: " + selectedInterface.getName() + " - " + selectedInterface.getDescription());

                String localSubnet = getLocalSubnet(selectedInterface);
                if (localSubnet == null) {
                    System.err.println("Could not determine subnet.");
                    return;
                }

                List<String> ipAddresses = getIPsInSubnet(localSubnet);
                List<Callable<Void>> tasks = ipAddresses.stream().map(ip -> (Callable<Void>) () -> {
                    if (!running) return null;

                    if (isReachable(ip)) {
                        String macAddress = getMacAddress(ip);
                        if (macAddress != null) {
                            String deviceName = getDeviceName(ip);
                            String vendor = macVendorLookup.getVendor(macAddress);
                            addToTable(ip, macAddress, vendor, deviceName);
                            System.out.println("Discovered: " + ip + " - " + macAddress + " - " + vendor + " - " + deviceName);
                        }
                    }
                    return null;
                }).collect(Collectors.toList());

                executor.invokeAll(tasks);
            } catch (IOException | PcapNativeException | InterruptedException e) {
                System.err.println("Error discovering devices: " + e.getMessage());
            } finally {
                executor.shutdown();
                running = false;
                if (onComplete != null) {
                    onComplete.run(); combo.setEnabled(true);
                    System.out.println("Discovery Complete!");
                }
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

    private static PcapNetworkInterface getSelectedInterface(int index) throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces == null || interfaces.isEmpty()) {
            throw new PcapNativeException("No network interfaces found.");
        }

        if (index < 0 || index >= interfaces.size()) {
            throw new PcapNativeException("Invalid interface index: " + index);
        }

        return interfaces.get(index);
    }

    private String getLocalSubnet(PcapNetworkInterface nif) throws IOException {
        for (PcapAddress address : nif.getAddresses()) {
            if (address.getAddress() instanceof Inet4Address) {
                String ip = address.getAddress().getHostAddress();
                int subnetPrefix = getSubnetPrefix(nif);
                return getSubnetFromIp(ip, subnetPrefix);
            }
        }
        return null;
    }

    private int getSubnetPrefix(PcapNetworkInterface nif) {
        for (PcapAddress address : nif.getAddresses()) {
            if (address.getNetmask() instanceof Inet4Address) {
                String[] octets = address.getNetmask().getHostAddress().split("\\.");
                int mask = 0;
                for (String octet : octets) {
                    mask += Integer.bitCount(Integer.parseInt(octet));
                }
                return mask;
            }
        }
        return 24;
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

    private boolean isReachable(String ip) {
        try {
            InetAddress inet = InetAddress.getByName(ip);
            return inet.isReachable(500); // 500ms timeout
        } catch (IOException ignored) {
            return false;
        }
    }

    private String getMacAddress(String ip) {
        try {
            Process p = Runtime.getRuntime().exec("arp -a " + ip);
            try (Scanner scanner = new Scanner(p.getInputStream())) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (line.contains(ip)) {
                        String rawMac = extractMac(line);
                        return formatMac(rawMac);
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
                return token.toUpperCase().replace('-', ':');
            }
        }
        return null;
    }

    private String formatMac(String mac) {
        if (mac == null) return null;
        String[] parts = mac.split(":");
        if (parts.length != 6) return null;

        for (int i = 0; i < parts.length; i++) {
            if (parts[i].length() == 1) {
                parts[i] = "0" + parts[i];
            }
        }
        return String.join(":", parts).toUpperCase();
    }

    private String getDeviceName(String ip) {
        String deviceName = getNetBIOSName(ip);
        if (deviceName == null) {
            deviceName = getReverseDNSName(ip);
        }
        return (deviceName != null && !deviceName.equals(ip)) ? deviceName : "Unknown Device";
    }

    private String getNetBIOSName(String ip) {
        try {
            Process p = Runtime.getRuntime().exec("nbtstat -A " + ip);
            try (Scanner scanner = new Scanner(p.getInputStream())) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    if (line.contains("<00>") && !line.contains("GROUP")) {
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
            Process p = Runtime.getRuntime().exec("nslookup " + ip);
            try (Scanner scanner = new Scanner(p.getInputStream())) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (line.toLowerCase().contains("name")) {
                        return line.split(":")[1].trim();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Reverse DNS lookup failed for " + ip);
        }
        return null;
    }

    public boolean isRunning() {
        return running;
    }
}
