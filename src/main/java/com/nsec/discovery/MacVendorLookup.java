package com.nsec.discovery;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class MacVendorLookup {
    private static final String SERIALIZED_FILE = "src/main/resources/mac_vendor.ser";
    private Map<String, String> macToVendor;
    private boolean databaseLoaded = false;

    public MacVendorLookup() {
        loadFromSerializedFile();
    }

    public MacVendorLookup(String filePath) {
        loadFromSerializedFile(filePath);
    }

    private void loadFromSerializedFile() {
        loadFromSerializedFile(SERIALIZED_FILE);
    }

    private void loadFromSerializedFile(String filePath) {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filePath))) {
            macToVendor = (HashMap<String, String>) in.readObject();
            databaseLoaded = true;
            System.out.println("MAC Vendor database loaded successfully with " + macToVendor.size() + " entries.");
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error loading database: " + e.getMessage());
            macToVendor = new HashMap<>();
        }
    }

    public String getVendor(String macAddress) {
        if (!databaseLoaded) {
            return "Database not loaded";
        }

        if (macAddress == null || macAddress.isEmpty()) {
            return "Invalid MAC Address";
        }

        // Normalize the MAC address - remove separators and convert to uppercase
        String normalizedMac = macAddress.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();

        // First try exact match with standard prefixes (most common case)
        // This is an optimization for performance
        if (normalizedMac.length() >= 6) {
            String standardPrefix = normalizedMac.substring(0, 6); // First 3 bytes (24 bits)
            if (macToVendor.containsKey(standardPrefix)) {
                String vendor = macToVendor.get(standardPrefix);
                return cleanVendorName(vendor);
            }
        }

        // If no match with standard prefix, try to find the vendor using different prefix lengths
        for (Map.Entry<String, String> entry : macToVendor.entrySet()) {
            String key = entry.getKey();

            // Check if this is a prefix with length indicator
            int prefixLength = 24; // Default is 24 bits (3 bytes)
            String macPrefix = key;

            if (key.contains("/")) {
                String[] parts = key.split("/");
                macPrefix = parts[0].trim();
                try {
                    prefixLength = Integer.parseInt(parts[1].trim());
                } catch (NumberFormatException e) {
                    prefixLength = 24;
                }
            }

            // Normalize the key MAC prefix
            String normalizedPrefix = macPrefix.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();

            // Calculate how many hex characters we need to compare based on prefix length
            int hexCharsToCompare = (int) Math.ceil(prefixLength / 4.0);

            // Ensure we have enough characters to compare
            if (normalizedMac.length() >= hexCharsToCompare &&
                    normalizedPrefix.length() >= hexCharsToCompare) {

                // Compare the required number of characters
                if (normalizedMac.substring(0, hexCharsToCompare).equals(
                        normalizedPrefix.substring(0, hexCharsToCompare))) {

                    return cleanVendorName(entry.getValue());
                }
            }
        }

        return "Unknown Vendor";
    }

    private String cleanVendorName(String vendor) {
        if (vendor == null) {
            return "Unknown Vendor";
        }

        // Remove surrounding quotes if present
        if (vendor.startsWith("\"") && vendor.endsWith("\"")) {
            vendor = vendor.substring(1, vendor.length() - 1);
        }

        return vendor.trim();
    }

    public boolean isDatabaseLoaded() {
        return databaseLoaded;
    }

    public int getDatabaseSize() {
        return macToVendor != null ? macToVendor.size() : 0;
    }

    public void displayDatabase(int limit) {
        if (!databaseLoaded || macToVendor.isEmpty()) {
            System.out.println("No database loaded or database is empty.");
            return;
        }

        System.out.println("MAC PREFIX\tVENDOR");
        System.out.println("----------\t------");

        int count = 0;
        for (Map.Entry<String, String> entry : macToVendor.entrySet()) {
            System.out.println(entry.getKey() + "\t" + cleanVendorName(entry.getValue()));
            count++;

            if (limit > 0 && count >= limit) {
                System.out.println("... (showing first " + limit + " of " + macToVendor.size() + " entries)");
                break;
            }
        }

        System.out.println("\nTotal entries: " + macToVendor.size());
    }
}