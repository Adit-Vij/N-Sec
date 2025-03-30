package com.nsec.portscanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class PortChecker {
    private static final Map<Integer, String> SERVICE_MAP = new HashMap<>();
    static{
        SERVICE_MAP.put(21, "FTP");
        SERVICE_MAP.put(22, "SSH");
        SERVICE_MAP.put(23, "Telnet");
        SERVICE_MAP.put(25, "SMTP");
        SERVICE_MAP.put(53, "DNS");
        SERVICE_MAP.put(80, "HTTP");
        SERVICE_MAP.put(110, "POP3");
        SERVICE_MAP.put(143, "IMAP");
        SERVICE_MAP.put(443, "HTTPS");
        SERVICE_MAP.put(3306, "MySQL");
        SERVICE_MAP.put(3389, "RDP");
    }// Service Map for Static Service Recognition for Open Ports

    private static boolean isAllowedIP(String ip){
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*");
    }// Returns `true` for Local IPs

    public static boolean isPortOpen(String ip, int port){
        try(Socket socket = new Socket(ip,port)){
            return true;
        }catch(IOException ignored){
            return false;
        }
    }// Returns True if Socket is Able to Establish Connection (Port is Open)

    public static String detectService(String ip, int port){
        // Check if Port - Service is Present in SERVICE_MAP
        if(SERVICE_MAP.containsKey(port)){
            return SERVICE_MAP.get(port);
        }try(Socket socket = new Socket(ip,port)){
            socket.setSoTimeout(2000);
            try(BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))){
                String banner = reader.readLine();
                return (banner != null && !banner.isEmpty()) ? banner : "Unknown";
            }
        }catch(IOException E){
            return "Unknown";
        }
    }
}