package com.nsec.portscanner;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class PortChecker {
    private static final Map<Integer, String> SERVICE_MAP = new HashMap<>();
    static{
        // Standard Internet services
        SERVICE_MAP.put(20, "FTP Data");
        SERVICE_MAP.put(21, "FTP Control");
        SERVICE_MAP.put(22, "SSH");
        SERVICE_MAP.put(23, "Telnet");
        SERVICE_MAP.put(25, "SMTP");
        SERVICE_MAP.put(37, "Time");
        SERVICE_MAP.put(43, "WHOIS");
        SERVICE_MAP.put(53, "DNS");
        SERVICE_MAP.put(67, "DHCP Server");
        SERVICE_MAP.put(68, "DHCP Client");
        SERVICE_MAP.put(69, "TFTP");
        SERVICE_MAP.put(79, "Finger");
        SERVICE_MAP.put(80, "HTTP");
        SERVICE_MAP.put(88, "Kerberos");
        SERVICE_MAP.put(110, "POP3");
        SERVICE_MAP.put(111, "RPC");
        SERVICE_MAP.put(119, "NNTP");
        SERVICE_MAP.put(123, "NTP");
        SERVICE_MAP.put(135, "MS RPC");
        SERVICE_MAP.put(137, "NetBIOS Name");
        SERVICE_MAP.put(138, "NetBIOS Datagram");
        SERVICE_MAP.put(139, "NetBIOS Session");
        SERVICE_MAP.put(143, "IMAP");
        SERVICE_MAP.put(161, "SNMP");
        SERVICE_MAP.put(162, "SNMP Trap");
        SERVICE_MAP.put(179, "BGP");
        SERVICE_MAP.put(194, "IRC");
        SERVICE_MAP.put(389, "LDAP");
        SERVICE_MAP.put(443, "HTTPS");
        SERVICE_MAP.put(445, "SMB/CIFS");
        SERVICE_MAP.put(464, "Kerberos Change/Set");
        SERVICE_MAP.put(465, "SMTPS");
        SERVICE_MAP.put(513, "rlogin");
        SERVICE_MAP.put(514, "Remote Shell");
        SERVICE_MAP.put(515, "LPD/LPR");
        SERVICE_MAP.put(520, "RIP");
        SERVICE_MAP.put(531, "AOL/IRC");
        SERVICE_MAP.put(540, "UUCP");
        SERVICE_MAP.put(546, "DHCPv6 Client");
        SERVICE_MAP.put(547, "DHCPv6 Server");
        SERVICE_MAP.put(548, "AFP");
        SERVICE_MAP.put(554, "RTSP");
        SERVICE_MAP.put(563, "NNTPS");
        SERVICE_MAP.put(587, "SMTP Submission");
        SERVICE_MAP.put(631, "IPP");
        SERVICE_MAP.put(636, "LDAPS");
        SERVICE_MAP.put(873, "rsync");
        SERVICE_MAP.put(989, "FTPS Data");
        SERVICE_MAP.put(990, "FTPS Control");
        SERVICE_MAP.put(993, "IMAPS");
        SERVICE_MAP.put(995, "POP3S");

// Database services
        SERVICE_MAP.put(1433, "MS SQL");
        SERVICE_MAP.put(1521, "Oracle DB");
        SERVICE_MAP.put(1830, "Oracle DB");
        SERVICE_MAP.put(3306, "MySQL/MariaDB");
        SERVICE_MAP.put(5432, "PostgreSQL");
        SERVICE_MAP.put(6379, "Redis");
        SERVICE_MAP.put(27017, "MongoDB");
        SERVICE_MAP.put(9042, "Cassandra");

// Remote access services
        SERVICE_MAP.put(3389, "RDP");
        SERVICE_MAP.put(5900, "VNC");
        SERVICE_MAP.put(5901, "VNC-1");
        SERVICE_MAP.put(5902, "VNC-2");
        SERVICE_MAP.put(5903, "VNC-3");

// Web services and applications
        SERVICE_MAP.put(4444, "WebLogic");
        SERVICE_MAP.put(8000, "HTTP Alt");
        SERVICE_MAP.put(8008, "HTTP Alt");
        SERVICE_MAP.put(8080, "HTTP Proxy");
        SERVICE_MAP.put(8443, "HTTPS Alt");
        SERVICE_MAP.put(8888, "HTTP Alt");
        SERVICE_MAP.put(9000, "Jenkins/Tomcat");
        SERVICE_MAP.put(9090, "Websphere");
        SERVICE_MAP.put(9200, "Elasticsearch");
        SERVICE_MAP.put(10000, "Webmin");

// Messaging & communication
        SERVICE_MAP.put(1812, "RADIUS Auth");
        SERVICE_MAP.put(1813, "RADIUS Accounting");
        SERVICE_MAP.put(5060, "SIP");
        SERVICE_MAP.put(5061, "SIP TLS");
        SERVICE_MAP.put(5222, "XMPP Client");
        SERVICE_MAP.put(5223, "XMPP Client SSL");
        SERVICE_MAP.put(5269, "XMPP Server");

// Version control
        SERVICE_MAP.put(9418, "Git");

// Gaming
        SERVICE_MAP.put(25565, "Minecraft");
        SERVICE_MAP.put(27015, "Steam/Source");

// Other common services
        SERVICE_MAP.put(1194, "OpenVPN");
        SERVICE_MAP.put(1701, "L2TP");
        SERVICE_MAP.put(1723, "PPTP");
        SERVICE_MAP.put(1883, "MQTT");
        SERVICE_MAP.put(2049, "NFS");
        SERVICE_MAP.put(3000, "Node.js/dev");
        SERVICE_MAP.put(3268, "Global Catalog");
        SERVICE_MAP.put(3269, "Global Catalog SSL");
        SERVICE_MAP.put(3690, "SVN");
        SERVICE_MAP.put(5353, "mDNS");
        SERVICE_MAP.put(5672, "AMQP");
        SERVICE_MAP.put(6443, "Kubernetes API");
        SERVICE_MAP.put(8443, "Kubernetes Dashboard");
        SERVICE_MAP.put(8500, "Consul");
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

    public static String detectService(String ip, int port) {
        // First check static map
        if (SERVICE_MAP.containsKey(port)) {
            return SERVICE_MAP.get(port);
        }

        // Try to get banner dynamically
        try (Socket socket = new Socket()) {
            // Connect with timeout
            socket.connect(new InetSocketAddress(ip, port), 3000);
            socket.setSoTimeout(3000);

            // For some common protocols, send appropriate initial messages
            if (port == 80 || port == 8080) {
                // Send HTTP request
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println("HEAD / HTTP/1.0");
                out.println("Host: " + ip);
                out.println("");
                out.flush();
            }

            // Read response (up to first 100 chars)
            try {
                InputStream in = socket.getInputStream();
                byte[] buffer = new byte[100];
                int bytesRead = in.read(buffer, 0, buffer.length);

                if (bytesRead > 0) {
                    String response = new String(buffer, 0, bytesRead)
                            .replaceAll("[\\r\\n]", " ")  // Replace newlines with spaces
                            .replaceAll("[^\\x20-\\x7E]", "");  // Keep only printable ASCII
                    return response.length() > 0 ? response : "Unknown";
                }
            } catch (IOException e) {
                // Reading timed out - no banner
            }

            return "Unknown (Open)";
        } catch (IOException e) {
            return "Unknown";
        }
    }
}