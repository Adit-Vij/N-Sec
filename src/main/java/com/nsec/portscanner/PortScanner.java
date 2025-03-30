package com.nsec.portscanner;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PortScanner {
    private final String ip;
    private final int start_port;
    private final int end_port;
    private ExecutorService executor;
    private volatile boolean running;
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors()*2;

    public PortScanner(String ip, int start_port, int end_port){
        this.ip = ip;
        this.start_port = start_port;
        this.end_port = end_port;
    }
    public void startScan(){
        if(running){
            System.out.println("Scan Already in Progress.");
        }
        running = true;
        executor = Executors.newFixedThreadPool(THREAD_COUNT);
        System.out.println("Starting Scan...");

        for(int port = start_port; port<=end_port; port++){
            final int p = port;
            executor.execute(()->{
                if (!running) return;
                if (PortChecker.isPortOpen(ip, p)){
                    String detectedService = PortChecker.detectService(ip, p);
                    System.out.printf("Port %d is OPEN (%s)\n", p, detectedService);
                }
            });
        }
        executor.shutdown();
    }
    public void stopScan(){
        if (!running) {
            System.out.println("No scan is running.");
            return;
        }
        running = false;
        executor.shutdownNow();
        System.out.println("Scan stopped.");
    }
}