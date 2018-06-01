package com.mobigen.ProcManager;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.*;

import jodd.util.StringUtil;

public class Main {
	
	Logger logger = LoggerFactory.getLogger(getClass());	
	
	public static final String watchDir = Context.RAW_PCAP_PATH; //"/root/apps/data/capture/raw";
	public Path toBeFinished;
	
	public void setInitFile() {
		logger.info("SET INIT Target Raw FILE @DIR="+watchDir);
		setInitFile(watchDir);
	}
	
	public void setInitFile(String dir) {
		try {
			ArrayList<Path> files = Utility.getLS_Sorted(dir);
			int l = files.size();
//			for(Path p: files) {
//				System.out.println(p.toString());
//			}
			toBeFinished = files.get(l-1).getFileName();
			logger.info(toBeFinished.toString());
		} catch (IOException e) {		
			e.printStackTrace();
		}
		
	}
	
	public void doWatch(String watchDir) {
		
		try {
            // Creates a instance of WatchService.
            WatchService watcher = FileSystems.getDefault().newWatchService();

            // Registers the logDir below with a watch service.
            Path logDir = Paths.get(watchDir);
            logDir.register(watcher, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);

            // Monitor the logDir at listen for change notification.
            while (true) {
                WatchKey key = watcher.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();

                    if (ENTRY_CREATE.equals(kind)) {
//                        System.out.println("Entry was created on log dir.");
                        Path filename = (Path) event.context();
                        Path targetFile = toBeFinished;                        
                        System.out.println("created f = "+filename + " & start Process With f="+targetFile);
                        toBeFinished = filename;
                        if(targetFile != null && targetFile.toString().length() > 1) {
                        	startProc(targetFile);	
                        }                        
                        
                    } 
                }
                key.reset();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

		
	}

	public String extractWtime(Path p) {
		String fn = p.toString();
		int s_idx = fn.indexOf("dump");
		String tempFn = fn.substring(s_idx);
		tempFn = StringUtil.replace(tempFn, "dump-", "");
		tempFn = StringUtil.replace(tempFn, ".pcap", "");
		return tempFn.trim();
	}
	
	public String extractWtime(String p) {
		String fn = p;
		int s_idx = fn.indexOf("dump");
		String tempFn = fn.substring(s_idx);
		tempFn = StringUtil.replace(tempFn, "dump-", "");
		tempFn = StringUtil.replace(tempFn, ".pcap", "");
		return tempFn.trim();
	}
	
	public void startProc(Path filename) {
		String wTime = extractWtime(filename);
		String cmdArr[] = new String[2]; 
		String cmd1 = Context.BIN_PATH+"/ndpiRun.sh";
		String cmd2 = Context.BIN_PATH+"/filterRun.sh";
		String cmd3 = Context.BIN_PATH+"/headerAnalRun.sh";
		String cmd4 = Context.BIN_PATH+"/mv2bakDir.sh";
		try {
			logger.info("-----------------START --------------------------");
			logger.info("starting  " + cmd1 + " " +filename.toString());
			cmdArr[0] = cmd1;
			cmdArr[1] = filename.toString();
			Process p1 = Runtime.getRuntime().exec(cmdArr);
			p1.waitFor();
			p1.destroy();
			
			cmdArr[0] = cmd2;
			cmdArr[1] = wTime;
			
			logger.info("starting  " + cmd2 + " " +wTime);
			Process p2 = Runtime.getRuntime().exec(cmdArr);
			p2.waitFor();
			p2.destroy();
			
			cmdArr[0] = cmd3;
			cmdArr[1] = wTime;
			logger.info("starting  " + cmd3 + " " +wTime);
			Process p3 = Runtime.getRuntime().exec(cmdArr);
			p3.waitFor();
			p3.destroy();
//			System.out.println("starting  " + cmd4 + " " +wTime);
//			Process p4 = Runtime.getRuntime().exec(cmd4 + " " +wTime);
//			p4.waitFor();
		
			logger.info("-----------------END --------------------------");
		} catch (IOException | InterruptedException e) {

			e.printStackTrace();
		}
	}
	
	public static void main(String args[]) {
		Context.initEnvs();
		Main m = new Main();		
//		m.setInitFile();
		System.out.println(Context.RAW_PCAP_PATH);
		m.setInitFile(Context.RAW_PCAP_PATH);
		m.doWatch(Context.RAW_PCAP_PATH);
		
//		System.out.println(m.extractWtime("/sdfsdf/dump-2018-05-17_1103.pcap"));
		
	}
	
	
	
	
}
