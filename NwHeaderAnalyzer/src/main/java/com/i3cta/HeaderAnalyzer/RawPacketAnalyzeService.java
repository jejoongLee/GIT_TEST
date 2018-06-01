package com.i3cta.HeaderAnalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.headers.util.FTPHeaderWJsonHandler;
import com.i3cta.headers.util.HttpHeaderWJsonHandler;

import concurrents.OneTimeThread;

public class RawPacketAnalyzeService {
	
	static final int CONCURRENT_TASK_MAX = 20;
	private Logger logger = LoggerFactory.getLogger(getClass());

	HttpHeaderWJsonHandler httpHeaderWJsonHandler = new HttpHeaderWJsonHandler();
	FTPHeaderWJsonHandler ftpHeaderWJsonHandler = new FTPHeaderWJsonHandler();
	
	public void process(String wtime) throws Exception {
		
		ExecutorService exeThreadPool = Executors.newFixedThreadPool(CONCURRENT_TASK_MAX);
		
		ArrayList<Path> hFilteredFileList = getTFilteredFileNames(wtime);
		
		for(Path p :hFilteredFileList) {
			
			if(p.toString() == null) continue;
			
			OneTimeThread taskWorker = new OneTimeThread() {
				String fileName = p.toString();
				@Override
						public void task() throws Exception
						{
							if(fileName.toUpperCase().contains("TCP")) {
								if(fileName.toUpperCase().contains("HTTP")) httpHeaderWJsonHandler.handler(fileName,wtime);
								else if (fileName.toUpperCase().contains("FTP")) ftpHeaderWJsonHandler.handler(fileName,wtime);
								else{ logger.debug("TCP BUT NOT HTTP!!! " + fileName); }
							}else if(fileName.toUpperCase().contains("UDP")) {
								logger.debug("UDP BUT NOT HANDLING!!! " + fileName); 
							}else if(fileName.toUpperCase().contains("ICMP")) {
								logger.debug("ICMP BUT NOT HANDLING!!! " + fileName);
							}else {
								logger.debug("OTHER L4 INFO!!! " + fileName);
							}
							
						}
			};
			
			exeThreadPool.execute(taskWorker);	
		}
		
		exeThreadPool.shutdown();		
		while(!exeThreadPool.isTerminated()) {}
		logger.info("NEW_RAWPKT_HEADER_PARSED_LIST\n"
				+   "UID_UNCLOSED_ITEMS_MAP Are Finished.");
	}
	
	public ArrayList<Path> getTFilteredFileNames(String wtime) throws IOException{
		logger.debug("Dir for fileLists : "+Context.OUTFILE_PATH_TSHARK_RESULT + " , FILE:"+wtime+".txt");
		ArrayList<Path> resultlist = new ArrayList<>();		
		Files.newDirectoryStream(Paths.get(Context.OUTFILE_PATH_TSHARK_RESULT), path -> path.toAbsolutePath().toString().endsWith(wtime+".txt")).forEach(resultlist::add);
		return resultlist;
	}
	
	
}
