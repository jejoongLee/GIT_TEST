package com.i3cta.NwPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.packet.util.TsharkCmdHandler;

import concurrents.OneTimeThread;

public class HeaderFilterService {
	
	Logger logger = LoggerFactory.getLogger(getClass());
//	List<String[]> ndpiList;
	List<String> skippedProtos;
	List<String[]> tsharCmdList =  new ArrayList<String[]>();
	TsharkCmdHandler tsharkCmdHandler = new TsharkCmdHandler(); 

	public void tSharkProcessor(String jobTime, String pcapFile, List<String[]> ndpiList) {
		
		String[] tsharkCmd= null;
		logger.debug("SIZE ==== "+ndpiList.size());
		for(String[] tuple: ndpiList) {			
			tsharkCmd= tsharkCmdHandler.getTsharkCmd(tuple,pcapFile,jobTime);
			if(tsharkCmd!= null) {
				
				tsharCmdList.add(tsharkCmd);	
				
			}			
			else {
				String debugStr = "";
				for(String e:tuple) {
					debugStr+=e+" ";
				}
				if("".equals(tsharkCmd))skippedProtos.add(debugStr);
			} 
		}
		long startMillis = System.currentTimeMillis();
		logger.info("Tshark Filtering Started.!");
		runTsharkCmds();
		long endMillis = System.currentTimeMillis();
		logger.info("Tshark Filtering Terminated.!");
		logger.info("timeLaps : "+ (endMillis - startMillis)/1000 +"sec");
		
	}
	
	private void runTsharkCmds() {
		
		ExecutorService exeThreadPool = Executors.newFixedThreadPool(Context.CONCURRENT_TASK_MAX);
		
		for(String[] command : tsharCmdList) {
			
					OneTimeThread taskWorker = new OneTimeThread() {
						@Override
						public void task() throws Exception {
//							String fcmd = command;
//							if(isWin) fcmd = "cmd /c "+command;
//							System.out.println(fcmd);
//							for(String debug : command) {
//								System.out.print(debug+" ");								
//							}
//							System.out.println("");
							
							Process p = Runtime.getRuntime().exec(command);
							p.waitFor();
							
						}
					};

			exeThreadPool.execute(taskWorker);	
		}
		
		exeThreadPool.shutdown();
		
		while(!exeThreadPool.isTerminated()) {}
		
		logger.info("tShark Command Execution Finished.");
		
	}
	
	
}
