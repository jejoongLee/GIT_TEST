package com.i3cta.NwPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.packet.util.PcapSplitHandler;

import concurrents.OneTimeThread;

public class PcapDissectService {
	Logger logger = LoggerFactory.getLogger(getClass());
	List<String[]> tcpdumpCmdList  = new ArrayList<String[]>();
	PcapSplitHandler pcapSplitHandler = new PcapSplitHandler();

	public void pcapSplitProcessor(String jobTime, String pcapFile, List<String[]> ndpiList) {
		
		String[] tcpdumpCmd = null;
		for(String[] tuple : ndpiList) {
			tcpdumpCmd = pcapSplitHandler.getTcpDumpCmd(tuple, pcapFile, jobTime);
			String debugstr = "";
			for(String c :tcpdumpCmd) {
				debugstr+= " "+c;
			}
			logger.debug("tcpdumpCmd="+debugstr);
			tcpdumpCmdList.add(tcpdumpCmd);
		}
		
		long startMillis = System.currentTimeMillis();
		logger.info("pcapSplitter Filtering Started.!");
		runTcpdumpCmds();
		long endMillis = System.currentTimeMillis();
		logger.info("pcapSplitter Filtering Terminated.!");
		logger.info("timeLaps : "+ (endMillis - startMillis)/1000 +"sec");
		
	}
	
public void runTcpdumpCmds() {			
	
	ExecutorService exeThreadPool = Executors.newFixedThreadPool(Context.CONCURRENT_TASK_MAX);
	
	for(String[] command : tcpdumpCmdList) {
		
				OneTimeThread taskWorker = new OneTimeThread() {
					@Override
					public void task() throws Exception {
//						String fcmd = command;
//						if(isWin) fcmd = "cmd /c "+command;
						
						Process p = Runtime.getRuntime().exec(command);
						p.waitFor();						
						
					}
				};

		exeThreadPool.execute(taskWorker);	
	}
	
	exeThreadPool.shutdown();
	
	while(!exeThreadPool.isTerminated()) {}
	
	logger.info("tcpdumpCmdList Command Execution Finished.");
	
}

}
