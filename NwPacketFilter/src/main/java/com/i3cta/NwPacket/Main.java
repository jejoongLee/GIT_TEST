package com.i3cta.NwPacket;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.packet.util.NdpiResultHandler;
import com.i3cta.packet.util.TsharkCmdHandler;

import concurrents.OneTimeThread;

/*
 * 
 *  * Ndpi 의 수행결과파일의 flow 별 조합을 기반을  Tshark 명령어를 만들어 실행 
 *  * flow 별 Tshark 명령어를 만든다 
 * 
 * 
 */

public class Main {

	Logger logger = LoggerFactory.getLogger(getClass());
	
	PcapDissectService pcapDissectService = new PcapDissectService();	
	NdpiResultHandler ndpiResultHandler = new NdpiResultHandler();	
	HeaderFilterService headerFilterService = new HeaderFilterService();
	
	List<String[]> ndpiList = new ArrayList<String[]>();	
	boolean isWin = false;
		
	public Main() {
		isWin = System.getProperty("os.name").toLowerCase().indexOf("win") >= 0 ? true : false ;
		
	}
	
	public void process(String wtime) {		
		Context.initEnvs();
		nDpiResultFormatter(Context.getNDPIResultFileName(wtime));
		pcapDissectService.pcapSplitProcessor(wtime, Context.getRawPcpFileName(wtime),ndpiList);
		headerFilterService.tSharkProcessor(wtime, Context.getRawPcpFileName(wtime),ndpiList);
	}
	
	private void nDpiResultFormatter(String ndpiFile) {
		try {
		
		     ndpiList = ndpiResultHandler.get_List_Ip_Protocol(ndpiFile);
		
		} catch (FileNotFoundException e) {
			logger.error(e.getMessage());
		}
	}
	
	/* 
	 * args[0] : 2018-04-30_1714
	 * 
	 */
	public static void main(String args[]) {
		
		System.out.println("Packet Filter Start For WTIME:"+args[0]);		
		new Main().process(args[0]);
		
		
		
	}
	
}
