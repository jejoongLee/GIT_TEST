package com.i3cta.HeaderAnalyzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.headers.util.FileOutHandler;

public class Main {

	Logger logger = LoggerFactory.getLogger(getClass());	
	
	public void process(String wtime) {
		
		Context.initEnvs();
		
		SessionDataAnalyzeService sessionDataHandler = new SessionDataAnalyzeService();
		sessionDataHandler.init();
		try {
			
				logger.info("1. PARSE NDPI-RESULT-FILE & LOAD TO HASMAP START.");
				//BUILD  [id:2]NDPI_TUPLE_UID_MAP , [id:1]NEW_SESSION_LIST_UNCLOSED , [id:5]NDPI_TUPLE_LIST
				sessionDataHandler.initNdpiTupleListWuidMap(wtime); //6-TupleList 생성 [L4_Protocol, L7_Protocol, SRC_IP, SRC_PORT, DST_IP, DST_PORT]
				logger.info("1. PARSE NDPI-RESULT-FILE & LOAD TO HASMAP END.");
			if(sessionDataHandler.validateTListUidMap(wtime)) {
				logger.info("2. PARSE HEADER FROM RAW DATA START.");	
				RawPacketAnalyzeService rawPacketDataHandler = new RawPacketAnalyzeService();
				//BUILD [id:3]NEW_RAWPKT_HEADER_PARSED_LIST  [id:4]UID_UNCLOSED_ITEMS_MAP
				rawPacketDataHandler.process(wtime);
				logger.info("2. PARSE HEADER FROM RAW DATA END.");
				//BUILD [id:1-1] NEW_SESSION_LIST_FINISHED
				logger.info("3. REPLACE SESSION DATA START.");
				sessionDataHandler.makeupUnclosedSessionList(wtime);
				logger.info("3. REPLACE SESSION DATA END.");
				logger.info("4. MEMORY TO FILE DUMP START.");
				FileOutHandler.dumpToFile(Context.getSessionResultFileName(wtime), Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_FINISHED());
				
				FileOutHandler.dumpToFile(Context.getRawHeaderReultFileName(wtime), Context.getWTimeCollections(wtime).getNEW_RAWPKT_HEADER_PARSED_LIST());				
				logger.info("4. MEMORY TO FILE DUMP END.");
			}
			/*
			 * TODO:
			 * DONE: 1) 두개끝나면 NEW_SESSION_LIST_UNCLOSED 에 UID_UNCLOSED_ITEMS_MAP 의 값으로 REPLACE
			 * DONE: 2) NEW_RAWPKT_HEADER_PARSED_LIST , NEW_SESSION_LIST_UNCLOSED 두개의 내용을 파일로 쓴다.
			 * 3) 필터파일 들을 ThreadPool 로 병렬처리 하는 부분으로 수정. 
			 * */
			
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			Context.WTIMED_DATA_HOLDER.remove(wtime);
		}
		return;
		
	}
	
	
	public static void main(String[] args) {

		// args[0] = wtime (job time)
		
		System.out.println("Header Analyzer Start For WTIME:"+args[0]);		
		new Main().process(args[0]);
		
	}
	
	
}
