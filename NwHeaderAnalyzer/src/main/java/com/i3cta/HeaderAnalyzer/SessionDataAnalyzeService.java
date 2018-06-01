package com.i3cta.HeaderAnalyzer;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;
import com.i3cta.headers.util.NdpiResultHandler;

import jodd.util.StringUtil;

public class SessionDataAnalyzeService {
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public NdpiResultHandler ndpiResultHandler;
	
	public void init(){		
		this.ndpiResultHandler = new NdpiResultHandler();
	}
	
	public void initNdpiTupleListWuidMap(String wtime) throws Exception {		
//		Context.NDPI_TUPLE_LIST = (ArrayList<String[]>) this.ndpiResultHandler.getTupleList(wtime);
		Context.getWTimeCollections(wtime).setNDPI_TUPLE_LIST((ArrayList<String[]>) this.ndpiResultHandler.getTupleList(wtime));
		String debugStr = "";
		for(String[] list : Context.getWTimeCollections(wtime).getNDPI_TUPLE_LIST()) {			
			for(String debug: list) {
				debugStr= debugStr+","+debug;
			}
			debugStr+="\n";
		}
		logger.debug("NDPI TUPLE LIST : \n"+debugStr);
	}
	
	public boolean validateTListUidMap(String wtime) {
		
		int tupleSize = Context.getWTimeCollections(wtime).getNDPI_TUPLE_LIST().size();
		int uidMapSize = Context.getWTimeCollections(wtime).getNDPI_TUPLE_UID_MAP().size();
		logger.debug("TupleList:"+tupleSize + " uidKeys:"+uidMapSize);
		if(tupleSize > 0 &&  uidMapSize > 0 ) 
			return true;
		else 
			return false;		
	}
	
	public void makeupUnclosedSessionList_remove_ver(String wtime) {
		int sListSize = Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_UNCLOSED().size();
		String raw;
		for(int i =0; i < sListSize ; i ++)
		{
			raw = Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_UNCLOSED().get(i);
			replaceItems(raw,wtime);			
//			Context.NEW_SESSION_LIST_UNCLOSED.remove(i);
		}
		
	}
	
	public void makeupUnclosedSessionList(String wtime) {		
		for(String raw : Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_UNCLOSED()) {
			replaceItems(raw,wtime);	
		}	
	}
	
	private void replaceItems(String raw,String wtime) {
		String[] tempRow = StringUtil.split(raw, Context.RAWPKT_DELI);
		
		if(tempRow != null) {
			String[] sessionVals = Context.getWTimeCollections(wtime).getUID_UNCLOSED_ITEMS_MAP().get(tempRow[0]);
			if(sessionVals != null) {				
				raw = StringUtil.replaceFirst(raw, "$F_TCP_FLAG$", sessionVals[1]);
				raw = StringUtil.replaceFirst(raw, "$F_TIME$", sessionVals[2]);
				raw = StringUtil.replaceFirst(raw, "$L_TCP_FLAG$", sessionVals[3]);		
				raw = StringUtil.replaceFirst(raw, "$L_TIME$", sessionVals[4]);
				
				Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_FINISHED().add(raw);	
			}else {
//				logger.debug("KEY="+tempRow[0]+" NOT IN UID_UNCLOSED_ITEMS_MAP");
			}
			
		}else {
			logger.debug("CANNOT READ RAW DATA  raw String:"+ raw);
		}
				
	}
	
	

}
