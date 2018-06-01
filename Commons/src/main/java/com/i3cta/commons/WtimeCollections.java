package com.i3cta.commons;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class WtimeCollections {
	
	public String wtime;
	

	public List<String> NEW_SESSION_LIST_UNCLOSED; 				//[id:1] "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" Unclosed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
	public ArrayList<String> NEW_SESSION_LIST_FINISHED; 				//[id:1-1] 처리가 끝난 "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" closed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
	public ConcurrentHashMap<String,String[]> NDPI_TUPLE_UID_MAP; 				//[id:2] key:SIP^SPORT^DIP^DPORT , val:[UID,L4Proto,L7Proto]
	public List<String[]> NDPI_TUPLE_LIST; 						//[id:5] [TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22] ,[TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22],,,,
	public List<String> NEW_RAWPKT_HEADER_PARSED_LIST; 			//[id:3] HTTP_HEADER_LIST 의 항목 순서대로 Context.RAWPKT_DELI 구분자 포함 항목들이 String Row 로 된 리스트.
	public ConcurrentHashMap<String,String[]> UID_UNCLOSED_ITEMS_MAP; //[id:6] UID : Session Cols At "NEW_SESSION_LIST_UNCLOSED"
	
	
	public void init(String wtime){
		this.wtime = wtime;
		this.NEW_SESSION_LIST_UNCLOSED = Collections.synchronizedList(new ArrayList<String>()); 
		this.NEW_SESSION_LIST_FINISHED = new ArrayList<String>();
		this.NDPI_TUPLE_UID_MAP = new ConcurrentHashMap<String,String[]>();
		this.NDPI_TUPLE_LIST = Collections.synchronizedList(new ArrayList<String[]>());
		this.NEW_RAWPKT_HEADER_PARSED_LIST = Collections.synchronizedList(new ArrayList<String>()); 
		this.UID_UNCLOSED_ITEMS_MAP = new ConcurrentHashMap<String,String[]>();
	
	}
	
	
	public List<String> getNEW_SESSION_LIST_UNCLOSED() {
		return NEW_SESSION_LIST_UNCLOSED;
	}
	public void setNEW_SESSION_LIST_UNCLOSED(List<String> nEW_SESSION_LIST_UNCLOSED) {
		NEW_SESSION_LIST_UNCLOSED = nEW_SESSION_LIST_UNCLOSED;
	}
	public ArrayList<String> getNEW_SESSION_LIST_FINISHED() {
		return NEW_SESSION_LIST_FINISHED;
	}
	public void setNEW_SESSION_LIST_FINISHED(ArrayList<String> nEW_SESSION_LIST_FINISHED) {
		NEW_SESSION_LIST_FINISHED = nEW_SESSION_LIST_FINISHED;
	}
	public ConcurrentHashMap<String, String[]> getNDPI_TUPLE_UID_MAP() {
		return NDPI_TUPLE_UID_MAP;
	}
	public void setNDPI_TUPLE_UID_MAP(ConcurrentHashMap<String, String[]> nDPI_TUPLE_UID_MAP) {
		NDPI_TUPLE_UID_MAP = nDPI_TUPLE_UID_MAP;
	}
	public List<String[]> getNDPI_TUPLE_LIST() {
		return NDPI_TUPLE_LIST;
	}
	public void setNDPI_TUPLE_LIST(List<String[]> nDPI_TUPLE_LIST) {
		NDPI_TUPLE_LIST = nDPI_TUPLE_LIST;
	}
	public List<String> getNEW_RAWPKT_HEADER_PARSED_LIST() {
		return NEW_RAWPKT_HEADER_PARSED_LIST;
	}
	public void setNEW_RAWPKT_HEADER_PARSED_LIST(List<String> nEW_RAWPKT_HEADER_PARSED_LIST) {
		NEW_RAWPKT_HEADER_PARSED_LIST = nEW_RAWPKT_HEADER_PARSED_LIST;
	}
	public ConcurrentHashMap<String, String[]> getUID_UNCLOSED_ITEMS_MAP() {
		return UID_UNCLOSED_ITEMS_MAP;
	}
	public void setUID_UNCLOSED_ITEMS_MAP(ConcurrentHashMap<String, String[]> uID_UNCLOSED_ITEMS_MAP) {
		UID_UNCLOSED_ITEMS_MAP = uID_UNCLOSED_ITEMS_MAP;
	}
	public void setWtime(String str) {
		this.wtime = str;
	}
	
	public String getWtime() {
		return this.wtime;
	}
}
