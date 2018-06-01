package com.mobigen.HeaderAnalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

//import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.headers.util.NdpiResultHandler;

import jodd.util.StringUtil;

public class Context {
	Logger logger = LoggerFactory.getLogger(getClass());	
	
	public static final String RAWPKT_DELI = "\t";
	public static final String KEY_DELI = "^";
	
	public static String WTIME;	
	public static String NDPI_FILE_NAME;	
	public static String OUTFILE_PATH_TSHARK_RESULT ="/root/apps/data/tsharkR";
	public static String RAW_HEADER_OUTPUT_PATH;
	public static String SESSION_OUTPUT_PATH;
	public static String RAW_HEADER_OUTPUT_FILE = RAW_HEADER_OUTPUT_PATH+"/"+WTIME+"_headers.dat";
	public static String SESSION_OUTPUT_FILE = SESSION_OUTPUT_PATH+"/"+WTIME+"_sessions.dat";
	
	public static List<String> NEW_SESSION_LIST_UNCLOSED; 				//[id:1] "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" Unclosed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
	public static ArrayList<String> NEW_SESSION_LIST_FINISHED; 				//[id:1-1] 처리가 끝난 "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" closed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
	public static ConcurrentHashMap<String,String[]> NDPI_TUPLE_UID_MAP; 				//[id:2] key:SIP^SPORT^DIP^DPORT , val:[UID,L4Proto,L7Proto]
	public static List<String[]> NDPI_TUPLE_LIST; 						//[id:5] [TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22] ,[TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22],,,,
	public static List<String> NEW_RAWPKT_HEADER_PARSED_LIST; 			//[id:3] HTTP_HEADER_LIST 의 항목 순서대로 Context.RAWPKT_DELI 구분자 포함 항목들이 String Row 로 된 리스트.
	public static ConcurrentHashMap<String,String[]> UID_UNCLOSED_ITEMS_MAP; 			//[id:4] key:UID , val:["FirstFlag","FirstPktTime","EndFlag","EndPktTime"]}
//	public static HashMap<String,String[]> UID_UNCLOSED_ITEMS_MAP_FINISHED; //[id:4-1] 처리가 끝난 key:UID , val:["FirstFlag","FirstPktTime","EndFlag","EndPktTime"]}
	 
	
	public static void init(){
		NEW_SESSION_LIST_UNCLOSED = Collections.synchronizedList(new ArrayList<String>()); 
		NEW_SESSION_LIST_FINISHED = new ArrayList<String>();
		NDPI_TUPLE_UID_MAP = new ConcurrentHashMap<String,String[]>();
		NDPI_TUPLE_LIST = Collections.synchronizedList(new ArrayList<String[]>());
		NEW_RAWPKT_HEADER_PARSED_LIST = Collections.synchronizedList(new ArrayList<String>()); 
		UID_UNCLOSED_ITEMS_MAP = new ConcurrentHashMap<String,String[]>();
//		UID_UNCLOSED_ITEMS_MAP_FINISHED = new HashMap<String,String[]>();
		
		RAW_HEADER_OUTPUT_PATH = System.getenv("RAW_HEADER_RESULT_DIR");
		SESSION_OUTPUT_PATH = System.getenv("SESSION_DATA_RESULT_DIR");
		OUTFILE_PATH_TSHARK_RESULT = System.getenv("TSHARK_RSLT_PATH");
		RAW_HEADER_OUTPUT_FILE = RAW_HEADER_OUTPUT_PATH+"/"+WTIME+"_headers.dat";
		SESSION_OUTPUT_FILE = SESSION_OUTPUT_PATH+"/"+WTIME+"_sessions.dat";
	}
	
	/**
	 * TCP Header Name <-> DB Column Name 
	 * */
	public static String transStrToMapKey(String arg) {		
		if("ip.src".equals(arg)) { return "srcip"; }
		else if("tcp.srcport".equals(arg)) { return "srcport";}
		else if("ip.dst".equals(arg)) { return "dstip";}
		else if("tcp.dstport".equals(arg)) { return "dstport";}
		else if("tcp.dstport".equals(arg)) { return "dstport";}
		else {return arg;}
	}
	
	
	/**
	 *  MAP_KEY = SRCIP^SRCPORT^DSTIP^DSTPORT
	 * */
	public static String makeMapKey(String sip, String sport, String dip, String dport) {
		return cleanIP(sip)+KEY_DELI+sport+KEY_DELI+cleanIP(dip)+KEY_DELI+dport;
	}	

	
	public static String cleanIP(String src) {		
		src = StringUtil.replace(src, "[", "");
		src = StringUtil.replace(src, "]", "");		
		return src;
	}
	
	/**
	 *  UID = L4PROTO^L7PROTO^SRCIP^SRCPORT^DSTIP^DSTPORT
	 * */
	public static String makeUid(String l4, String l7, String sip, String sport, String dip, String dport) {		
		return l4+KEY_DELI+l7+KEY_DELI+sip+KEY_DELI+sport+KEY_DELI+dip+KEY_DELI+dport;		
	}
	
	public static final String[] HTTP_HEADER_LIST = { 
			"uid"
			,"frame.time_epoch"
			,"srcip"          
			,"srcport"     
			,"dstip"          
			,"dstport"     
			,"tcp.flags"       
			,"l4proto"         
			,"l7proto"
			,"request.accept"
			,"request.accept-charset"
			,"request.accept-encoding"
			,"request.accept-language"
			,"request.accept-datetime"
			,"request.access-control-request-method"
			,"request.access-control-request-headers"
			,"request.authorization"
			,"request.cache-control"
			,"request.connection"
			,"request.cookie"
			,"request.content-length"
			,"request.content-md5"
			,"request.content-type"
			,"request.date"
			,"request.expect"
			,"request.forwarded"
			,"request.from"
			,"request.host"
			,"request.if-match"
			,"request.if-modified-since"
			,"request.if-none-match"
			,"request.if-range"
			,"request.if-unmodified-since"
			,"request.max-forwards"
			,"request.origin"
			,"request.pragma"
			,"request.proxy-authorization"
			,"request.range"
			,"request.referer"
			,"request.te"
			,"request.user-agent"
			,"request.upgrade"
			,"request.via"
			,"request.warning"
			,"response.access-control-allow-origin"
			,"response.access-control-allow-credentials"
			,"response.access-control-expose-headers"
			,"response.access-control-max-age"
			,"response.access-control-allow-methods"
			,"response.access-control-allow-headers"
			,"response.accept-patch"
			,"response.accept-ranges"
			,"response.age"
			,"response.allow"
			,"response.alt-svc"
			,"response.cache-control"
			,"response.connection"
			,"response.content-disposition"
			,"response.content-encoding"
			,"response.content-language"
			,"response.content-length"
			,"response.content-location"
			,"response.content-md5"
			,"response.content-range"
			,"response.content-type"
			,"response.date"
			,"response.etag"
			,"response.expires"
			,"response.last-modified"
			,"response.link"
			,"response.location"
			,"response.p3p"
			,"response.pragma"
			,"response.proxy-authenticate"
			,"response.public-key-pins"
			,"response.retry-after"
			,"response.server"
			,"response.set-cookie"
			,"response.strict-transport-security"
			,"response.trailer"
			,"response.transfer-encoding"
			,"response.tk"
			,"response.upgrade"
			,"response.vary"
			,"response.via"
			,"response.warning"
			,"response.www-authenticate"
			,"response.x-frame-options"};	
	
	
}
