package com.i3cta.commons;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jodd.util.StringUtil;

public class Context {
	Logger logger = LoggerFactory.getLogger(getClass());	
	
	public static String RAW_PCAP_PATH;
	public static String OUTFILE_PATH_SPLITPCAP_RESULT; // = "/root/apps/data/capture/spl";
	public static String NDPI_RSLT_PATH;
	public static String OUTFILE_PATH_TSHARK_RESULT; 	// = "/root/apps/data/tsharkR";
	public static String WIRESHARK_INSTALL_PATH; 		//="/root/apps/wireshark-2.2.14";
	public static String RUN_TSHARK_TEMPLATE_FILE; 		//="/root/apps/bin/tsharkTempls/runTshark";	
	public static String RUN_TCPDUMP_TEMPLATE_FILE; 	//="/root/apps/bin/tcpDumpSplitter.sh";
	public static String RAW_HEADER_OUTPUT_PATH;
	public static String SESSION_OUTPUT_PATH;
	
	public static String BIN_PATH;
	public static String LIB_PATH;
	public static String DATA_PATH;
	
	public static String FIN_RAW_PCAP_PATH;
	public static String FIN_OUTFILE_PATH_SPLITPCAP_RESULT;
	public static String FIN_NDPI_RSLT_PATH;
	public static String FIN_OUTFILE_PATH_TSHARK_RESULT;
	
	public static String CLEANUP_DATA_COMMAND = "/root/apps/bin/mv2bakDir.sh";
	
	public static ConcurrentHashMap<String, WtimeCollections> WTIMED_DATA_HOLDER;
	
//	public static String WTIME;	//PCAP WINDOW TIME	
	
//	public static String RAW_HEADER_OUTPUT_FILE = RAW_HEADER_OUTPUT_PATH+"/"+WTIME+"_headers.dat";
//	public static String SESSION_OUTPUT_FILE = SESSION_OUTPUT_PATH+"/"+WTIME+"_sessions.dat";
	
//	public static List<String> NEW_SESSION_LIST_UNCLOSED; 				//[id:1] "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" Unclosed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
//	public static ArrayList<String> NEW_SESSION_LIST_FINISHED; 				//[id:1-1] 처리가 끝난 "$F_TCP_FLAG$", "$L_TCP_FLAG$", "$F_TIME$", "$L_TIME$" closed. i.e.(|== tab) STR = UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES
//	public static ConcurrentHashMap<String,String[]> NDPI_TUPLE_UID_MAP; 				//[id:2] key:SIP^SPORT^DIP^DPORT , val:[UID,L4Proto,L7Proto]
//	public static List<String[]> NDPI_TUPLE_LIST; 						//[id:5] [TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22] ,[TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22],,,,
//	public static List<String> NEW_RAWPKT_HEADER_PARSED_LIST; 			//[id:3] HTTP_HEADER_LIST 의 항목 순서대로 Context.RAWPKT_DELI 구분자 포함 항목들이 String Row 로 된 리스트.
//	public static ConcurrentHashMap<String,String[]> UID_UNCLOSED_ITEMS_MAP; 
		
	public static String FILE_NAME_DELI="^";
	public static final String RAWPKT_DELI = "\t";
	public static final String KEY_DELI = "^";
	
	public static boolean ENV_VALIDATION = false;
	
	public static final int CONCURRENT_TASK_MAX = 20;
	
//	public static String OUTFILE_PATH_TSHARK_RESULT = "D:/work/wireshark_capture/unitTest";
//	public static String OUTFILE_PATH_SPLITPCAP_RESULT = "D:/work/wireshark_capture/unitTest/spls";

	public static void initEnvs() {
		RAW_PCAP_PATH = System.getenv("RAW_PCAP_PATH");
		OUTFILE_PATH_SPLITPCAP_RESULT = System.getenv("SPLIT_PCAP_PATH");
		NDPI_RSLT_PATH = System.getenv("NDPI_RSLT_PATH");
		OUTFILE_PATH_TSHARK_RESULT = System.getenv("TSHARK_RSLT_PATH");
		WIRESHARK_INSTALL_PATH=System.getenv("WIRESHARK_INST_PATH");
		RUN_TSHARK_TEMPLATE_FILE=System.getenv("TSHARK_TEMPLATE_PATH");		
		RUN_TCPDUMP_TEMPLATE_FILE =System.getenv("TCPDUMP_SPLITTER");
		RAW_HEADER_OUTPUT_PATH = System.getenv("RAW_HEADER_RESULT_PATH");		
		SESSION_OUTPUT_PATH = System.getenv("SESSION_DATA_RESULT_PATH");
		
		FIN_RAW_PCAP_PATH = System.getenv("RAW_PCAP_PATH_FIN");
		FIN_OUTFILE_PATH_SPLITPCAP_RESULT = System.getenv("SPLIT_PCAP_PATH_FIN");
		FIN_NDPI_RSLT_PATH = System.getenv("NDPI_RSLT_PATH_FIN");
		FIN_OUTFILE_PATH_TSHARK_RESULT = System.getenv("TSHARK_RSLT_PATH_FIN");
		
		BIN_PATH = System.getenv("BIN_PATH");
		LIB_PATH = System.getenv("LIB_PATH");
		DATA_PATH = System.getenv("DATA_PATH");
				
			if(OUTFILE_PATH_TSHARK_RESULT == null  
				|| OUTFILE_PATH_SPLITPCAP_RESULT == null
				|| RUN_TCPDUMP_TEMPLATE_FILE == null
				|| RUN_TSHARK_TEMPLATE_FILE == null
				|| WIRESHARK_INSTALL_PATH == null
				|| RAW_HEADER_OUTPUT_PATH == null
				|| SESSION_OUTPUT_PATH == null
				|| OUTFILE_PATH_TSHARK_RESULT == null
				|| BIN_PATH == null
				|| LIB_PATH == null
				|| DATA_PATH == null
				|| "".equals(OUTFILE_PATH_TSHARK_RESULT)
				|| "".equals(OUTFILE_PATH_SPLITPCAP_RESULT)
				|| "".equals(RUN_TCPDUMP_TEMPLATE_FILE)
				|| "".equals(RUN_TSHARK_TEMPLATE_FILE)
				|| "".equals(WIRESHARK_INSTALL_PATH)
				|| "".equals(RAW_HEADER_OUTPUT_PATH)
				|| "".equals(SESSION_OUTPUT_PATH)
				|| "".equals(OUTFILE_PATH_TSHARK_RESULT)
				|| "".equals(BIN_PATH)
				|| "".equals(LIB_PATH)
				|| "".equals(DATA_PATH)
				) 
			{
				ENV_VALIDATION = false;
				System.out.println("MUST RUN FIRST : $APP_HOME/source env-config" );
			}else {
				ENV_VALIDATION = true;
			}
			 WTIMED_DATA_HOLDER = new ConcurrentHashMap<String,WtimeCollections>();
			

	}
	
	public static WtimeCollections getWTimeCollections(String wtime) {
		WtimeCollections wc;
		if(!WTIMED_DATA_HOLDER.containsKey(wtime)) {
			wc = new WtimeCollections();
			wc.init(wtime);
			WTIMED_DATA_HOLDER.put(wtime, wc);
		}
		else {
			wc = WTIMED_DATA_HOLDER.get(wtime);
		}
		return wc;
	}
	
	public static String cleanIP(String src) {
		
		src = StringUtil.replace(src, "[", "");
		src = StringUtil.replace(src, "]", "");		
		
		return src;
	}
	
	public static String getNDPIResultFileName(String wtime) {
		return NDPI_RSLT_PATH+"/"+wtime+".ndpiresult";
	}
	
	public static String getRawPcpFileName(String wtime) {
		return RAW_PCAP_PATH+"/dump-"+wtime+".pcap";
	}
	
	public static String getRawHeaderReultFileName(String wtime) {
		return RAW_HEADER_OUTPUT_PATH+"/"+wtime+"_headers.dat";
	}
	
	public static String getSessionResultFileName(String wtime) {
		return SESSION_OUTPUT_PATH+"/"+wtime+"_sessions.dat";
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
	
	/**
	 *  UID = L4PROTO^L7PROTO^SRCIP^SRCPORT^DSTIP^DSTPORT
	 * */
	public static String makeUid(String l4, String l7, String sip, String sport, String dip, String dport) {		
		return l4+KEY_DELI+l7+KEY_DELI+sip+KEY_DELI+sport+KEY_DELI+dip+KEY_DELI+dport;		
	}
	
	public static final String[] HTTP_HEADER_LIST = HeaderList.HTTP_HEADER_LIST;
	public static final String[] FTP_HEADER_LIST = HeaderList.FTP_HEADER_LIST;
	
	
}
