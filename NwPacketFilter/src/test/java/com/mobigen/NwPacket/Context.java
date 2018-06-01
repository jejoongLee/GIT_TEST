package com.mobigen.NwPacket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jodd.util.StringUtil;

public class Context {
	Logger logger = LoggerFactory.getLogger(getClass());	
	
	public static String OUTFILE_PATH_TSHARK_RESULT = "/root/apps/data/tsharkR";
	public static String OUTFILE_PATH_SPLITPCAP_RESULT = "/root/apps/data/capture/spl";
	public static String RUN_TCPDUMP_TEMPLATE_FILE="/root/apps/bin/tcpDumpSplitter.sh";
	public static String RUN_TSHARK_TEMPLATE_FILE="/root/apps/bin/tsharkTempls/runTshark";
	public static String WIRESHARK_INSTALL_PATH="/root/apps/wireshark-2.2.14";
	
	public static String FILE_NAME_DELI="^";
	
	public static boolean ENV_VALIDATION = false;
	
//	public static String OUTFILE_PATH_TSHARK_RESULT = "D:/work/wireshark_capture/unitTest";
//	public static String OUTFILE_PATH_SPLITPCAP_RESULT = "D:/work/wireshark_capture/unitTest/spls";

	public void initEnvs() {
		OUTFILE_PATH_TSHARK_RESULT = System.getenv("TSHARK_RSLT_PATH");
		OUTFILE_PATH_SPLITPCAP_RESULT = System.getenv("SPLIT_PCAP_PATH");
		RUN_TCPDUMP_TEMPLATE_FILE =System.getenv("TCPDUMP_SPLITTER");
		RUN_TSHARK_TEMPLATE_FILE=System.getenv("TSHARK_TEMPLATE_PATH");
		WIRESHARK_INSTALL_PATH=System.getenv("WIRESHARK_INST_PATH");
		
			if(OUTFILE_PATH_TSHARK_RESULT == null  
				|| OUTFILE_PATH_SPLITPCAP_RESULT == null
				|| RUN_TCPDUMP_TEMPLATE_FILE == null
				|| RUN_TSHARK_TEMPLATE_FILE == null
				|| WIRESHARK_INSTALL_PATH == null
				|| "".equals(OUTFILE_PATH_TSHARK_RESULT)
				|| "".equals(OUTFILE_PATH_SPLITPCAP_RESULT)
				|| "".equals(RUN_TCPDUMP_TEMPLATE_FILE)
				|| "".equals(RUN_TSHARK_TEMPLATE_FILE)
				|| "".equals(WIRESHARK_INSTALL_PATH)
				) 
			{
				ENV_VALIDATION = false;
				System.out.println("MUST RUN FIRST : $APP_HOME/source env-config" );
			}else {
				ENV_VALIDATION = true;
			}
	}
	
	public static String cleanIP(String src) {
		
		src = StringUtil.replace(src, "[", "");
		src = StringUtil.replace(src, "]", "");		
		
		return src;
	}
	
	
}
