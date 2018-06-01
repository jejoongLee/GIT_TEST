package com.i3cta.packet.util;

import java.util.HashMap;
import java.util.Map;

import com.i3cta.commons.Context;

public class TsharkCmdHandler {
	Map<String,String> cmdTemplate = new HashMap<String, String>();
	
	String cmd_tcp_http_key = "TCP:HTTP";
//	String cmd_tcp_http_val =  "tshark -r $PCAPFILE$ -Y '(ip.src == $SRCIP$ && tcp.srcport == $SRCPORT$ && ip.dst == $DSTIP$ && tcp.dstport == $DSTPORT$ ) || (ip.src == $DSTIP$ && tcp.srcport == $DSTPORT$ && ip.dst == $SRCIP$ && tcp.dstport == $SRCPORT$ )' -O tcp,http -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e http.request.method -e http.authorization -e http.connection -e http.request.line -e http.response.line > $OUTFILE$";
	String cmd_tcp_http_val =  "tshark -r $PCAPFILE$ -Y \"(ip.src == $SRCIP$ && tcp.srcport == $SRCPORT$ && ip.dst == $DSTIP$ && tcp.dstport == $DSTPORT$ ) || (ip.src == $DSTIP$ && tcp.srcport == $DSTPORT$ && ip.dst == $SRCIP$ && tcp.dstport == $SRCPORT$ )\" -O tcp,http -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e http.request.method -e http.authorization -e http.connection -e http.request.line -e http.response.line -w $OUTFILE$";
//	String cmd_tcp_http_val =  "tshark -r $PCAPFILE$ -Y \"(ip.src == $SRCIP$ && tcp.srcport == $SRCPORT$ && ip.dst == $DSTIP$ && tcp.dstport == $DSTPORT$ ) || (ip.src == $DSTIP$ && tcp.srcport == $DSTPORT$ && ip.dst == $SRCIP$ && tcp.dstport == $SRCPORT$ )\" -O tcp,http -T json -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e http.request.method -e http.authorization -e http.connection -e http.request.line -e http.response.line > $OUTFILE$";

	String cmd_general_key = "GENERAL";
	String cmd_general_val = "tshark -r $PCAPFILE$ -Y \"(ip.src == $SRCIP$ && tcp.srcport == $SRCPORT$ && ip.dst == $DSTIP$ && tcp.dstport == $DSTPORT$ ) || (ip.src == $DSTIP$ && tcp.srcport == $DSTPORT$ && ip.dst == $SRCIP$ && tcp.dstport == $SRCPORT$ )\" -T json -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.ack -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.fin -e tcp.flags.ns -e tcp.flags.push -e tcp.flags.res -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg > $OUTFILE$";
	
	
	
	public TsharkCmdHandler() {		
		initCmdTemplates();
	}
	
	private void initCmdTemplates() {
		cmdTemplate.put(cmd_tcp_http_key, cmd_tcp_http_val);
		cmdTemplate.put(cmd_general_key, cmd_general_val);
		
	}
	
    private String protoTemplKeyMapper(String[] tuple) {
		String rawKey = tuple[0]+":"+tuple[1];
    	String mappedKey = "";
    	mappedKey = rawKey.contains(cmd_tcp_http_key) ? "_TCP_HTTP": "";
    	
		return mappedKey;
	}
	
	public String[] getTsharkCmd(String[] tuple, String pcapFile,String jobTime) {		
		String key = "";
		key = protoTemplKeyMapper(tuple);
		if("".equals(key)) {
			// no template available
			return null;
		}
		String cmd = cmdTemplate.get(key);
		return replaceParams(cmd,key, pcapFile,tuple,jobTime);
	}
	
	private String[] replaceParams(String notInUse,String key, String pcapFile,String[] tuple, String jobTime) {
		
		String[] cmdval = new String[8];
		cmdval[0]=Context.RUN_TSHARK_TEMPLATE_FILE+key+".sh";
		cmdval[1] = Context.cleanIP(tuple[2]);
		cmdval[2] = tuple[3];
		cmdval[3] = Context.cleanIP(tuple[4]);
		cmdval[4] = tuple[5];
		cmdval[5]=Context.OUTFILE_PATH_SPLITPCAP_RESULT+"/"+tuple[0]+Context.FILE_NAME_DELI+tuple[1]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[2])+Context.FILE_NAME_DELI+tuple[3]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[4])+Context.FILE_NAME_DELI+tuple[5]+Context.FILE_NAME_DELI+jobTime+".pcap";
		cmdval[6]=Context.OUTFILE_PATH_TSHARK_RESULT+"/"+tuple[0]+Context.FILE_NAME_DELI+tuple[1]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[2])+Context.FILE_NAME_DELI+tuple[3]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[4])+Context.FILE_NAME_DELI+tuple[5]+Context.FILE_NAME_DELI+jobTime+".txt";
		cmdval[7]= "-f";

		return cmdval;
		
	}
	

	
	
}
