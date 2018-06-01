package com.i3cta.packet.util;

import org.apache.commons.lang.StringUtils;

import com.i3cta.commons.Context;

import jodd.util.StringUtil;

public class PcapSplitHandler {
	
	
//	private String cmdTemplate = "tcpdump '(src^^$SRCIP$^^and^^src^^port^^$SRCPORT$^^and^^dst^^$DSTIP$^^and^^dst^^port^^$DSTPORT$)^^or^^(src^^$DSTIP$^^and^^src^^port^^$DSTPORT$^^and^^dst^^$SRCIP$^^and^^dst^^port^^$SRCPORT$)' -r $PCAPFILE$ -w $OUTFILE$";
	
	
	public String[] getTcpDumpCmd(String[] tuple, String pcapFile, String jobTime) {
		
//		String cmdval = cmdTemplate;
		String[] cmdval = new String[7]; 
				cmdval[0] = Context.RUN_TCPDUMP_TEMPLATE_FILE;
				cmdval[1] = Context.cleanIP(tuple[2]);
				cmdval[2] = tuple[3];
				cmdval[3] = Context.cleanIP(tuple[4]);
				cmdval[4] = tuple[5];
				cmdval[5] = pcapFile;				
				cmdval[6] = cmdval[6] = Context.OUTFILE_PATH_SPLITPCAP_RESULT+"/"+tuple[0]+Context.FILE_NAME_DELI+tuple[1]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[2])+Context.FILE_NAME_DELI+tuple[3]+Context.FILE_NAME_DELI+Context.cleanIP(tuple[4])+Context.FILE_NAME_DELI+tuple[5]+Context.FILE_NAME_DELI+jobTime+".pcap";
				
//		cmdval = StringUtil.replace(cmdval,"$PCAPFILE$",pcapFile);
//	    cmdval = StringUtil.replace(cmdval,"$SRCIP$",tuple[2]);
//	    cmdval = StringUtil.replace(cmdval,"$SRCPORT$",tuple[3]);
//	    cmdval = StringUtil.replace(cmdval,"$DSTIP$",tuple[4]);
//	    cmdval = StringUtil.replace(cmdval,"$DSTPORT$",tuple[5]);
//	    cmdval = StringUtil.replace(cmdval,"$OUTFILE$",Context.OUTFILE_PATH_SPLITPCAP_RESULT+"/"+tuple[0]+"_"+tuple[1]+"_"+tuple[2]+"_"+tuple[3]+"_"+tuple[4]+"_"+tuple[5]+"_"+jobTime+".pcap");
//			
//		cmdval = cmdval+" "+tuple[2]+" "+tuple[3]+" "+tuple[4]+" "+tuple[5]+
//	    
		return cmdval; 
	}
	
	
	
	

}
