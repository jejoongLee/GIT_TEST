package com.i3cta.headers.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;

import jodd.util.StringUtil;

public class NdpiResultHandler {
	
	    private Logger logger = LoggerFactory.getLogger(getClass());
	
	    public List<String> skippedLines = new ArrayList<String>();
	    public String deli = "|";
	
	
	    
	    
	    /*   
		 * INPUT :
		 * NDPI Result 파일
		 *     
		 * OUTPUT:
		 *  LIST< [L4_Protocol, L7_Protocol, SRC_IP, SRC_PORT, DST_IP, DST_PORT] >
		 *    i.e.)  List<[TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22]>
		 */	    
	    
	    public ArrayList<String[]> getTupleList(String wtime) throws FileNotFoundException {
	    	return getTupleListWFile(Context.getNDPIResultFileName(wtime) , wtime);
	    }
	    
		public ArrayList<String[]> getTupleListWFile(String fileName, String wtime) throws FileNotFoundException {
		
			logger.debug("READ-NDPI & GET TUPLE LIST with file="+fileName);
			File file = new File(fileName);
			Scanner inputFile = new Scanner(file);
			ArrayList<String[]> list = new ArrayList<String[]>();

			String aLine = "";
			String[] paLine = null;
			while (inputFile.hasNextLine()) {
				aLine = inputFile.nextLine();				
				paLine = getIpProtoInRow(aLine,wtime);
				if(paLine != null) {list.add(paLine);} 
			}
			inputFile.close();
			logger.info("NDPI_TUPLE_UID_MAP / NEW_SESSION_LIST_UNCLOSED / NDPI_TUPLE_LIST Are Finished.");
			
		return list;
		
	}

	
		/*   
		 * INPUT :
		 *  
		 *  03/May/2018 10:26:14|TCP|192.168.202.182|49862|<->|192.168.101.20|22|92|SSH|11 pkts|876 bytes|<->| 13 pkts|2910 bytes|||||
		 *                     0| 1 |      2        |  3  | 4 |     5        |6 | 7| 8 |  
		 * OUTPUT:
		 * 
		 *  [L4_Protocol, L7_Protocol, SRC_IP, SRC_PORT, DST_IP, DST_PORT]
		 *  i.e. [TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22]
		 */
	private String[] getIpProtoInRow(String line, String wtime) {
		
		String[] lineArr = null;		
		String[] parsed = StringUtil.split(line, deli);
		String[] UIDArr = new String[3]; //[UID,L4Proto,L7Proto]
		
		if(parsed == null || parsed.length < 2) {
			logger.debug("[@ndpiResultParse]Skipped Line="+line);	
			skippedLines.add(line);
			return null;
		}else {
			String mapKey = Context.makeMapKey(parsed[2],parsed[3],parsed[5],parsed[6]); //SRCIP^SRCPORT^DSTIP^DSTPORT
			String uid = Context.makeUid(parsed[1],parsed[8],parsed[2],parsed[3],parsed[5],parsed[6]); //L4PROTO^L7PROTO^SRCIP^SRCPORT^DSTIP^DSTPORT
			UIDArr[0] = uid;
			UIDArr[1] = parsed[1];
			UIDArr[2] = parsed[8];
//			logger.debug("@NDPI_TUPLE_UID_MAP mapKey="+mapKey);
			Context.getWTimeCollections(wtime).getNDPI_TUPLE_UID_MAP().put(mapKey, UIDArr);
			Context.getWTimeCollections(wtime).getNEW_SESSION_LIST_UNCLOSED().add(makeSessionData(uid, wtime, parsed));
			
//			logger.debug("line="+line);
//		    logger.debug("1="+parsed[1] +","+ "2="+parsed[2]+","+"3="+parsed[3] +","+"4="+parsed[4]+","+"5="+parsed[5]+","+"6="+parsed[6]+","+"7="+parsed[7]+","+"8="+parsed[8]+","+"0="+parsed[0]);
			lineArr = new String[6];
			lineArr[0] = parsed[1] == null? "": parsed[1].toUpperCase(); //L4 Proto
			lineArr[1] = parsed[8] == null? "": parsed[8].toUpperCase(); //L7 Proto
			lineArr[2] = Context.cleanIP(parsed[2]); //Src IP
			lineArr[3] = parsed[3]; //Src Port
			lineArr[4] = Context.cleanIP(parsed[5]); //Dst IP
			lineArr[5] = parsed[6]; //Dst Port
			
			return lineArr;
		}
		
	}
	
	/* * 
	 * SESSION DATA ROW = 
	 * UID | W_TIME | L4PROTO | L7PROTO | SRCIP | SRCPORT | DSTIP | DSTPORT | FIRST_PKT_TCPFLAG | LAST_PKT_TCPFLAG | FIRST_PKT_EPOCH_TIME | LAST_PKT_EPOCH_TIME | S-D_PKT_CNT | S-D BYTES | D-S_PKT_CNT | D-S BYTES 
	 * */
	String makeSessionData(String uid, String wTime, String[] parsed) {
		String sessionRow = "";
		sessionRow = uid+Context.RAWPKT_DELI+wTime+Context.RAWPKT_DELI+parsed[1]+Context.RAWPKT_DELI+parsed[8]
				+Context.RAWPKT_DELI+Context.cleanIP(parsed[2])+Context.RAWPKT_DELI+parsed[3]
				+Context.RAWPKT_DELI+Context.cleanIP(parsed[5])+Context.RAWPKT_DELI+parsed[6]
				+Context.RAWPKT_DELI+"$F_TCP_FLAG$"+Context.RAWPKT_DELI+"$L_TCP_FLAG$"+Context.RAWPKT_DELI+"$F_TIME$"+Context.RAWPKT_DELI+"$L_TIME$"
				+Context.RAWPKT_DELI+parsed[9].substring(0, parsed[9].indexOf("pkts")).trim()
				+Context.RAWPKT_DELI+parsed[10].substring(0,parsed[10].indexOf("bytes")).trim()
				+Context.RAWPKT_DELI+parsed[12].substring(0, parsed[12].indexOf("pkts")).trim() //StringUtil.replace(parsed[12], " pkts", "")
				+Context.RAWPKT_DELI+parsed[13].substring(0,parsed[13].indexOf("bytes")).trim();
		

//	    sessionRow = uid+S_DELI+wTime+S_DELI+parsed[1]+S_DELI+parsed[8]+S_DELI+parsed[2]+S_DELI+parsed[3]+S_DELI+parsed[5]+S_DELI+parsed[6]
//				+"$F_TCP_FLAG$"+S_DELI+"$L_TCP_FLAG$"+S_DELI+"$F_TIME$"+S_DELI+"$L_TIME$"
//				+S_DELI+StringUtil.replace(parsed[9], " pkts", "")+S_DELI+StringUtil.replace(parsed[10], " bytes", "")
//				+S_DELI+StringUtil.replace(parsed[12], " pkts", "")+S_DELI+StringUtil.replace(parsed[13], " bytes", "");
		
		return sessionRow;
		
	}
	
	String cleanPktCnt(String src) {
		return StringUtil.replace(src, " pkts", "");
	}
	
	
	public static void main(String[] args) {
//		String fileName = "D:\\work\\wireshark_capture\\unitTest\\2018-04-30_1714.ndpiresult";
		String wtime = "2018-04-30_1714";
		NdpiResultHandler nrh = new NdpiResultHandler();
		try {
//			nrh.getTupleList(fileName);
			nrh.getTupleList(wtime);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
	}
	

	

}
