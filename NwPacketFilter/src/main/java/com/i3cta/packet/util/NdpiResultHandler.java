package com.i3cta.packet.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	    
		public List<String[]> get_List_Ip_Protocol(String fileName) throws FileNotFoundException {
		
			File file = new File(fileName);
			Scanner inputFile = new Scanner(file);
			List<String[]> list = new ArrayList<String[]>();

			String aLine = "";
			String[] paLine = null;
			while (inputFile.hasNextLine()) {
				aLine = inputFile.nextLine();				
				paLine = get_Line_Ip_Protocol(aLine);
				if(paLine != null) {list.add(paLine);} 
			}
		
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
		 *  [TCP, SSH, 192.168.202.182, 49862, 192.168.101.20, 22]
		 */
	private String[] get_Line_Ip_Protocol(String line) {
		
		String[] lineArr = null;		
		String[] parsed = StringUtil.split(line, deli);
		
		if(parsed == null || parsed.length < 2) {
			logger.debug("[@ndpiResultParse]Skipped Line="+line);	
			skippedLines.add(line);
			return null;
		}else {
			System.out.println("line="+line);
		    System.out.println("1="+parsed[1] +","+ "2="+parsed[2]+","+"3="+parsed[3] +","+"4="+parsed[4]+","+"5="+parsed[5]+","+"6="+parsed[6]+","+"7="+parsed[7]+","+"8="+parsed[8]+","+"0="+parsed[0]);
			lineArr = new String[6];
			lineArr[0] = parsed[1] == null? "": parsed[1].toUpperCase(); //L4 Proto
			lineArr[1] = parsed[8] == null? "": parsed[8].toUpperCase(); //L7 Proto
			lineArr[2] = parsed[2]; //Src IP
			lineArr[3] = parsed[3]; //Src Port
			lineArr[4] = parsed[5]; //Dst IP
			lineArr[5] = parsed[6]; //Dst Port
			
			return lineArr;
		}
		
	}
	

	

}
