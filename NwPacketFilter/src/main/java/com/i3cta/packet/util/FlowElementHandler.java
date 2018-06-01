package com.i3cta.packet.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class FlowElementHandler {
	
	
	 Scanner fileLoader(String fileName) throws FileNotFoundException {
		
		File file = new File(fileName);
		return new Scanner(file);
		
	}
	 
	 //동일 pcap 로 ndpi 돌려보고, cnt 에 맞게 raw 패킷 만들기.
	 
	 
	 /*
	  * 1) tshark 로 필터링된 패킷(= 아이피,포트,TCP flag, 헤더 값) 을 읽어들인다.
	  * 2) 단위 시간 내 첫 TCP 플래그 값&시간, 마지막 TCP 플래그 & 시간 값을 저장   
	  */	 
	public void getFisrtLastFlaginfo(String file) throws FileNotFoundException {
		// 1523942447.341707000, 192.168.202.182, 50240, 211.216.46.4, 80, SYN 
		Scanner input = fileLoader(file);
		String aLine = "";
		String[] parsed = null;
		String flag = "";
		String flagOfFirst = "";
		String timeOfFirst = "";
		String flagOfLast = "";
		String timeOfLast = "";
		boolean isFirst = true;
		while (input.hasNextLine()) {
			aLine = input.nextLine();			
			parsed = aLine.split(",");
			try {
				flag = parsed[5];
				if(flag != null && !"".equals(flag)) {
					if(isFirst) {
						flagOfFirst = flag;
						timeOfFirst = parsed[0]; 
						isFirst = false;
						System.out.println(aLine);
					}else {
						flagOfLast = flag;
						timeOfLast = parsed[0];						
					}
					
				}
			}catch(Exception e) {
				
			}
			 
			
		}
		System.out.println(flagOfFirst+","+timeOfFirst+","+ flagOfLast +","+timeOfLast);
	}
	
	
	
	
	public static void main(String args[]) {
		
		String file = "D:/work/wireshark_capture/demo.txt";
		
		FlowElementHandler feh = new FlowElementHandler();
		try {
			feh.getFisrtLastFlaginfo(file);
		} catch (FileNotFoundException e) {			
			e.printStackTrace();
		}
	}

}
