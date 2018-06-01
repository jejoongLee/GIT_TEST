package com.mobigen.NwPacket;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.packet.util.NdpiResultHandler;
import com.i3cta.packet.util.TsharkCmdHandler;

import concurrents.OneTimeThread;
import jodd.util.StringUtil;

/*
 * 
 *  * Ndpi 의 수행결과파일의 flow 별 조합을 기반을  Tshark 명령어를 만들어 실행 
 *  * flow 별 Tshark 명령어를 만든다 
 * 
 * 
 */



public class Main2 {

	public static void main(String args[]) {
		
		
//		String env1 = System.getenv("RAW_PCAP_PATH");
//		String env2 = System.getenv("SPLIT_PCAP_PATH");
//		String env3 = System.getenv("NDPI_RSLT_PATH");
//		String env4 = System.getenv("TSHARK_RSLT_PATH");
//		
//		System.out.println("RAW_PCAP_PATH="+env1+ " SPLIT_PCAP_PATH="+env2 + " NDPI_RSLT_PATH="+env3 + " TSHARK_RSLT_PATH="+env4);


//		HashMap<String,String> org1 = new HashMap<String,String>();
//		org1.put("1","1a");
//		org1.put("2","2a");
//		org1.put("3","3a");
//		
//		HashMap<String,String> org2 = null;
//		
//		org2 = (HashMap<String, String>) org1.clone();
//		org2.put("1", "1b");
//		
//		System.out.println(org1.get("1"));
//		System.out.println(org2.get("1"));
//		
		
//ArrayList<String> list = new ArrayList<String>();
//list.add("a");
//list.add("b");
//list.add("c");
//list.add("d");
//list.add("e");
//		
//
//System.out.println("0:"+list.get(0));
//System.out.println("1:"+list.get(1));
//System.out.println("2:"+list.get(2));
//System.out.println("3:"+list.get(3));
//System.out.println("4:"+list.get(4));
//
//list.remove(0);
//
//System.out.println("0:"+list.get(0));
//System.out.println("1:"+list.get(1));
//System.out.println("2:"+list.get(2));
//System.out.println("3:"+list.get(3));



//String test = "30758 bytes[Host: spi.naver.net]";
//
//System.out.println(test.substring(0,test.indexOf("bytes[")).trim());

		
//String filename1 = "1";
//String filename2 = "2";
//String temp = filename1;
//filename1 = filename2;
//System.out.println(temp);


		
	}
	
}
