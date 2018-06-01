package com.i3cta.NwPacket;

import java.util.HashMap;

import com.i3cta.commons.WtimeCollections;

public class TEST {

	static HashMap<String,WtimeCollections> hm = new HashMap<String,WtimeCollections>();
	
	
	public static void init() {
		
		WtimeCollections wc1 = new WtimeCollections();
		wc1.init("1");
		wc1.setWtime("10");
//		wc1.wtime = "10";
		hm.put("1", wc1);
		
		WtimeCollections wc2 = new WtimeCollections();
		wc2.init("2");
//		wc2.wtime = "30";
		wc2.setWtime("20");
		hm.put("2", wc2);
		
		
	}
	
	public static void main(String[] args) {
		TEST.init();
		System.out.println("1:"+hm.get("1").getWtime() +" 2:"+hm.get("2").getWtime());
//		System.out.println("1:"+hm.get("1").wtime +" 2:"+hm.get("2").wtime);
		
	}
	
	
}
