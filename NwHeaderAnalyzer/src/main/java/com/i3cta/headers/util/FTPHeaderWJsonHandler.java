package com.i3cta.headers.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import javax.sound.midi.Synthesizer;

import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.i3cta.commons.Context;

import jodd.util.StringUtil;

public class FTPHeaderWJsonHandler {
	Logger logger = LoggerFactory.getLogger(getClass());	

	public HashMap<String, String> FTP_HEADER_MAP = null;
	String LINE_BR = System.getProperty("line.separator");

	public FTPHeaderWJsonHandler() {
		initHeaderInfo();
	}
	
	private void retain_UID_BeginEnd_Flag_Time(String uid, String flag, String packetTime , String[] sessionElements) {
		if(sessionElements[0] == null) {
			sessionElements[0] = uid;
			sessionElements[1] = flag;
			sessionElements[2] = packetTime;
		}else {
			sessionElements[3] = flag;
			sessionElements[4] = packetTime;
		}
	
	}
	
	private String[] keyValProc(String rawStr) {
		String bf = rawStr;
		bf = StringUtil.replace(rawStr, "\r\n", "");
		String[] keyVal = StringUtil.split(bf, ":");
		return keyVal;
	}
	
	/**
	 * 	 RETURN [UID,L4Proto,L7Proto] 
	 **/
	private String[] getNdpiUIDL4L7ProtoValue(String wtime, String ip_src, String  port_src, String  ip_dst, String  port_dst) {
		logger.debug("mapKey="+Context.makeMapKey(ip_src, port_src, ip_dst, port_dst));
		String[] retVal;
		String mapKey = Context.makeMapKey(ip_src, port_src, ip_dst, port_dst);
		retVal = Context.getWTimeCollections(wtime).getNDPI_TUPLE_UID_MAP().get(mapKey);
		if(retVal == null) {
			mapKey = Context.makeMapKey(ip_dst, port_dst,ip_src, port_src);
			retVal = Context.getWTimeCollections(wtime).getNDPI_TUPLE_UID_MAP().get(mapKey);
		}
		return retVal;
	}
	
	private boolean parseL7part(JSONObject _layers, HashMap<String, String> VAL_FILLED_FTP_HEADER_MAP) {

		boolean isReq = false;
		String keyPrefix = "";
		JSONArray ftp_re = null;
		String DEBUG_reqKeyVals = "";
		String reqResHeaderObj = "";
		ftp_re = (JSONArray) _layers.get("ftp.request.command");

		if (ftp_re != null)
			isReq = true;
		else
			ftp_re = (JSONArray) _layers.get("ftp.response");

		if (ftp_re != null)
			isReq = false;
		else
			return false;

		if (isReq)
			keyPrefix = "request.";
		else
			keyPrefix = "response.";

		Iterator<String> iterReq = ftp_re.iterator();

		String hkey = "";
		while (iterReq.hasNext()) {
			reqResHeaderObj = (String) iterReq.next(); // "Date: Tue, 17 Apr 2018 05:20:43 GMT\r\n","Server:
														// Apache\r\n",
			String reqKeyVal[] = keyValProc(reqResHeaderObj); // "Date: Tue, 17 Apr 2018 05:20:43 GMT\r\n" ->
																// ["Date","Tue, 17 Apr 2018 05:20:43 GMT"]
			if (reqKeyVal[0] != null || !"".equals(reqKeyVal[0])) {
				hkey = keyPrefix + reqKeyVal[0].toLowerCase();
				if (VAL_FILLED_FTP_HEADER_MAP.containsKey(hkey)) {
					VAL_FILLED_FTP_HEADER_MAP.put(hkey, reqKeyVal[1]);
				} else {
					logger.debug("key:" + hkey + " is not exists in the Map-Key-List");
				}
			}
			DEBUG_reqKeyVals += "," + StringUtil.replace(reqResHeaderObj, "\r\n", "");
		}

		return true;
	}
	
	private boolean parseL4Part(String wtime, JSONObject _layers, HashMap<String, String> VAL_FILLED_FTP_HEADER_MAP, String[] sessionElements) {


		boolean isSuccessful = false;

		String epoch_time = "";
		String ip_src = "";
		String ip_dst = "";
		String port_src = "";
		String port_dst = "";
		String tcp_flag_str = "";
		
		JSONObject frame = (JSONObject)_layers.get("frame");
		String temp = (String)frame.get("frame.time_epoch");
		epoch_time = temp == null ? "" : (String) temp;
		
		JSONObject ip = (JSONObject)_layers.get("ip");
		JSONObject tcp = (JSONObject)_layers.get("tcp");
		JSONObject tcp_flags_tree = (JSONObject) tcp.get("tcp.flags_tree");
		
		ip_src = temp == null ? "" :(String)temp;
		if ("".equals(ip_src)) {
			return isSuccessful;
		} else {
			temp = (String) ip.get("ip.dst");
			ip_dst = temp == null ? "" : (String) temp;

			temp = (String) tcp.get("tcp.srcport");
			port_src = temp == null ? "" : (String) temp;

			temp = (String) tcp.get("tcp.dstport");
			port_dst = temp == null ? "" : (String) temp;

			String flagTemp = "";
			temp = (String) tcp_flags_tree.get("tcp.flags.ack");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",ACK" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.cwr");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",CWR" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.ecn");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",ECN" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.fin");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",FIN" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.ns");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",NS" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.push");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",PSH" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.res");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",RES" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.reset");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",RST" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.syn");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",SYN" : "";
			temp = (String) tcp_flags_tree.get("tcp.flags.urg");
			flagTemp += temp == null ? "" : Integer.parseInt((String) temp) == 1 ? ",URG" : "";
			tcp_flag_str = flagTemp.startsWith(",") ? flagTemp.substring(1) : flagTemp;
			String[] UID_L4_L7 = getNdpiUIDL4L7ProtoValue(wtime,ip_src, port_src, ip_dst, port_dst);
			
			retain_UID_BeginEnd_Flag_Time(UID_L4_L7[0], tcp_flag_str, epoch_time, sessionElements);

			
			VAL_FILLED_FTP_HEADER_MAP.put("uid", UID_L4_L7[0]);
			VAL_FILLED_FTP_HEADER_MAP.put("l4proto", UID_L4_L7[1]);
			VAL_FILLED_FTP_HEADER_MAP.put("l7proto", UID_L4_L7[2]);
			VAL_FILLED_FTP_HEADER_MAP.put("frame.time_epoch", epoch_time);
			VAL_FILLED_FTP_HEADER_MAP.put(Context.transStrToMapKey("ip.src"), ip_src);
			VAL_FILLED_FTP_HEADER_MAP.put(Context.transStrToMapKey("ip.dst"), ip_dst);
			VAL_FILLED_FTP_HEADER_MAP.put(Context.transStrToMapKey("tcp.srcport"), port_src);
			VAL_FILLED_FTP_HEADER_MAP.put(Context.transStrToMapKey("tcp.dstport"), port_dst);
			VAL_FILLED_FTP_HEADER_MAP.put("tcp.flags", tcp_flag_str);

			return isSuccessful;
		}
	}
	
	@SuppressWarnings("unchecked")
	public void handler(String file,String wtime) { //IP 파일별로 프로세스가 수행되어야 하고, 파일별 병렬처리이므로, **Thread Safe** 해야함!!!!!.
		String[] sessionElements = new String[5];//{"uid","FirstFlag","FirstPktTime","EndFlag","EndPktTime"};
		JSONParser parser = new JSONParser();

		try {			
			Object obj = parser.parse(new FileReader(file));
			
			JSONArray rawList = (JSONArray) obj;

			Iterator<JSONObject> iter = rawList.iterator();
			StringBuffer buffer = new StringBuffer();
			boolean isFirtLine = true;
			HashMap<String, String> VAL_FILLED_FTP_HEADER_MAP = null;
			String headerParsedStr = "";
			
			
			/* LOOP FOR EACH PACKET FROM JSON */
			while (iter.hasNext()) {
				
				if (!isFirtLine)
					buffer.append(LINE_BR);
				isFirtLine = false;
				JSONObject jdpt1 = iter.next();
				JSONObject _src = (JSONObject) jdpt1.get("_source");
				JSONObject _layers = (JSONObject) _src.get("layers");
				VAL_FILLED_FTP_HEADER_MAP = (HashMap<String, String>) FTP_HEADER_MAP.clone();

				if (_layers != null) {

					parseL4Part(wtime,_layers, VAL_FILLED_FTP_HEADER_MAP,sessionElements);

					parseL7part(_layers, VAL_FILLED_FTP_HEADER_MAP);

					headerParsedStr = makeTSVLine(VAL_FILLED_FTP_HEADER_MAP);

					addTSVLineToRawPktList(headerParsedStr,wtime);
				}

			}			
			Context.getWTimeCollections(wtime).getUID_UNCLOSED_ITEMS_MAP().put(sessionElements[0], sessionElements);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}

	}
	
	private void addTSVLineToRawPktList(String headerParsedStr,String wtime) {
		Context.getWTimeCollections(wtime).getNEW_RAWPKT_HEADER_PARSED_LIST().add(headerParsedStr);	
	}
	
	public void initHeaderInfo() {
		this.FTP_HEADER_MAP = new HashMap<String, String>();
		for (String el : Context.FTP_HEADER_LIST)
			FTP_HEADER_MAP.put(el, "");
	}
	
	private String makeTSVLine(HashMap h) {
		String headerRow = "";
		String val = "";
		for (String k : Context.FTP_HEADER_LIST) {
			val = (String) h.get(k);
//			if (val != null && !"".equals(val))

				headerRow = headerRow+Context.RAWPKT_DELI + val;
		}
		headerRow = StringUtil.replaceFirst(headerRow, Context.RAWPKT_DELI, "");
//		System.out.println(headerRow);
		return headerRow;

	}
	
	public static void main(String args[]) {

		FTPHeaderWJsonHandler jh = new FTPHeaderWJsonHandler();

		String file = "OUTFILE_PATH_TSHARK_RESULT";
		String type = "";

		jh.initHeaderInfo();
		jh.handler(file,"");
		// jh.initHeaderInfo();

	}
	/*************************************************
	 *
	 * Sample Single Packet Header Format at given JSON { "_index":
	 * "packets-2018-05-03", "_type": "pcap_file", "_score": null, "_source": {
	 * "layers": { "frame.time_epoch": ["1523942447.350996000"], "ip.src":
	 * ["211.216.46.4"], "tcp.srcport": ["80"], "ip.dst": ["192.168.202.182"],
	 * "tcp.dstport": ["50240"], "tcp.flags.ack": ["1"], "tcp.flags.cwr": ["0"],
	 * "tcp.flags.ecn": ["0"], "tcp.flags.fin": ["0"], "tcp.flags.ns": ["0"],
	 * "tcp.flags.push": ["1"], "tcp.flags.res": ["0"], "tcp.flags.reset": ["0"],
	 * "tcp.flags.syn": ["0"], "tcp.flags.urg": ["0"], "http.response.line": ["Date:
	 * Tue, 17 Apr 2018 05:20:46 GMT\r\n","Server: Apache\r\n","Last-Modified: Thu,
	 * 12 Apr 2018 08:18:18 GMT\r\n","Accept-Ranges: bytes\r\n","Cache-Control:
	 * max-age=2592000\r\n","Vary: Accept-Encoding\r\n","Content-Encoding:
	 * gzip\r\n","Content-Length: 3970\r\n","Content-Type:
	 * application\/javascript\r\n","Age: 421306\r\n","Expires: Sat, 12 May 2018
	 * 08:19:01 GMT\r\n"] } } }
	 * 
	 * 
	 * 
	 ************************************************/

}
