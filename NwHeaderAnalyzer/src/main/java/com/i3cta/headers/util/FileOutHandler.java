package com.i3cta.headers.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class FileOutHandler {

	
	public static void dumpToFile(String outputFileName, List<String> list) throws IOException {
		BufferedWriter bwr = new BufferedWriter(new FileWriter(new File(outputFileName)));
		for(String row: list) {
			bwr.write(row+"\n");	
		}		
		bwr.flush();
		bwr.close();
	}
	
	
	
}
