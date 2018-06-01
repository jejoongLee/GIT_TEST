package com.i3cta.commons;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;

public class Utility {

	public static ArrayList<Path> getLS(String dir) throws IOException{
		ArrayList<Path> resultlist = new ArrayList<>();		
//		Files.newDirectoryStream(Paths.get(dir), path -> path.toFile().isFile() && path.toFile().length()> 0).forEach(resultlist::add);
		Files.newDirectoryStream(Paths.get(dir), path -> path.toFile().isFile()).forEach(resultlist::add);
		return resultlist;
	}
	
	public static ArrayList<Path> getLS_Sorted(String dir) throws IOException{
		ArrayList<Path> resultlist = getLS(dir);
		Collections.sort(resultlist, (o1,o2) -> o1.toString().compareTo(o2.toString()) );
		return resultlist;
	}
	
		
public static void main(String args[]) {
	try {
		ArrayList<Path> list = Utility.getLS("C:/");
		Collections.sort(list, (o1,o2) -> o1.toString().compareTo(o2.toString()) );
		for(Path p: list) {
			System.out.println(p.toString());
			
		}
	} catch (IOException e) {
	
		e.printStackTrace();
	}
	
}	
	
}
