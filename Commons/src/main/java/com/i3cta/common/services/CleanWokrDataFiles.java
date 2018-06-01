package com.i3cta.common.services;

import java.io.IOException;

import com.i3cta.commons.Context;

public class CleanWokrDataFiles {

	void doClean(String wtime) {
		
		String[] command = {Context.CLEANUP_DATA_COMMAND, wtime};
		Process p;
		try {
			p = Runtime.getRuntime().exec(command);
			p.waitFor();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	}
	
	public static void main(String args[]) {
		
		String wTime = args[0];
		
		new CleanWokrDataFiles().doClean(wTime);
		
	}
	
}
