package com.mobigen.NwPacket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ThreadPoolTest {

	
	public static void main(String[] args) {
	
		
ExecutorService exeThreadPool = Executors.newFixedThreadPool(2);
		
List<String> tsharCmdList = new ArrayList<String>();
tsharCmdList.add("cmd.exe /c echo 1");
tsharCmdList.add("cmd.exe /c echo 2");
tsharCmdList.add("cmd.exe /c echo 3");
tsharCmdList.add("cmd.exe /c echo 4");

		for(String command : tsharCmdList) {
			
					Runnable taskWorker = new Runnable() {
						int cnt = 5;
				

						@Override
						public void run() {
							while(cnt > 0) {
								try {
									System.out.println(command);
									Runtime.getRuntime().exec(command);
								} catch (IOException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}
								System.out.println(Thread.currentThread().getName() +" cnt="+cnt);
								try {
									Thread.currentThread().sleep(50);
								} catch (InterruptedException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								cnt--;
							}
								
							
						}
					};
			
			exeThreadPool.execute(taskWorker);	
		}
		
		exeThreadPool.shutdown();
		
		while(!exeThreadPool.isTerminated()) {
			System.out.print(".");
			}
		
		System.out.println("tShark Command Execution Finished.");
		
	}
	
}
