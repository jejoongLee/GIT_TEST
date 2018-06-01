package com.i3cta.SessionBuilder;

/**
 * Hello world!
 *
 */
public class Main 
{
	
	public void process() {
		
		// SESSION BUILD LOGIC
		//
		//Tables [OPEN-SESSION], [CLOSE-READY] ,[FIN-SESSION], [UN-CLOSED] , [ERR_ALREADY_FIN]
		
		// 1. Watch Session Data File(SDF) Dir
		// 2. Parse SDF and then add "Received time" @ each line.
		// 3. For Each line(for each 6-tuple) Get a Data From [OPEN-SESSION]
		// 4. IF Exist at [OPEN-SESSION],
		//				IF the New has FIN or RST, 4-1) Update Last-Packet-Time & FLAG
		//										   4-2) MOVE [OPEN-SESSION] TO [CLOSE-READY]
		//				ELSE 4-1)
		//    ELSE       IF the New NOT have FIN or RST || have SYN,
		//										   4-3) PUT TO [OPEN-SESSION]
		//				ELSE IF the New have FIN or RST
		//										IF EXIST at [CLOSE-READY]
		//										   Do 4-1) & MOVE TO [FIN-SESSION] 	
		//										ELSE IF EXIST at [FIN-SESSION]	
		//										   PUT TO [ERR_ALREADY_FIN] 버리는거
		//										ELSE IF EXIST at [UN-CLOSED]
		//											
		//										ELSE PUT TO [UN-CLOSED]
		
		// SESSION MANAGEMENT LOGIC
		// 1. [OPEN-SESSION] 에서 older than 3분  -> [UN-CLOSED] (move Phase)
		// 2. [CLOSE-READY] 에서 older than 3분 -> [FIN-SESSION] (move Phase)
		// 3. [FIN-SESSION] 에서 older than 24*60분 -> 삭제
		// 4. [FIN-SESSION] 에 PUT 할때, 파일로 쓰기 행위 동시.(또는 전송)
		
		
	}
	
    public static void main( String[] args )
    {
        Main m = new Main();
        m.process();
    }
}
