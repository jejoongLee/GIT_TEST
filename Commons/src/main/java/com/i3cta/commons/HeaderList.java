package com.i3cta.commons;

public class HeaderList {

	public static String[] HTTP_HEADER_LIST = { 
			"uid"
			,"frame.time_epoch"
			,"srcip"          
			,"srcport"     
			,"dstip"          
			,"dstport"     
			,"tcp.flags"       
			,"l4proto"         
			,"l7proto"
			,"request.accept"
			,"request.accept-charset"
			,"request.accept-encoding"
			,"request.accept-language"
			,"request.accept-datetime"
			,"request.access-control-request-method"
			,"request.access-control-request-headers"
			,"request.authorization"
			,"request.cache-control"
			,"request.connection"
			,"request.cookie"
			,"request.content-length"
			,"request.content-md5"
			,"request.content-type"
			,"request.date"
			,"request.expect"
			,"request.forwarded"
			,"request.from"
			,"request.host"
			,"request.if-match"
			,"request.if-modified-since"
			,"request.if-none-match"
			,"request.if-range"
			,"request.if-unmodified-since"
			,"request.max-forwards"
			,"request.origin"
			,"request.pragma"
			,"request.proxy-authorization"
			,"request.range"
			,"request.referer"
			,"request.te"
			,"request.user-agent"
			,"request.upgrade"
			,"request.via"
			,"request.warning"
			,"response.access-control-allow-origin"
			,"response.access-control-allow-credentials"
			,"response.access-control-expose-headers"
			,"response.access-control-max-age"
			,"response.access-control-allow-methods"
			,"response.access-control-allow-headers"
			,"response.accept-patch"
			,"response.accept-ranges"
			,"response.age"
			,"response.allow"
			,"response.alt-svc"
			,"response.cache-control"
			,"response.connection"
			,"response.content-disposition"
			,"response.content-encoding"
			,"response.content-language"
			,"response.content-length"
			,"response.content-location"
			,"response.content-md5"
			,"response.content-range"
			,"response.content-type"
			,"response.date"
			,"response.etag"
			,"response.expires"
			,"response.last-modified"
			,"response.link"
			,"response.location"
			,"response.p3p"
			,"response.pragma"
			,"response.proxy-authenticate"
			,"response.public-key-pins"
			,"response.retry-after"
			,"response.server"
			,"response.set-cookie"
			,"response.strict-transport-security"
			,"response.trailer"
			,"response.transfer-encoding"
			,"response.tk"
			,"response.upgrade"
			,"response.vary"
			,"response.via"
			,"response.warning"
			,"response.www-authenticate"
			,"response.x-frame-options"};	

	public static String[] FTP_HEADER_LIST = { 
			"uid"
			,"frame.time_epoch"
			,"srcip"          
			,"srcport"     
			,"dstip"          
			,"dstport"     
			,"tcp.flags"       
			,"l4proto"         
			,"l7proto"
			,"request.command"
		    ,"response"
	};	
	
}
