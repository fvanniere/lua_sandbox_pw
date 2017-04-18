-- This Source Code Form is subject to the terms of the MIT License

-- Copyright 2016 Frédéric VANNIÈRE <f.vanniere@planet-work.com>

--[[


## Functions

### get_prog_grammar

Retrieves the parser for a particular program.

*Arguments*
- prog (string) - program name e.g. "CRON", "dhclient", "dhcpd"...

*Return*
- grammar (LPEG user data object) or nil if the `programname` isn't found

### get_wildcard_grammar

*Arguments*
- prog (string) - program name, currently only accepts "PAM"

*Return*
- grammar (LPEG user data object) or nil if the `programname` isn't found
--]]


local string = require "string"
local l = require "lpeg"
local syslog = require"lpeg.syslog"
local ip = require "lpeg.ip_address"
local dt = require "lpeg.date_time"
l.locale(l)
local tonumber = tonumber
local type = type
local rawset = rawset

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module

local prog_grammar = {}
local wildcard_grammar = {}

-- LPEG helpers
local integer = (l.P"-"^-1 * l.digit^1) / tonumber
local float = (l.P"-"^-1 * l.digit^1 * (l.P"." * l.digit^1)^1) / tonumber
local ipv4    = l.Ct(l.Cg(ip.v4, "value") * l.Cg(l.Cc"ipv4", "representation"))
local ipv6    = l.Ct(l.Cg(ip.v6, "value") * l.Cg(l.Cc"ipv6", "representation"))
local ipv46   = ipv4 + ipv6

local CHAR = l.R"\0\127"
local SPACE = l.S"\40\32"
local CTL = l.R"\0\31" + l.P"127******"
local SPECIALS = l.S[=[()<>@,;:\".[]]=]
local atom = (CHAR-SPECIALS-SPACE-CTL)^1
local dtext = CHAR - l.S"[]\\\13"
local qtext = CHAR - l.S'"\\\13'
local quoted_pair = "\\" * CHAR
local domain_literal = l.P"[" * ( dtext + quoted_pair )^0 + l.P"]"
local quoted_string = l.P'"' * ( qtext + quoted_pair )^0 * l.P'"'
local word = atom + quoted_string

local domain = l.P {
    l.V"sub_domain" * ( l.P"." * l.V"sub_domain" )^0 ;
    sub_domain = l.V"domain_ref" + domain_literal ;
    domain_ref = atom ;
}

local email = l.P {
    l.V"addr_spec" ;
    addr_spec = l.V"local_part" * l.P"@" * l.C(domain) ;
    local_part = word * ( l.P"." * word )^0 ;
}


local function capture_until(var, txt)
    return l.Cg((l.P(1) - l.P(txt))^0, var)
end
local function capture_followed_by(var, txt)
    return capture_until(var, txt) * l.P(txt)
end


--[[    Apache Error / PHP     ]]--
local aploglevel    = ( l.P"emerg" / "0"
                      + l.P"alert" / "1"
                      + l.P"crit"  / "2"
                      + l.P"error" / "3"
                      + l.P"warn"  / "4"
                      + l.P"notice"/ "5"
                      + l.P"info"  / "6"
                      + l.P"debug" / "7"
                      + (l.P"trace" * l.digit) / "7") / tonumber
local aplog_name    =   l.P"emerg"
                      + l.P"alert"
                      + l.P"crit"
                      + l.P"error"
                      + l.P"warn"
                      + l.P"notice"
                      + l.P"info"
                      + l.P"debug"
                      + (l.P"trace" * l.digit)

local phperrlevel   = (
       l.P"Fatal error"           / "0"
     + l.P"Parse error"           / "1"
     + l.P"Catchable fatal error" / "2"
     + l.P"Warning"               / "3"
     + l.P"Deprecated"            / "4"
     + l.P"Strict Standards"      / "5"
     + l.P"Notice"                / "6"
     + l.P"Debug"                 / "7")  / tonumber
local phperr_name   =
       l.P"Fatal error"
     + l.P"Parse error"
     + l.P"Catchable fatal error"
     + l.P"Warning"
     + l.P"Deprecated"
     + l.P"Strict Standards"
     + l.P"Notice"
     + l.P"Debug"

local phplog = (
       l.P"PHP " 
      * capture_followed_by("php_severity", ": ")
      * capture_until("phpErrDetails", " in /") * l.P" in "
      * capture_followed_by("filename", " on line ")
      * integer
      * (
	      (l.P", referer: " * capture_until("http_referer",-1))
		 +l.P(-1)
		 )
)
local apache22log = (
      ( l.P"script '" * capture_followed_by("filename", "'"))
	+ ( capture_followed_by("apache_error",-1) ) 
)
local apache24log = (
      ( l.P"script '" * capture_followed_by("filename", "'"))
	 +( capture_followed_by("apache_error",-1) ) 
)
prog_grammar["apache-error"] = l.Ct(
    l.P"["
  * (l.Cg(dt.build_strftime_grammar("%a %b %d %T.%f %Y") / dt.time_to_ns, "timestamp") -- nanosecond time
    + l.Cg(dt.build_strftime_grammar("%a %b %d %T %Y") / dt.time_to_ns, "timestamp"))
  * l.P"] "
  * (   -- Apache 2.4 
        (( l.P"[" * capture_followed_by("apache_module",":") * l.Cg(aplog_name,"apache_severity") * l.P"] ")^-1
		* l.P"[pid "
        * capture_followed_by("pid", "] ") 
        * (l.P"[vhost "
           * capture_followed_by("http_host", "] "))^-1
        * (l.P"[client "
           * l.Cg((ip.v4+ip.v6),"remoteAddr")
		   * l.P":"
           * l.Cg(integer, "remotePort")
           * l.P"] ") ^-1
	     )
      + ( -- Apache 2.2
	    l.P"[" * capture_followed_by("apache_severity","] ")
	    * (l.P"[client " * capture_followed_by("remoteAddr","] ")^-1)
	   ) 
      + ( -- Apache 2.2
	    l.P"[" * capture_followed_by("apache_severity","]")
	   ) 
	
	)
  * (phplog + apache22log + apache24log )
)

--[[ nginx error ]]--
local nginx_error_levels = l.Cg((
  l.P"debug"   / "7"
  + l.P"info"    / "6"
  + l.P"notice"  / "5"
  + l.P"warn"    / "4"
  + l.P"error"   / "3"
  + l.P"crit"    / "2"
  + l.P"alert"   / "1"
  + l.P"emerg"   / "0")
  / tonumber, "Severity")
local sp = l.P" "
local nginx_errdata =  l.P", client: " * l.Cg((ip.v4+ip.v6),"remoteAddr")
                 * l.P", server: " * (l.print-l.S",")^1
				 * l.P", request: \"" * capture_followed_by("http_method", " ") *  capture_followed_by("http_uri", " ") * 
				   capture_followed_by("http_protocol", "\"")
				 * (l.P", upstream:" * (l.print-l.S",")^1)^-1
				 * l.P", host: \"" * capture_followed_by("http_host", "\"")
local nginx_payload = ((l.P"stat()" + l.P"open()" + l.P"testing") * l.P" \"" * capture_followed_by("filename", "\"") * (l.print-l.S",")^0 * nginx_errdata)
                + (l.P"lua udp socket read timed out" * nginx_errdata)
			    + l.P(1)^0
prog_grammar["nginx-error"] = l.Ct(l.Cg(dt.build_strftime_grammar("%Y/%m/%d %T") / dt.time_to_ns, "timestamp")
                           --* l.space * "[" * nginx_error_levels * "]"
                           * l.space * "[" * l.Cg(l.alnum^1,"nginx_severity") * "]"
                           * l.space * l.Cg(l.digit^1 / tonumber, "Pid") * "#"
                           * l.Cg(l.digit^1 / tonumber, "nginx_tid") * ": " * (l.P"*" * l.Cg(l.digit^1 / tonumber, "nginx_connection") * " ")^-1
* nginx_payload) 
    

--[[ Proftpd ]]--

prog_grammar["proftpd"] = l.Ct(
     -- FTP 
      l.Cg(l.P"ftps" + l.P"ssh2" + l.P"ftp" + l.P"sftp","ftp_protocol") * l.P" "
    * l.P"[" * l.Cg((ip.v4+ip.v6),"remoteAddr") * l.P"] "
    * capture_until("ftp_login"," ") * l.P" " 
    * ( (l.P'"' * 
                (  (l.Cg(l.P"USER","ftp_cmd") * l.P" " * capture_until("ftp_login",'"'))
                 + (l.Cg((l.upper+l.S"_")^1,"ftp_cmd") * l.P" " * capture_until("ftp_args",'"'))
                 + l.Cg((l.upper+l.S"_")^1,"ftp_cmd")
                )
          * l.P'"')
        + l.P"-"
      ) * l.P" "
    * capture_until("ftp_cwd"," ") * l.P" "
    * (l.Cg(integer, "ftp_responsecode") + l.P"-")  * l.P" "
    * (l.Cg(integer, "ftp_size") + l.P"-")
  + (
      l.Cg((ip.v4+ip.v6),"localAddr") * l.P" "
    * l.P"(" * l.Cg((ip.v4+ip.v6),"remoteAddr") * l.P"[" *  l.Cg((ip.v4+ip.v6),"remoteAddr2") * l.P"])"
    * l.P" - " 
    * capture_followed_by("ftp_message",-1)
    )
)


--[[   Dovecot  ]]--
local sp            = l.P" "
local fp            = l.P", "
local double        = l.P"-"^-1 * l.digit^1 * "." * l.digit^1 / tonumber
local protocol      = l.Cg(l.P"pop3" + l.P"imap" + l.P"lmtp" + l.P"lda" + l.P"managesieve" + l.P"auth","mail_protocol")
local dovecotuser   = (l.alnum + l.S"_@+.- ?;")^1
local messageId     = (l.alnum + l.S",;+.-_$=/{}~!&#@%[]?*'\"")^1
local messageId2    = (l.alnum + l.S":,;+.-_$=/{}~!&#@%[]?*'\"")^1
local msg           = l.P"Logged out" + l.P"Disconnected in IDLE" + l.P"Disconnected in APPEND" + l.P"Disconnected"
local connclosemsg  = l.P"Connection closed: Connection reset by peer" + l.P"Disconnected for inactivity" + l.P"Connection closed" + l.P"Disconnected in IDLE" + l.P"Disconnected in APPEND"
local method        = l.P"method=" * (l.alnum + l.P"-") ^1
local user          = l.P"user=<" * (l.Cg(dovecotuser,"mail_login") + l.P"") * l.P">"
local session       = l.P"session=<" * l.Cg((l.alnum + l.S"/+")^1,"mail_session") * l.P">"
local remoteIP      = l.P"rip=" * l.Cg(ip.v4+ip.v6,"remoteAddr")
local localIP       = l.P"lip=" * l.Cg(ip.v4+ip.v6,"localAddr")
local mpId          = l.P"mpid=" * l.digit^1
local msgid         = l.P"msgid=" * ( l.P"<"^-1 * l.Cg(messageId,"mail_msgid") * l.P">"^-1  + ( l.P"??<"*  l.Cg(messageId,"mail_msgid") * l.P">")) + ( l.P"<" * l.Cg(messageId2,"mail_msgId") * l.P">")
local tls           = (l.P"TLS" * (l.alnum + l.S" _@+.:-()")^1  ) + l.P"TLS" + l.P"secured"
local sessionData   = user * (fp * method)^-1 * fp * remoteIP * fp * localIP * (fp * mpId)^-1 * (fp * tls )^-1 * fp * session
local popData       =  l.P"top=" * integer * l.P"/" * l.Cg(integer,"out_bytes_top")  * l.P", retr=" * integer * l.P"/" * l.Cg(integer,"out_bytes_retr") * l.P", del=" * integer * l.P"/" * integer * l.P", size=" * integer
local imapData      = l.P"in=" * l.Cg(integer,"mail_inBytes") * l.P" out=" * l.Cg(integer,"mail_outBytes")
local msgAction     = (((l.alnum + l.S"+/")^1 * l.P": ")^-1 * l.P"sieve: "^-1 * msgid * ": " * l.P(1)^1 
                       + l.P"sieve: execution of script" * l.P(1)^1 
					  )
local logoutAction  = ((( l.P"Disconnected: " * msg ) + connclosemsg ) * sp * (popData+imapData))
                    + (l.P"Disconnected for inactivity")
                    + (l.P"Disconnect from " * l.print^1 )
                    + (l.P"Connect from " * l.print^1)
local errorAction   = (l.P"Error: " + l.P"Warning: ") * l.print^1
local lmtpAction    = (l.alnum+l.S"/+")^3 * l.P": "
                      * ( l.P"Sent "  + l.P"Failed to send ")
                      * l.P"message to <" * l.Cg(dovecotuser,"mail_login") * l.P">" * l.print^1
local disconnected  = (l.P"(" * integer * l.P"s idle, in=" * l.Cg(integer,"mail_inBytes") * l.P", out=" * l.Cg(integer,"mail_outBytes") * (l.P"+"*integer)^-1 * l.P", client output blocked"^-1 * l.P")")  
                     +(l.P"(state=" * integer * l.P",duration="*integer*l.P"s)" )
                     +(l.P"after 60 secs, 60 reconnects, local=" *ip.v4 * l.P":"* integer )
local proxy         =   l.P"proxy(" * email * l.P"): " 
                      * (l.P"started proxying to " + l.P"disconnecting " ) * (ip.v4+ip.v6)*(l.P":"*integer)^-1 
                      * (l.P" (Disconnected by " *  ( 
                               (l.P"client: read(size="*integer*l.P") failed:" * (l.alnum+l.S" ")^1 * disconnected)
                              + ((l.alnum+l.S" :")^1 * disconnected)
                              + ((l.print-l.P")")^1) 
                         ) * l.P")")^-1
local authfile      = (l.P"passwd-file(" + l.P"dict(" + l.P"login(") 
                       * l.Cg(dovecotuser,"mail_login") * l.P"," 
					   * l.Cg(ip.v4+ip.v6,"remoteAddr") 
					   * (l.P",<" * (l.alnum + l.S"/+")^1 * l.P">")^-1 
					   *l.P")"
local loginErr      = ( (l.P"Aborted login" * (l.P" (client didn't finish SASL auth, waited 0 secs)")^-1)
                     + l.P"Disconnected: Too many invalid commands") * l.P" (" * (l.alnum + l.S" ,")^1 * l.P")"
                     + l.P"Disconnected:" * (l.print-l.S":")^1
                     + l.P"Disconnected (" * (l.print-l.S":")^1
                     + l.P"Disconnected"
					 + l.P"Maximum number of connections from user+IP exceeded (mail_max_userip_connections="*l.digit^1*l.P")"
                     + l.P"Aborted login (client didn't finish SASL auth, waited " * integer * l.P" secs)"
					 + l.P"Error: " * (l.print-l.S":")^1 * l.P": " * (l.print-l.S":")^1 * l.P": " * (l.print-l.S")")^1 * l.P")"
					 + l.P"proxy: " *  (l.print-l.S")")^1 * l.P")" *  (l.print-l.S")")^1 * l.P")" 

local login = protocol * l.P"-login:" * sp * (  loginErr + proxy  + l.P"Login" )  * l.P": " * sessionData
local logout = protocol * l.P"(" * (integer)^-1 * (l.P", ")^-1 * l.Cg(dovecotuser,"mail_login")^-1 * l.P"): " * (msgAction + logoutAction + errorAction + lmtpAction)
local authErr = l.Cg(l.P"auth","mail_protocol") * (l.P"-worker" * (l.P"("*integer*l.P")")^-1)^-1 * l.P": " * l.P"Error: "^-1  * authfile  * l.P": " * l.print^1


prog_grammar["dovecot"] = l.Ct(
    login + logout + authErr  * -l.P(1)
)

--[[   Exim  ]]--

local sp              = l.P" "
local eximDatetime    = l.Cg(dt.build_strftime_grammar("%Y-%m-%d %T")  / dt.time_to_ns, "timestamp")
local eximId          = l.Cg(l.alnum^6 * "-" * l.alnum^6 * "-" * l.alnum^2,"mail_eximId")
local eximFlag        = l.Cg(l.P"<="  / "input"
                           + l.P"**"  / "error"
                           + l.P"=>"  / "output"
                           + l.P"->"  / "output"
                           + l.P"=="  / "defer","mail_eximFlag")
local eximPipe        = l.P"|" * (l.alnum + l.S"-:/" + l.print)^1
local mailaddr        = (l.alnum + l.S",;+.-_$=/{}~!&#@%[]?*'\"" )^1 + eximPipe
local eximInternalIP  = l.P"I=["  * l.Cg((ip.v4 + ip.v6),"localAddr") * l.P"]" *  (l.P":" * l.Cg(integer/tonumber, "localPort"))^-1
local eximIP          = l.P"[" * l.P"("^-1 * l.Cg((ip.v4 + ip.v6),"remoteAddr") * l.P"]" * l.P"*"^-1 * (sp*eximInternalIP)^-1
local eximMachineName = l.P"(" * l.Cg((l.alnum + l.S"-.[]:_")^1,"mail_machinename")  * l.P")"
local eximHostNameIP  = (l.P"["^-1 * l.Cg(domain,"mail_ehlo") * l.P"]"^-1)^-1 * (sp^-1 * eximMachineName)^-1 * sp * eximIP
local eximHost        = l.P"H="  * eximHostNameIP
local eximProtocol    = l.P"P="  * l.Cg(l.alnum^1,"mail_protocol")
local eximCertifValid = l.P"CV=" * l.Cg( mailaddr , "mail_cert")
local eximSize        = l.P"S="  * l.Cg(l.digit^1 / tonumber,"mail_size") 
local eximAuth        = l.P"A="  * (l.alnum + l.P"_")^1 * l.P":" * l.Cg(mailaddr,"eximAuth")
local eximMsgId       = l.P"id=" * l.Cg( mailaddr , "mail_msgId")
local eximTls         = l.P"X="  * capture_until("eximTls"," ")
local eximUser        = l.P"U="  * l.Cg( (l.alnum + l.S".-_")^1 , "eximUser")
local eximBounce      = l.P"R="  * l.Cg( l.alnum^6 * "-" * l.alnum^6 * "-" * l.alnum^2,"eximBounce")
local eximRouter      = l.P"R="  * l.Cg( (l.alnum + l.S"-_")^1 ,"eximRouter")
local eximTransport   = l.P"T="  * l.Cg( (l.alnum + l.S"-_*")^1,"eximTransport")
local eximTranspRes   = l.P"C="  * l.P"\"" * (
                           (l.P"250- " * (l.print-l.P"=")^1 * l.P"=" * capture_until("mail_remoteId",'"') )
                         + capture_until("eximRemoteRes",'"')
                        ) *  l.P"\""
local eximDest        = l.Cg(mailaddr,"mail_rcpt") * (sp * l.P"(" * mailaddr * l.P")")^-1 * (sp * l.P"<" * l.Cg(mailaddr,'eximMailto') * l.P">")^-1
local eximFrom        = l.P"F=<" * l.Cg(mailaddr+l.P"","mail_from")*">"
local eximRcpt        = l.P"<" * l.Cg(mailaddr,"mail_rcpt")*">"
local eximDetail      = l.P"(" * (l.alnum + l.S":-_ <>")^3 *  l.P")"
local eximErrorDetail = eximDetail * l.P": " * l.print^1
local eximFilterMsg   = (l.P"Incoming mail" +  l.P"Outgoing mail") *  l.print^1

local eximTranspInfo  = (sp*eximTls)^-1 * (sp * eximCertifValid)^-1 * (sp*l.P"K")^-1

-- Exemple: 
local eximFlagInput  =  eximId * sp * l.Cg(l.P"<="/"input","mail_eximFlag") * sp * (l.Cg(mailaddr,"mail_from") + l.P"<>") * (sp * eximBounce)^-1 * (sp * eximHost)^-1 * (sp * eximUser)^-1 * sp * eximProtocol * eximTranspInfo * (sp * eximAuth)^-1 *  (sp*l.P"K")^-1 *sp * eximSize * (sp * eximMsgId)^-1

-- Exemple: 2015-06-05 16:18:28 1Z0sRx-0005aa-0I => pi@xx.com <PI@xx.com> R=virtual_localuser T=remote_smtp_proxy H=192.168.3.143 [192.168.3.143]
local eximFlagOutput = eximId * sp * l.Cg((l.P"=>" /"output"+l.P"->"/"output"),"mail_eximFlag") * sp * (eximFilterMsg + eximDest) * (sp * eximRouter)^-1 * (sp * eximTransport)^-1 * (sp * eximHost)^-1 * eximTranspInfo * (sp*eximTranspRes)^-1 * (sp * eximDetail)^-1

-- Exemple:
local eximFlagError  = eximId * sp * l.Cg(l.P"**"/"error","mail_eximFlag") * sp * eximDest * (sp * eximRouter)^-1 * (sp * eximTransport)^-1 * (sp * eximHost)^-1 * (eximTranspInfo)^-1 * l.P": " * l.P(1)^1
-- local eximFlagError  = eximId * sp * l.Cg(l.P"**"/"error","mail_eximFlag") * sp * eximDest * (sp * eximRouter)^-1 * (sp * eximTransport)^-1 * (sp * eximHost)^-1 * eximTranspInfo *  l.P": " * l.print^1

-- Exemple: 2015-06-07 12:51:13 1Z1XGd-0007Ib-34 == admin@yrxx.com R=dnslookup T=remote_smtp defer (-46): SMTP error from remote mail server after end of data: host oa.yrxxtech.com [182.254.147.118]: 451 4.0.0 Error processing message: Unable to retrieve the data:smdksmlk 
local eximFlagDefer  = eximId * sp * l.Cg(l.P"=="/"defer","mail_eximFlag") * sp * eximDest * (sp * eximRouter)^-1 * (sp * eximTransport)^-1 * l.P" routing"^-1 * l.P" defer " * l.print^1

-- Exemple: 
local eximMsgLogline = eximId * sp * (
                          (l.P"Completed"
                         + l.P"Message is frozen"
                         + l.P"cancelled by timeout_frozen_after"
                         + l.P"** " * l.Cg((l.alnum+l.S"@_+.")^1,"eximRcpt") * l.P": " * l.P(1)^1
                         + (l.P"Frozen"  * l.print^1)
                         + (l.P"Frozen"  * l.P(1)^-1)
                         + (l.P"Spool file is locked" * l.print^1)
                         + (l.P"original recipients ignored" * l.P(1)^1)
                         + (l.P"Unfrozen" * l.print^1)
                         + (l.P"is a bounced spam" * l.print^1)
                         + l.P"rejected from " * eximRcpt * sp * eximHost * l.P(1)^1
                         + (l.P"SMTP error from remote mail server after end of data: host " * eximHostNameIP * l.P": " * l.print^1)
                         + (l.P"SMTP error from remote mail server after RCPT TO:<" * l.Cg(mailaddr,"mail_rcpt") * l.P">: host " * eximHostNameIP * l.P": " * l.print^1)
                         + (eximHostNameIP * sp * (l.P"Network is unreachable" + l.P"Connection timed out" + l.P"Connection refused"))
                         + ((l.P"Remote host " + l.P"SMTP timeout while connected to " ) * eximHostNameIP * l.print^1)
                         + l.P"original recipients ignored"
                         + (l.Cg(mailaddr,"rcpt") * l.P": error ignored" * l.print^1)
                         + (l.P"X-Sender=" * (
									 (l.Cg(mailaddr,"mail_login") * l.P" (" * l.Cg(mailaddr,"mail_from") *l.P")" * capture_followed_by("foo","[") * capture_until("remoteAddr","]"))
									 + (l.Cg(mailaddr,"mail_login") * l.P"\\n (" * l.Cg(mailaddr,"mail_from") *l.P")" * capture_followed_by("foo","[") * capture_until("remoteAddr","]"))
						            +(l.Cg((l.alnum + l.S".-_")^1,"user") 
								    	* l.P"@" * l.Cg((l.alnum + l.S".-_")^1,"tenant") 
									    * (l.P" (" * l.Cg(domain,"vhost") *l.P")")^-1 
										* l.P(1)^-1
									 )))
                         + (l.P"X-Domain=" * l.Cg((l.alnum + l.S".-_")^1,"domain") * l.P(1)^1)
                         + (l.P"DKIM: "+l.P"spam") * l.print^2)
						 + ( eximHost * l.P": " * (l.P"SMTP timeout after" 
						                         + l.P"Remote host closed connection" 
												 + l.P"TLS error" 
												 + l.P"SMTP error from remote mail") * l.print^1)
                         + ( eximHost * eximTranspInfo * sp * eximFrom * sp * l.P"rejected after DATA" * l.P": " * l.Cg(l.print^2,"eximLogMsg"))
                         + ( eximHost * sp * l.P"Warning"  * l.P": " * l.Cg(l.print^2,"eximLogMsg"))
                         + (l.P"TLS error on connection from"* sp * eximHostNameIP * sp * l.Cg(l.print^2,"eximLogMsg"))
                         + (l.P"SMTP connection lost after final dot" * sp * eximHost * sp * eximProtocol)
						 + l.P(1)^1
                         ) * l.print^-1
-- Exemple: 2015-06-05 13:59:32 TLS error on connection from (remarkablehealthcare.net) [49.248.10.42] (send): The specified session has been invalidated for some reason.
--local eximErrors = l.P"TLS error on connection from" + l.P"failed to expand condition" +  
local eximErrorConn = ( l.P"SMTP command timeout on TLS connection from" + l.P"unexpected disconnection while reading SMTP command from" + l.P"SMTP command timeout on connection from" ) * sp * eximHostNameIP * (sp * l.P"(" * l.Cg(l.print^1))^-1


-- Exemple:  fixed_login authenticator failed for (ylmf-pc) [117.207.213.26]: 535 Incorrect authentication data (set_id=contact)
local eximLoginError = l.P"fixed_" * (l.P"login" + l.P"plain") * l.P" authenticator failed for " * eximHostNameIP * l.P": " * l.digit^3 * sp * (l.alnum + l.S" ")^1 * l.P" (set_id=" * mailaddr * l.P")"  * l.print^1
eximLoginError = l.P"fixed_" * (l.P"login" + l.P"plain") * l.P" authenticator failed for " * eximHostNameIP * l.P": " * integer * sp * l.print^1
local eximLogLine    = (l.P"no IP address found for host " * domain * l.P" (during SMTP connection from " * eximHostNameIP * l.P")")
                     + (l.P"no host name found for IP address " * (ip.v4+ip.v6))
					 + l.P"SMTP call from " * eximHostNameIP *  l.print^1
                     + (l.P"SMTP connection from " * eximHostNameIP * sp * l.print^2)
                     + l.P"SMTP command timeout on TLS connection from " * eximIP
                     + l.P"SMTP command timeout on connection from " * eximIP
					 + l.P"SMTP call from " * eximMachineName * sp * eximIP * l.print^1
                     + (l.P"lowest numbered MX record points to local host: " * l.Cg(l.print^2,"eximLogMsg"))
                     + ((l.P"TLS error on connection from" + l.P"unexpected disconnection while reading SMTP command from") * sp * (eximHostNameIP + eximIP) * l.print^2)
                     + (l.P"failed to expand condition"  * sp * l.Cg(l.print^2,"eximLogMsg"))
                     + l.P"Sender " * l.Cg(mailaddr,"eximAuth") * l.P" is blacklisted"
                     + l.P"unqualified recipient rejected: <" * l.Cg(mailaddr,"eximRcpt") * l.P"> " * eximHost * l.P(1)^1
                     + (l.P"no IP address found for host" * l.print^2)
                     + (l.P"rejected MAIL command " * eximHost * l.print^1)
                     + (l.P"[" * l.P(1)^0)
                     + (l.P"daemon: accept process fork failed" * l.P(1)^0)
                     + (l.P"rejected EHLO from " * eximIP * l.P(1)^1)
                     + (l.P"rejected HELO from " * eximIP * l.P(1)^1)
                     + ((l.P"Start queue run:" + l.P"End queue run:")  * l.print^2)
                     + (l.P"SMTP protocol synchronization error " * eximDetail * l.P": " * l.P"rejected connection from " 
					            * (eximHost  + (l.P"H=" + eximIP))
								* l.P(1)^1)

local eximHostLog = eximHost * sp * (
            (l.P"sender verify" * sp * (l.P"defer"+l.P"fail") * sp * l.P"for <" * capture_until("mail_from",">") * l.print^1)
			+ (l.P"Warning:" * l.print^1)
			+ (l.P"rejected VRFY" * l.print^1)
			)

local eximRejectLog  = eximHost * eximTranspInfo * (sp*eximUser)^-1 * sp * eximFrom * (sp * eximAuth)^-1 * sp * (l.P"temporarily rejected RCPT" + l.P"rejected RCPT")* sp * eximRcpt * l.P": " *  l.Cg(l.P(1)^2,"eximLogMsg")


prog_grammar["exim"] = l.Ct(
       (eximDatetime * sp * ( eximFlagInput + eximFlagOutput + eximFlagError + eximFlagDefer + eximMsgLogline + eximLogLine + eximRejectLog + eximErrorConn + eximHostLog + eximLoginError))
     + (l.P"[" * integer * l.print^1)
       ) * -l.P(1)


--[[   sshd   ]]--
local remoteIp           = l.Cg((ip.v4+ip.v6),"remoteAddr")
local port               = l.Cg(integer,"remotePort")
local remoteIpHost       = (l.alnum + l.S".-_")^1 + remoteIp
local pid                = l.P"PID=" * l.Cg(integer,"pid")
local uid                = l.P"UID=" * l.Cg(integer,"uid")
local cmd                = l.Cg(l.print^1,"cmd")
local rsakey             = l.Cg((l.digit + l.S"abcdef:")^10,"rsakey")
local protocol           = l.P"ssh" + l.P"ssh2"
local step               = l.P"[" * (l.P"preauth" ) * l.P"]"
local user               = l.Cg((l.alnum + l.S"_-.")^1,"user")
local ssh_skip           = l.P"Set /proc/self/oom_score_adj to 0"
                         + l.P"pam_unix(sshd:auth): check pass; user unknown"
                         + l.P"pam_ldap: ldap_search_s No such object"
                         + l.P"Disconnecting: Too many authentication failures for" * l.P(1)^1
                         + l.P"Changed root directory to " * l.P(1)^1
                         + l.P"Transferred" * l.P(1)^1
                         + l.P"Address " * l.P(1)^1
                         + l.P"Failed none for " * l.P(1)^1
                         + l.P"warning: /etc/hosts.allow" * l.P(1)^1
                         + l.P"fatal: no matching mac found" * l.P(1)^1
                         + l.P"fatal: Read from socket" * l.P(1)^1
                         + l.P"Read error from remote" * l.P(1)^1
                         + l.P"error: Could not load host key" * l.P(1)^1
                         + l.P"Changed root directory to " * l.P(1)^1
                         + l.P"PAM service(sshd) ignoring max retries; " * l.P(1)^1
                         + l.P"pam_ldap: could not open secret file"  * l.P(1)^1

local ssh_conn           = (l.P"Connection from " * remoteIp * " port " * port * (l.P" on " * l.P(1)^1)^-1)
                         + (l.P"Connection closed by " * remoteIp * (sp * l.P"port" * sp * port)^-1 * (sp * step)^-1)
                         + (l.P"Closing connection to " * remoteIp * sp * l.P"port" * sp * port)
                         + (l.P"Found matching RSA key: " * rsakey)
                         + l.P"reverse mapping checking getaddrinfo for " * remoteIpHost * l.P" " * l.P(1)^1
                         + (l.P"pam_unix(sshd:session): session closed for user " * user)
                         + (l.P"refused connect from " * remoteIpHost * l.P" (" * remoteIp * l.P")")
                         + ((l.P"Postponed publickey" + l.P"Accepted publickey" + l.P"Accepted password" + l.P"Failed publickey") * l.P" for " * user * l.P" from " * remoteIp * l.P" port " * port * sp * l.P"ssh2" * (l.P": " * l.upper^1 * sp * l.Cg((l.alnum+l.S":")^1,"ssh_key"))^-1* (sp*step)^-1)
                         + (l.P"Received disconnect from " * remoteIp * l.P": " * l.print^1)
                         + l.P"User child is on pid " * integer
                         + l.P"Did not receive identification string from " * remoteIp
						 + l.P"Starting session: " * (l.P"command" + l.P"subsystem 'sftp'" + l.P"shell") * (l.P" on pts/0" )^-1*l.P" for " * user * l.P" from " * remoteIp * l.P" port " * port
                         + (l.P"Invalid user " * user * " from " * remoteIp)
                         + (l.P"input_userauth_request: invalid user " * user * sp * step)
                         + (l.P"warning:" * l.print^1)
                         + (l.P"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=" * (user+l.P"") * l.P" rhost="*remoteIp * sp * (l.P" user="*user)^-1)
                         + (l.P"PAM " * integer * l.P" more authentication failures; logname= uid=0 euid=0 tty=ssh ruser=" * (user+l.P"") * l.P" rhost="*remoteIp * sp * (l.P" user="*user)^-1)
                         + (l.P"Failed " * (l.P"password" + l.P"publickey") * l.P" for " * (l.P"invalid user " + l.P"")  * user * l.P" from " * remoteIp * l.P" port " * port * sp * l.P"ssh2" )
                         + (l.P"pam_unix(sshd:session): session opened for " * user * sp * l.print^1)

prog_grammar["sshd"]     = l.Ct(ssh_skip + ssh_conn) * -l.P(1)
prog_grammar["bash"]    = l.Ct(l.P"HISTORY:" * sp * pid * sp * uid * sp * cmd )




 --[[   spamd   ]]--
local sp            = l.P" "
local fp            = l.P","
local discard       = (l.P"child states: " * l.P(1)^1)
                       + l.P"setuid to debian-spamd succeeded"
                       + l.P"connection from " * l.print^2
                       + l.P"identified spam " * l.print^2
                       + l.P"dcc: dccproc failed: no dcc_path found"
                       + l.P"Use of uninitialized" * l.P(1)^0
                       + l.P"Invalid header block at" * l.P(1)^0
                       + l.P"dns: reply" * l.print^1
                       + l.P"prefork:" * l.P(1)^1
                       + l.P"Use of uninitialized" * l.print^1
                       + l.P"clean message " * l.print^2
                       + l.P"server successfully spawned child process" * l.print^2
                       + l.P"handled cleanup of child pid " * l.print^2
                       + l.P"checking message (unknown)" * l.print^2
                  -- + l.P"" * l.print^2

local messageId     = ( l.P"<" * l.Cg((l.alnum + l.S",+.-_$=/{}~!&#;@%[]?*:'\"" )^1,"mail_msgId") * l.P">")
                       + l.P"(unknown)"
local messagerId    = ( l.P"<" * l.Cg((l.alnum + l.S",+.-_$=/{}~!&;#@%[]?*:'\"" )^1,"mail_msgrId") * l.P">")
                      + l.P"(unknown)"
local checking = l.P"checking message " * messageId * (l.P" aka " * messagerId)^-1 * l.P" for " * l.print^2
local spamFlag = l.Cg(l.P"." + l.P"Y","flag")
local spamScore = l.Cg(integer+float,"mail_spamscore")
local spamTest = l.Cg((l.alnum + l.S"_,")^1,"mail_spamtests")
local spamSize = l.P"size=" * l.Cg(integer ,"mail_bytes")
local spamScanTime = l.P"scantime=" * l.Cg(double,"mail_scantime")
local spamUser = l.P"user=" * (l.alnum + l.S"-_.")^1
local spamUid = l.P"uid=" * integer
local spamRequired = l.P"required_score=" * (double)
local spamRemoteHost = l.P"rhost=" * (l.alnum + l.S".-_")^1
local spamRemoteIP = l.P"raddr=" * l.Cg(ip.v4 + ip.v6,"remoteAddr")
local spamRepotePort = l.P"rport=" * l.Cg(integer,"remotePort")
local spamMsgId = l.P"mid=" * messageId
local spamrMsgId = l.P"rmid=" * messagerId
local spamAutolearn = l.P"autolearn=" * l.alnum^3
local spamData = spamScanTime  * fp * spamSize * fp * spamUser * fp * spamUid * fp * spamRequired * fp * spamRemoteHost * fp * spamRemoteIP * fp * spamRepotePort * fp * spamMsgId * fp * (spamrMsgId*fp)^-1 * spamAutolearn
local result = l.P"result: " * spamFlag * sp * spamScore * l.P" - " * (spamTest * sp)^-1 * spamData
prog_grammar["spamd"] = (l.P"spamd: " + l.P"prefork: ")^-1 *  l.Ct(discard + checking + result)  * -l.P(1)


local function prefix_param_name(param_name)
     return '_' .. param_name
end
local function unescape_param_value(param_value)
    return string.gsub(param_value, '\\([]"\\])', '%1')
end
local nilvalue = l.P"-"
local octet = l.P(1)
local param_value_esc = l.S'"\\]'
local printusascii = l.R"!~"
local sd_name         = (printusascii - l.S'=]" ')^-50 -- HERE !!
local param_name = sd_name / prefix_param_name
local param_value_esc = l.S'"\\]'
local esc = l.P'\\'
local param_value     = ((octet - param_value_esc) + (esc * octet))^0 / unescape_param_value
local sd_id           = l.Cg(l.Cc"id" * l.C(sd_name))
local sd_param        = l.Cg(param_name * '="' * param_value * '"')
local sd_params       = l.Cf(l.Ct"" * sd_id * (sp * sd_param)^0, rawset)
local sd_element = l.P"[" * sd_params * "]"
prog_grammar["syslog_structured_data"] = l.Ct(
   ((l.Ct"" * nilvalue) + sd_element )
   * l.P" " * syslog.build_rsyslog_grammar("%msg%")
) 


function get_prog_grammar(prog)
    return prog_grammar[prog]
end


function get_wildcard_grammar(prog)
    return wildcard_grammar[prog]
end

return M
