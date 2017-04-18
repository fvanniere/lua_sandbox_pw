-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.



msg = nil

function inject_message(_msg)
	msg = _msg
end

local syslog_parser = require "lpeg.syslog_parser"
local pwlog = require "decoders.syslog_pw"
local io = require"io"


local function syslog_decoder()

	log = '<38>1 2017-04-20T14:59:59.563339+02:00 server1234 sshd 23858 - [9c7105dc-a876-11e4-12412-10@34200] Connection closed by 192.168.34.3 [preauth]'
    res = pwlog.decode(log)
	assert(msg.Fields.appname == "sshd", msg.Fields.appname)
	assert(msg.Fields.remoteAddr == "192.168.34.3", msg.Fields.remoteAddr)

	log = "<134>1 2017-04-21T11:21:16.615213+02:00 flint consul 4006 - [000-0000-0000-0000-0000@34200] agent: check 'service:mutupw/php70' is passing"
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "consul", msg.Fields.appname)
	assert(msg.Hostname == "flint", msg.Hostname)
	assert(msg.Pid == 4006, msg.Pid)

	log = '<134>1 2017-04-21T11:21:16.602017+02:00 tam apache-access - - [000-0000-0000-0000-0000@34200 tag="apache"] www.website.com 193.26.11.202 - - [21/Apr/2017:11:21:06 +0200] "GET /modules/ukoo_form/form.php?content_only=1 HTTP/1.1" 200 1430 "http://www.website.com/plaque-boite-aux-lettres" "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36"'
	res = pwlog.decode(log)
	--debug(log, msg)
	assert(msg.Fields.appname == "apache-access", msg.Fields.appname)
    assert(msg.Hostname == "tam", msg.Hostname)
	assert(msg.Fields.http_host == "www.website.com", msg.Fields.http_host)
	assert(msg.Fields.http_method == "GET", msg.Fields.http_method)
	assert(msg.Fields.http_outBytes == 1430, msg.Fields.http_outBytes)
	assert(msg.Fields.http_protocol == "HTTP/1.1", msg.Fields.http_protocol)
	assert(msg.Fields.http_referer == "http://www.website.com/plaque-boite-aux-lettres", msg.Fields.http_referer)
    assert(msg.Fields.http_remoteUser == nil, msg.Fields.http_remoteUser)
	assert(msg.Fields.http_status == 200, msg.Fields.http_status)
	assert(msg.Fields.http_uri == "/modules/ukoo_form/form.php?content_only=1", msg.Fields.http_uri)
	assert(msg.Fields.http_userAgent == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36", msg.Fields.http_userAgent)
	--assert(msg.Fields.timestamp == "2017-04-21T09:21:06+0000", msg.Fields.timestamp)

	log = '<134>1 2017-04-21T11:54:50.382048+02:00 gadj nginx-access - - [000-0000-0000-0000-0000@34200 tag="nginx"] www.gadj.org 192.168.36.70 - - [21/Apr/2017:11:54:44 +0200] "POST /wp-cron.php?doing_wp_cron=1492768484.5128688812255859375000 HTTP/1.0" 200 229 "-" "WordPress/3.8.20; http://www.gadj.org" 0.432'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "nginx-access", msg.Fields.appname)
    assert(msg.Hostname == "gadj", msg.Hostname)
	assert(msg.Fields.http_host == "www.gadj.org", msg.Fields.http_host)
	assert(msg.Fields.http_method == "POST", msg.Fields.http_method)
	assert(msg.Fields.http_outBytes == 229, msg.Fields.http_outBytes)
	assert(msg.Fields.http_requestTime == 0.432, msg.Fields.http_requestTime)
	assert(msg.Fields.http_protocol == "HTTP/1.0", msg.Fields.http_protocol)
	assert(msg.Fields.http_referer == "", msg.Fields.http_referer)
    assert(msg.Fields.http_remoteUser == nil, msg.Fields.http_remoteUser)
	assert(msg.Fields.http_status == 200, msg.Fields.http_status)
	assert(msg.Fields.http_uri == "/wp-cron.php?doing_wp_cron=1492768484.5128688812255859375000", msg.Fields.http_uri)
	assert(msg.Fields.http_userAgent == "WordPress/3.8.20; http://www.gadj.org", msg.Fields.http_userAgent)

	log = '<22>1 2017-04-21T11:59:59.982632+02:00 mistral dovecot - - [000-0000-0000-0000-0000@34200] pop3-login: proxy(v.vial@mairie-xxx.fr): disconnecting 83.206.226.73 (Disconnected by server(0s idle, in=132, out=68)): user=<v.vial@mairie-xxx.fr>, method=PLAIN, rip=83.206.226.73, lip=192.168.34.25, session=<LBYMUqpN+UZTzuJJ>'
	res = pwlog.decode(log)
    assert(msg.Fields.appname == "dovecot", msg.Fields.appname)
	assert(msg.Hostname == "mistral", msg.Hostname)
	assert(msg.Fields.remoteAddr == "83.206.226.73", msg.Fields.remoteAddr)
	assert(msg.Fields.mail_login == "v.vial@mairie-xxx.fr", msg.Fields.mail_login)
	assert(msg.Fields.mail_protocol == "pop3", msg.Fields.mail_protocol)
	assert(msg.Fields.mail_inBytes == 132, msg.Fields.mail_inBytes)
	assert(msg.Fields.mail_outBytes == 68, msg.Fields.mail_outBytes)

    log = '<22>1 2017-04-21T12:09:57.762335+02:00 mistral exim 19858 - [000-0000-0000-0000-0000@34200] 2017-04-21 12:09:57 1d1VVl-0005AH-CD => video@tou.be R=vmail_user T=director_lmtp H=192.168.3.143 [192.168.3.143] X=TLS1.2:DHE_RSA_AES_256_GCM_SHA384:256 CV=no C="250 2.0.0 <video@tou.be> S2USJ3Xa+Vi9PAAAlB2uAQ Saved"'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "exim", msg.Fields.appname)
	assert(msg.Hostname == "mistral", msg.Hostname)
	assert(msg.Pid == 19858,  msg.Pid)
	assert(msg.Fields.mail_rcpt ==  "video@tou.be", msg.Fields.mail_rcpt)
	assert(msg.Fields.mail_eximFlag ==  "output", msg.Fields.mail_eximFlag)
	assert(msg.Fields.remoteAddr ==  "192.168.3.143", msg.Fields.remoteAddr)
	assert(msg.Fields.mail_eximId ==  "1d1VVl-0005AH-CD", msg.Fields.mail_eximId)

	log = '<93>1 2017-04-21T12:01:18.731176+02:00 studio proftpd 13572 - [000-0000-0000-0000-0000@34200] ftp [78.228.43.89] webmaster@ooaall.fr "LIST -a" /home/linoo/public_html/www/nous-contacter/-a 226 213'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "proftpd", msg.Fields.appname)
	assert(msg.Hostname == "studio", msg.Hostname)
	assert(msg.Pid == 13572,  msg.Pid)
	assert(msg.Fields.ftp_login == "webmaster@ooaall.fr", msg.Fields.ftp_login)
	assert(msg.Fields.remoteAddr == "78.228.43.89", msg.Fields.remoteAddr)
	assert(msg.Fields.ftp_cmd == "LIST", msg.Fields.ftp_cmd)
	assert(msg.Fields.ftp_responsecode == 226, msg.Fields.ftp_responsecode)


	log = '<22>1 2017-04-21T12:10:38.686958+02:00 yeti spamd 16086 - [000-0000-0000-0000-0000@34200] spamd: result: . 0 - FREEMAIL_FORGED_FROMDOMAIN,FREEMAIL_FROM,HEADER_FROM_DIFFERENT_DOMAINS,HTML_IMAGE_RATIO_02,HTML_MESSAGE,KAM_LOTSOFHASH,RCVD_IN_MSPIKE_H2,RP_MATCHES_RCVD,SPF_PASS,T_DKIM_INVALID,T_KAM_HTML_FONT_INVALID,URIBL_GREY scantime=2.6,size=31567,user=debian-spamd,uid=111,required_score=6.5,rhost=pixx.local.ds.planet-work.net,raddr=10.3.0.119,rport=32614,mid=<de3yCXU2T-mcdiIgnHOTIA@ismtpd0002p1iad1.sendgrid.net>,autolearn=disabled'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "spamd", msg.Fields.appname)
	assert(msg.Fields.mail_msgId == "de3yCXU2T-mcdiIgnHOTIA@ismtpd0002p1iad1.sendgrid.net", msg.Fields.mail_msgId)
	assert(msg.Fields.mail_spamscore == 0, msg.Fields.mail_spamscore)

    log = '<131>1 2017-04-21T12:05:39.967307+02:00 superdeco apache-error - - [000-0000-0000-0000-0000@34200 tag="apache"] [Fri Apr 21 12:05:38 2017] [pid 9082] [vhost www.superdeco.com] [client 138.41.3.36:21646] PHP Warning:  Invalid argument supplied for foreach() in /home/webmaster/public_html/www/classes/Cart.php on line 4055'
	res = pwlog.decode(log)
	--debug(log, msg)
	assert(msg.Fields.appname == "php", msg.Fields.appname)
	assert(msg.Hostname == "superdeco", msg.Hostname)
	assert(msg.Fields.http_host == "www.superdeco.com", msg.Fields.http_host)
	assert(msg.Fields.remoteAddr == "138.41.3.36", msg.Fields.remoteAddr)
	assert(msg.Fields.remotePort == 21646, msg.Fields.remotePort)
	assert(msg.Fields.php_severity == "Warning", msg.Fields.php_severity)
	assert(msg.Fields.timestamp == "2017-04-21T12:05:38+0200", msg.Fields.timestamp)

    log = '<78>1 2017-04-21T12:09:01.971654+02:00 kiwi CRON 26864 - [000-0000-0000-0000-0000@34200] (root) CMD (  [ -x /usr/lib/php5/sessionclean ] && /usr/lib/php5/sessionclean)'
	res = pwlog.decode(log)
	--debug(res,msg)
	assert(msg.Fields.appname == "CRON", msg.Fields.appname)
	assert(msg.Hostname == "kiwi", msg.Hostname)
	assert(msg.Fields.user == "root", msg.Fields.user)

    log = '<86>1 2017-04-21T08:00:01.168150+02:00 serv3 CRON 25881 - [000-0000-0000-0000-0000@34200] pam_unix(cron:session): session opened for user socredit by (uid=0)'
	res = pwlog.decode(log)
	--debug(res,msg)
	assert(msg.Fields.appname == "CRON", msg.Fields.appname)
	assert(msg.Fields.uid == 0, msg.Fields.uid)
	assert(msg.Fields.user == "socredit", msg.Fields.user)

	log = '<38>1 2017-04-24T00:02:58.584848+02:00 superbebe sshd 62635 - [000-0000-0000-0000-0000@34200] Set /proc/self/oom_score_adj to 0'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "sshd", msg.Fields.appname)

	log = '<21>1 2017-04-24T00:03:21.346602+02:00 kaa exim 17614 - [000-0000-0000-0000-0000@34200] [1\\4] 2017-04-24 00:03:21 fixed_login authenticator failed for (User) [80.82.70.210]: 435 Unable to authenticate at present (set_id=abuse@planet-work.net): error in perl_startup code: Can\'t locate Crypt/PasswdMD5.pm in @INC (you may need to install the Crypt::PasswdMD5 module) (@INC contains: /etc/perl /usr/local/lib/x86_64-linux-gnu/perl/5.20.2 /usr/local/share/perl/5.20.2 /usr/lib/x86_64-linux-gnu/perl5/5.20 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl/5.20 /usr/share/perl/5.20 /usr/local/lib/site_perl .) at /etc/exim4/perl-exim.pl line 4.'
	res = pwlog.decode(log)
	assert(msg.Fields.appname == "exim", msg.Fields.appname)

	log = '<38>1 2017-05-03T08:00:36.793584+02:00 dromadaire bash 20828 - [000-0000-0000-0000-0000@34200] HISTORY: PID=20828 UID=0 rm bin/*'
	res = pwlog.decode(log)
	--debug(log, msg)
	assert(msg.Fields.appname == "bash", msg.Fields.appname)
	
end


local function syslog_decoder_bulk()
    local fn = '/tmp/syslog.log'
    local fh = io.open(fn, "rb")
	if fh == nil then return 0 end
    for line in fh:lines() do
		msg = nil
		res = pwlog.decode(log)
		if msg == nil then
		   debug(line,msg)
		end  
    end
    fh:close()
end
	

syslog_decoder()
syslog_decoder_bulk()
