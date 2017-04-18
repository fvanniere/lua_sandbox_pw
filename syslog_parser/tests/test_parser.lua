-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

local syslog_parser = require "lpeg.syslog_parser"
local io = require"io"

local function apache_error()
    local grammar = syslog_parser.get_prog_grammar('apache-error')
    local log
    local fields

    log = '[Wed Apr 19 10:35:35 2017] [pid 8494] [vhost www.34usines.com] [client 183.181.197.14:57958] PHP Warning:  Invalid argument supplied for foreach() in /home/34usines/public_html/www/modules/blocklayered/blocklayered.php on line 1907, referer: http://www.google.fr/search?hl=fr&source=hp&biw='
    fields = grammar:match(log)

    assert(fields.php_severity == 'Warning', fields.php_severity)
    assert(fields.remoteAddr == '183.181.197.14', fields.remoteAddr)
    assert(fields.remotePort == 57958, fields.remotePort)
    assert(fields.filename == '/home/34usines/public_html/www/modules/blocklayered/blocklayered.php', fields.filename)
	--assert(fields.timestamp == 1.492590935e18, fields.timestamp)

	log = "[Wed Apr 19 10:43:16 2017] [error] [client 157.99.164.168] PHP Deprecated:  Function ereg() is deprecated in /home/kinoglaz/www/u_fiche_festival_total.php on line 145"
    fields = grammar:match(log)
	assert(fields.remoteAddr == '157.99.164.168', fields.remoteAddr)
	assert(fields.php_severity == 'Deprecated', fields.php_severity)
	assert(fields.filename == '/home/kinoglaz/www/u_fiche_festival_total.php', fields.filename)


	log = "[Wed Apr 19 10:36:52 2017] [pid 28776] [vhost www.happyyou.fr] [client 127.160.71.199:31010] script '/home/webmaster/public_html/current/public/wp-login.php' not found or unable to stat"
    fields = grammar:match(log)
	assert(fields.http_host == "www.happyyou.fr", fields.http_host)
	assert(fields.remotePort == 31010, fields.remotePort)
	assert(fields.filename == '/home/webmaster/public_html/current/public/wp-login.php', fields.filename)


	log = "[Wed Apr 19 10:41:29 2017] [access_compat:error] [pid 11051] [vhost static.mystore.com] [client 90.111.153.56:4046] AH01797: client denied by server configuration: /home/webmaster/public_html/mystore_release/stores/pharmacienligne/Images"
    fields = grammar:match(log)
	assert(fields.http_host == "static.mystore.com", fields.http_host)
	assert(fields.remoteAddr == "90.111.153.56",fields.remoteAddr)


	log = "[Wed Apr 19 08:41:43 2017] [warning]: Malformed UTF-8 character (unexpected end of string) in string ne at /usr/share/perl/5.14/Locale/Maketext.pm line 540. (/usr/share/perl/5.14/Locale/Maketext.pm:540)"
    fields = grammar:match(log)
	assert(fields.apache_severity == "warning", fields.apache_severity)


	log = "[Wed Apr 19 10:38:37 2017] [error] [client 2602:306:cd45:8060:25bb:c3cc:f80b:c9e9] script '/home/bnpetrole/www/wp-login.php' not found or unable to stat"
    fields = grammar:match(log)
	assert(fields.apache_severity == "error", fields.apache_severity)
	assert(fields.remoteAddr == "2602:306:cd45:8060:25bb:c3cc:f80b:c9e9", fields.remoteAddr)
	assert(fields.filename == "/home/bnpetrole/www/wp-login.php", fields.filename)


	log = "[Wed Apr 19 08:28:07 2017] [core:error] [pid 12207] [vhost web.planet-work.com] [client 2a01:cb00:4d8:7000:aabb:1234:7565:aaa3:55808] AH00082: an unknown filter was not added: INFLATE"
	fields = grammar:match(log)
	--debug(log, fields)
	assert(fields.apache_severity == "error", fields.apache_severity)
	assert(fields.remoteAddr == "2a01:cb00:4d8:7000:aabb:1234:7565:aaa3", fields.remoteAddr)
	assert(fields.remotePort == 55808, fields.remotePort)


	log = "[Tue Apr 18 00:19:23.680713 2017] [mpm_itk:error] [pid 15474] (12)Cannot allocate memory: fork: Unable to fork new process"
	fields = grammar:match(log)
	assert(fields.apache_module == "mpm_itk", fields.apache_severity)
	assert(fields.apache_severity == "error", fields.apache_severity)

	log = '[Fri Apr 28 08:27:55 2017] [pid 31814] [vhost www.superbebe.com] [client 2a01:e35:1234:abcd:f012:c822:de98:7d08:33068] PHP Deprecated:  mysql_connect(): The mysql extension is deprecated and will be removed in the future: use mysqli or PDO instead in /home/webmaster/public_html/www/includes/classes/mysql.class.php on line 38'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "2a01:e35:1234:abcd:f012:c822:de98:7d08", fields.remoteAddr)
	assert(fields.http_host == "www.superbebe.com", fields.http_host)
	assert(fields.filename == "/home/webmaster/public_html/www/includes/classes/mysql.class.php", fields.filename)

	log = "[Fri Apr 28 08:29:59 2017] [error] [client 231.176.229.244] PHP Notice: La m\xc3\xa9thode constructor appel\xc3\xa9e pour WP_Widget est <strong>obsol\xc3\xa8te</strong> depuis la version 4.3.0&nbsp;! Veuillez utiliser <pre>__construct()</pre> \xc3\xa0 la place. in /home/jefaismoimeme/public_html/www/wp-includes/functions.php on line 3669"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "231.176.229.244")

end

local function apache_error_bulk()
    local fn = '/tmp/apache-error.log'
    local fh = io.open(fn, "rb")
	if fh == nil then return 0 end
    for line in fh:lines() do
    local grammar = syslog_parser.get_prog_grammar('apache-error')
        fields = grammar:match(line)
		if fields == nil then
		    debug(line,fields)
	    end  
    end
    fh:close()
end
	
local function nginx_error()
    local grammar = syslog_parser.get_prog_grammar('nginx-error')
    local log
    local fields

    log = '2017/04/25 15:57:30 [crit] 5874#5874: *33580698 stat() "/home/udeux/public_html/www/plugins-dist/mediabox/javascript/jquery.colorbox.js" failed (13: Permission denied), client: 111.37.179.90, server: _, request: "GET /plugins-dist/mediabox/javascript/jquery.colorbox.js?1488792619 HTTP/1.1", host: "www.fernyepa.fr", referrer: "http://www.fernyepa.fr/-Francais-.html"'
    fields = grammar:match(log)
    assert(fields.nginx_severity == 'crit', fields.nginx_severity)
    assert(fields.remoteAddr == '111.37.179.90', fields.remoteAddr)
    assert(fields.http_host == 'www.fernyepa.fr', fields.http_host)

	log = '2017/04/26 22:59:25 [error] 6445#6445: *673873860 testing "/mnt/web/web1/zspectrum/jzfestival/" existence failed (2: No such file or directory) while logging request, client: 58.58.91.14, server: php56.web.planet-work.com, request: "GET /wp-content/uploads/2012/10/fr/vente-de-cialis-a-paris/125 HTTP/1.1", upstream: "http://10.3.100.26:8008/wp-content/uploads/2012/10/fr/vente-de-cialis-a-paris/125", host: "www.jzfestival.com"'
	fields = grammar:match(log)
	assert(fields.nginx_severity == 'error', fields.nginx_severity)
	assert(fields.filename == "/mnt/web/web1/zspectrum/jzfestival/", fields.filename)
	assert(fields.http_host == "www.jzfestival.com", fields.http_host)
	--assert(fields.timestamp == 1493240365000000000, fields.timestamp)

    log = '2017/04/25 15:51:47 [error] 1417#1417: *65010777 lua udp socket read timed out, client: 71.12.97.179, server: www.espace-typique.com, request: "GET /paris/immobilier/ventes/?gclid=CPi177Lgv9MCFbQW0wod9PUGOA HTTP/1.1", host: "www.espace-typique.com"'
    fields = grammar:match(log)
    assert(fields.nginx_severity == 'error', fields.nginx_severity)
    --assert(fields.remoteAddr == '71.12.97.179', fields.remoteAddr)
    --assert(fields.http_host == 'www.espace-typique.com', fields.http_host)

	log = '2017/04/25 15:30:27 [error] 3170#3170: *661998050 [lua] healthcheck_pw.lua:59: errlog(): healthcheck: failed to receive status line from 10.3.100.24:8007: timeout, context: ngx.timer'
    fields = grammar:match(log)
    assert(fields.nginx_severity == 'error', fields.nginx_severity)




end

local function proftpd() 
    local grammar = syslog_parser.get_prog_grammar('proftpd')
    local log
    local fields
  
	log = 'ftp [8.154.12.35] bb@syropg.com "PWD" /home1/sirmo/test/ 257 -'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "8.154.12.35", fields.remoteAddr)
	assert(fields.ftp_login == "bb@syropg.com", fields.ftp_login)
    assert(fields.ftp_responsecode == 257, fields.ftp_responsecode)

	log = 'ftp [228.247.42.15] backup@clors.fr "LIST" /home1/webz/www/clors/Data/Secu/BackUp/82418904700023/ 226 9521'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "228.247.42.15", fields.remoteAddr)

	log = 'ftp [113.155.249.80] - "USER webmaster@domain12.net" - 331 -'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "113.155.249.80", fields.remoteAddr)
	assert(fields.ftp_cmd == "USER", fields.ftp_cmd)
	assert(fields.ftp_login == "webmaster@domain12.net", fields.ftp_login)
	assert(fields.ftp_responsecode == 331, fields.ftp_responsecode)

	log = 'ftp [113.155.249.80] webmaster@domain12.net "PASS (hidden)" - 230 -'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "113.155.249.80", fields.remoteAddr)
	assert(fields.ftp_cmd == "PASS", fields.ftp_cmd)
	assert(fields.ftp_responsecode == 230, fields.ftp_responsecode)

	log = 'ftp [7.101.88.91] - "PASS (hidden)" - 530 -'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "7.101.88.91", fields.remoteAddr)
	assert(fields.ftp_responsecode == 530, fields.ftp_responsecode)

	log = '192.168.34.40 (246.182.38.215[246.182.38.215]) - USER user: no such user found from 246.182.38.215 [246.182.38.215] to 192.168.34.40:222'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "246.182.38.215", fields.remoteAddr)

	log = '192.168.34.40 (212.188.59.7[212.188.59.7]) - USER webmaster@techtech.fr: Login successful'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "212.188.59.7", fields.remoteAddr)

	log = '192.168.34.40 (2001:41d0:a:43d0::1[2001:41d0:a:43d0::1]) - error setting listen fd IPV6_TCLASS: Protocole non disponible'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "2001:41d0:a:43d0::1", fields.remoteAddr)
    
	log = 'ftps [18.45.222.69] webmaster@nechev.fr "STOR old-cp-background.php" /home/nechev/public_html/www-dev/composants/themes/sergy/admin/old-cp-background.php 226 7073'
	fields = grammar:match(log)
    assert(fields.remoteAddr == "18.45.222.69", fields.remoteAddr)
	assert(fields.ftp_cmd == "STOR", fields.ftp_cmd)
	assert(fields.ftp_login == "webmaster@nechev.fr", fields.ftp_login)
	assert(fields.ftp_responsecode == 226, fields.ftp_responsecode)

	log = 'ssh2 [141.130.164.55] - "USERAUTH_REQUEST" - - -'
	fields = grammar:match(log)
	--debug(log, fields)
    assert(fields.remoteAddr == "141.130.164.55", fields.remoteAddr)


end


local function dovecot()
    local grammar = syslog_parser.get_prog_grammar('dovecot')
	local log
	local fields

	log = 'imap-login: Login: user=<dievad@orange.fr>, method=PLAIN, rip=116.50.216.85, lip=192.168.35.158, mpid=17461, TLS, session=<BLwHK1dNNgBaOv5C>'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "116.50.216.85", fields.remoteAddr)
	assert(fields.mail_protocol == "imap", fields.mail_protocol)
	assert(fields.mail_login == "dievad@orange.fr", fields.mail_login)
	assert(fields.mail_session == "BLwHK1dNNgBaOv5C", fields.mail_session)


	log = 'imap(olineg@martin-dgp.fr): Connection closed in=54 out=809'
	fields = grammar:match(log)
	assert(fields.mail_protocol == "imap", fields.mail_protocol)
	assert(fields.mail_login == "olineg@martin-dgp.fr", fields.mail_login)
	assert(fields.mail_outBytes == 809, fields.mail_ouyBytes)
	assert(fields.mail_inBytes == 54, fields.mail_inBytes)
	

	log = 'pop3-login: Aborted login (no auth attempts in 0 secs): user=<>, rip=192.168.34.3, lip=192.168.35.158, session=<qfgmKFdNfABPY6QD>'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "192.168.34.3", fields.remoteAddr)
	assert(fields.mail_protocol == "pop3", fields.mail_protocol)

	log = 'pop3(stgend@pouilly.fr): Disconnected: Logged out top=0/0, retr=0/0, del=0/271, size=170609999'
	fields = grammar:match(log)
	--debug(log, fields)
	assert(fields.mail_login == "stgend@pouilly.fr", fields.remoteAddr)
	assert(fields.mail_protocol == "pop3", fields.mail_protocol)


	log = 'lda(aboussim@orange.fr): msgid=<201704170844.i9u24wcy1pwhdnj@elbit-fid2.com>: saved mail to INBOX'
	fields = grammar:match(log)
	assert(fields.mail_protocol == "lda", fields.mail_protocol)
	assert(fields.mail_msgid == "201704170844.i9u24wcy1pwhdnj@elbit-fid2.com", fields.mail_msgid)
	assert(fields.mail_login == "aboussim@orange.fr", fields.mail_login)
	

	log = 'managesieve-login: proxy(wildcard@lampe.net): disconnecting 192.168.34.11 (Disconnected by server(0s idle, in=245, out=1365+42)): user=<wildcard@lampe.net>, method=PLAIN, rip=192.168.34.11, lip=192.168.34.25, session=<gvi8w0lNzLlPY6QL>'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "192.168.34.11", fields.remoteAddr)
	assert(fields.mail_protocol == "managesieve", fields.mail_protocol)
	assert(fields.mail_login == "wildcard@lampe.net", fields.mail_login)
	assert(fields.mail_outBytes == 1365, fields.mail_ouyBytes)
	assert(fields.mail_inBytes == 245, fields.mail_inBytes)


	log = 'pop3-login: proxy(compta@marc.com): started proxying to 192.168.3.14:110: user=<compta@marc.com>, method=PLAIN, rip=0.99.119.156, lip=192.168.34.25, session=<gS0rxEFNu3TB/M3n>'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "0.99.119.156", fields.remoteAddr)
	assert(fields.mail_protocol == "pop3", fields.mail_protocol)
	assert(fields.mail_login == "compta@marc.com", fields.mail_login)
	

	log = 'imap-login: Disconnected (auth failed, 1 attempts in 5 secs): user=<office>, method=PLAIN, rip=24.98.64.90, lip=192.168.34.25, TLS, session=<ZkZtHU1NrLDeWoh9>'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "24.98.64.90", fields.remoteAddr)
	assert(fields.mail_protocol == "imap", fields.mail_protocol)
	assert(fields.mail_login == "office", fields.mail_login)

	log = 'lmtp(12130): Ql4zFbYV81hiLwAAosaHuQ: Sent message to <vpcsrv@velo.com> at 192.168.3.11:24: 250 2.0.0 <vpcsrv@velo.com> tImBIrYV81iUQgAAlB2uAQ Saved (1/1 at 156 ms)'
	fields = grammar:match(log)
	assert(fields.mail_login == "vpcsrv@velo.com", fields.mail_login)

	log = 'pop3-login: proxy(rossi46127@logique.net): started proxying to 192.168.3.11:110: user=<rossi46127@logique.net>, method=PLAIN, rip=92.158.225.185, lip=192.168.34.25, session=<4svtgUVNIcFcnuG5>'
	fields = grammar:match(log)
	assert(fields.mail_login == "rossi46127@logique.net", fields.mail_login)

	log = "imap-login: proxy(developpement@parc-mgt.fr): disconnecting 77.198.216.235 (Disconnected by client: read(size=1026) failed: Connection reset by peer(0s idle, in=298, out=1200)): user=<developpement@parc-mgt.fr>, method=PLAIN, rip=77.198.216.235, lip=192.168.34.25, session=<s49JfENNAppNxtjr>"
	fields = grammar:match(log)
	assert(fields.mail_login == "developpement@parc-mgt.fr", fields.mail_login)
	

	log = "imap-login: Aborted login (client didn't finish SASL auth, waited 0 secs): user=<>, method=LOGIN, rip=133.37.177.106, lip=192.168.34.25, TLS, session=<bOVVMEZNJv6wnoyN>"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "133.37.177.106", fields.remoteAddr)


	log = "imap-login: Error: proxy(ananas@orange.fr): connect(192.168.3.11, 143) failed: Connection refused (after 60 secs, 60 reconnects, local=192.168.3.93:56196): user=<ananas@orange.fr>, method=PLAIN, rip=2a01:e34:1234:abcd:1234:abcd:4244:d591, lip=2a01:648::25, session=<bafW/WtNop0qAQ407XCXAHgD19xCRNWR>"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "2a01:e34:1234:abcd:1234:abcd:4244:d591", fields.remoteAddr)
	

	log = "pop3-login: proxy: Logging in to 192.168.3.11:110 timed out (state=0, duration=180s) (internal failure, 4 successful auths): user=<rdveconomiquecepac@id2mark.com>, method=PLAIN, rip=187.47.37.139, lip=192.168.34.25, TLS, session=<K6lP92tNxeNaJV43>"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "187.47.37.139", fields.remoteAddr)
	
	log = "auth: Error: passwd-file(lamarcheo@elec.fr,84.217.35.208,<j1O5cpRNbwBNiCmI>): stat(/etc/vmail/elec.fr/passwd.temp) failed: No such file or directory"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "84.217.35.208", fields.remoteAddr)

    log = "lda(blanca@domain.fr): sieve: execution of script /etc/vmail/domain.fr/sieve/blanca/active-filter.sieve;name=main script failed, but implicit keep was successful (user logfile /etc/vmail/domain.fr/sieve/blanca/active-filter.sieve.log may reveal additional details)"
	fields = grammar:match(log)
	assert(fields.mail_login == "blanca@domain.fr", fields.mail_login)
	
	log = "imap-login: Maximum number of connections from user+IP exceeded (mail_max_userip_connections=10): user=<jean@immo.fr>, method=PLAIN, rip=61.136.200.177, lip=192.168.35.158, TLS, session=<eN/vKo1NsQBcWhF0>"
	fields = grammar:match(log)
    assert(fields.remoteAddr == "61.136.200.177", fields.remoteAddr)

	log = 'auth: dict(info@sebjeuffrain.com,137.174.74.137): Password mismatch'
	fields = grammar:match(log)
	assert(fields.mail_protocol == "auth", fields.mail_protocol)
    assert(fields.remoteAddr == "137.174.74.137", fields.remoteAddr)
	assert(fields.mail_login == "info@sebjeuffrain.com", fields.mail_login)

	log = 'auth-worker: dict(info@sebje.com,137.174.74.137): Password mismatch'
	fields = grammar:match(log)
	--debug(log, fields)
	assert(fields.mail_protocol == "auth", fields.mail_protocol)
    assert(fields.remoteAddr == "137.174.74.137", fields.remoteAddr)
	assert(fields.mail_login == "info@sebje.com", fields.mail_login)

	log = 'auth-worker(22720): dict(administrator@bayamo.planet-work.net,80.82.65.204): unknown user'
	fields = grammar:match(log)
	--debug(log, fields)
	assert(fields.mail_protocol == "auth", fields.mail_protocol)

	log = 'auth: Error: passwd-file(nora,115.56.194.91,<O6dLHf5NtQA8HQAx>): stat(/etc/vmail//passwd.temp) failed: No such file or directory'
	fields = grammar:match(log)
	--debug(log, fields)
	assert(fields.mail_protocol == "auth", fields.mail_protocol)
    assert(fields.remoteAddr == "115.56.194.91", fields.remoteAddr)
	assert(fields.mail_login == "nora", fields.mail_login)
end

local function dovecot_bulk()
    local fn = '/tmp/dovecot.log'
    local fh = io.open(fn, "rb")
	if fh == nil then return 0 end
    for line in fh:lines() do
    local grammar = syslog_parser.get_prog_grammar('dovecot')
        fields = grammar:match(line)
		if fields == nil then
		    debug(line,fields)
	    end  
    end
    fh:close()
end

local function exim()
    local grammar = syslog_parser.get_prog_grammar('exim')
	local log
	local fields

	log = '2017-04-20 12:06:19 1d18yh-0006Kd-Ji <= cheval@cheval.fr H=mou03-h01-176-128-239-175.dsl.sta.abo.bbox.fr ([192.168.1.95]) [177.27.244.99] I=[192.168.34.27]:2025 P=esmtpa A=fixed_plain:cheval@cheval.fr K S=723 id=DADD6207-CE79-4053-9A86-621C76BB5150@cheval.fr'
	fields = grammar:match(log)
	--sebug(log,fields)
	assert(fields.remoteAddr == "177.27.244.99", fields.remoteAddr)
	assert(fields.localAddr == "192.168.34.27", fields.localAddr)
	assert(fields.localPort == 2025, fields.localPort)

	log = '2017-04-20 10:05:08 1d175P-0002Rb-Pn <= chai@orange.fr H=smtp05.smtpout.orange.fr (smtp.smtpout.orange.fr) [151.78.71.164] P=esmtps X=TLS1.0:DHE_RSA_AES_128_CBC_SHA1:128 CV=no S=10710 id=58d02e0607cfb6aaa22b9e26633495e4@mwinf5d40.me-wanadoo.net'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "151.78.71.164", fields.remoteAddr)
	assert(fields.mail_from == "chai@orange.fr", fields.mail_from)
	assert(fields.mail_ehlo == "smtp05.smtpout.orange.fr", fields.mail_ehlo)
	assert(fields.mail_msgId == "58d02e0607cfb6aaa22b9e26633495e4@mwinf5d40.me-wanadoo.net", fields.mail_msgId)
	assert(fields.mail_protocol == "esmtps", fields.mail_protocol)
	assert(fields.mail_eximId == "1d175P-0002Rb-Pn", fields.mail_eximId)
	assert(fields.mail_size == 10710, fields.mail_size)
	assert(fields.mail_eximFlag == "input", fields.mail_eximFlag)


	log = '2017-04-20 10:01:31 1d171u-00027p-JF => a.mouse@cjapublic.fr R=vmail_user T=remote_smtp_proxy H=192.168.3.143 [192.168.3.143] K C="250- 39457 byte chunk, total 40669\\n250 OK id=1d171v-0007GV-Hi"'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "192.168.3.143", fields.remoteAddr)
	assert(fields.mail_eximId == "1d171u-00027p-JF", fields.mail_eximId)
	assert(fields.mail_remoteId == "1d171v-0007GV-Hi", fields.mail_remoteId)
	assert(fields.mail_rcpt == "a.mouse@cjapublic.fr", fields.mail_rcpt)
	assert(fields.mail_eximFlag == "output", fields.mail_eximFlag)


	log = "2017-04-20 09:55:29 1d0TWe-0007JO-V1 == editor@defense-a.com R=vmail_user T=remote_smtp_proxy defer (-53): retry time not reached for any host for 'defense-a.com'"
	fields = grammar:match(log)
	assert(fields.mail_eximId == "1d0TWe-0007JO-V1", fields.mail_eximId)
	assert(fields.mail_eximFlag == "defer", fields.mail_eximFlag)
	assert(fields.mail_rcpt == "editor@defense-a.com", fields.mail_rcpt)


	log = "2017-04-20 07:15:29 1d0VJU-0005B2-Vm == lal@segalu.cc R=vmail_catchall T=remote_smtp_proxy defer (-46) H=192.168.3.143 [192.168.3.143]: SMTP error from remote mail server after end of data: 421 Lost incoming connection"
	fields = grammar:match(log)
	assert(fields.mail_eximId == "1d0VJU-0005B2-Vm", fields.mail_eximId)
	assert(fields.mail_eximFlag == "defer", fields.mail_eximFlag)
	assert(fields.mail_rcpt == "lal@segalu.cc", fields.mail_rcpt)


    log = '2017-04-20 12:07:17 1d18za-0006OD-9T => claire@xl.fr R=dnslookup T=remote_smtp H=mx2.planet-work.com [2a01:648::44] I=[2a01:648::27] X=TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128 CV=yes K C="250- 64160 byte chunk, total 64822\\n250 OK id=1d18zc-0003pJ-Nc"'
    --[[fields = grammar:match(log)
	assert(fields.mail_eximId == "1d18za-0006OD-9T", fields.mail_eximId)
	assert(fields.mail_eximFlag == "output", fields.mail_eximFlag)
	assert(fields.mail_rcpt == "claire@xl.fr", fields.mail_rcpt)
	assert(fields.mail_remoteId == "1d18zc-0003pJ-Nc", fields.mail_remoteId)
	]]--


	log = '2017-04-20 12:06:35 1d18yx-0006M3-7Q X-Sender=divianne@hxmedia.com (divianne@hxmedia.com)\\n [2a01:cb04::c8d6:a26e]'
    fields = grammar:match(log)
	assert(fields.mail_eximId == "1d18yx-0006M3-7Q", fields.mail_eximId)
	assert(fields.mail_login == "divianne@hxmedia.com", fields.mail_login)
	assert(fields.mail_from == "divianne@hxmedia.com", fields.mail_from)
	assert(fields.remoteAddr == "2a01:cb04::c8d6:a26e", fields.remoteAddr)

	log = '2017-04-20 10:03:08 H=([214.159.229.204]) [214.159.229.204] F=<Violette146@silveraudiotechnology.com> rejected RCPT <e1onpeq-0004iy-6m@cdn.fr>: found in sbl-xbl.spamhaus.org'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "214.159.229.204", fields.remoteAddr)
	assert(fields.mail_from == "Violette146@silveraudiotechnology.com", fields.mail_from)
	assert(fields.mail_rcpt == "e1onpeq-0004iy-6m@cdn.fr", fields.mail_rcpt)

	log = "2017-04-20 10:04:08 1d174R-0002N0-Lb H=mta.49.247.xxx.fr [188.67.126.156] X=TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256 CV=no F=<noreply@manager.spammail.com> rejected after DATA: This message was classified as SPAM [Yes, score=57.0 required=6.5 tests=[DKIM_SIGNED=0.1, DKIM_VALID=-0.1, DKIM_VALID_AU=-0.1, HTML_FONT_LOW_CONTRAST=0.001, HTML_MESSAGE=0.001, LOTS_OF_MONEY=0.001, PW_EMLSYS=8, PW_MACROSITE=20, PW_MACROSITE2=20, PW_RCVD_IN_BL=7.5, RCVD_IN_BRBL_LASTEXT=1.644, RCVD_IN_DNSWL_NONE=-0.0001, SPF_PASS=-0.001, URIBL_BLOCKED=0.001] autolearn=disabled version=3.4.1 host=blizzard.ds.planet-work.net bayes=0.5 bayes_summary="
	fields = grammar:match(log)
	assert(fields.mail_eximId == "1d174R-0002N0-Lb", fields.mail_eximId)
	assert(fields.mail_ehlo == "mta.49.247.xxx.fr", fields.mail_ehlo)
	assert(fields.remoteAddr == "188.67.126.156", fields.remoteAddr)
	assert(fields.mail_from == "noreply@manager.spammail.com", fields.mail_from)


	log = "2017-04-20 09:52:38 H=(mail108.emailbackend.com) [240.10.194.49] sender verify defer for <bounce@emailbackend.com>: host lookup did not complete"
	fields = grammar:match(log)
	assert(fields.mail_machinename == "mail108.emailbackend.com", fields.mail_ehlo)
	assert(fields.remoteAddr == "240.10.194.49", fields.remoteAddr)
	assert(fields.mail_from == "bounce@emailbackend.com", fields.mail_from)

	log = '2017-04-20 12:05:56 1d18xM-0006FT-7q H=mx1.ovh.net [137.74.125.138]: SMTP timeout after EHLO bayamo.planet-work.net: Connection timed out'
	fields = grammar:match(log)
	--debug(log,fields)
	assert(fields.mail_eximId == "1d18xM-0006FT-7q", fields.mail_eximId)

    -- TODO
	log = "2017-04-20 12:13:48 remote host address is the local host: sante-vie-positive.org (while verifying <ethan_hale@sante-vie-positive.org> from host 46-105-63-163.kimsufi.com (revolusyn.com) [46.105.63.163])"
    log = "2017-04-20 11:01:02 SMTP data timeout (message abandoned) on connection from t2a2.t2agreen.com [193.164.131.17] F=<saleha@enicon.com>"

	log = "[1\\4] 2017-04-24 00:06:31 fixed_login authenticator failed for (User) [91.200.12.165]: 435 Unable to authenticate at present (set_id=scanner): error in perl_startup code: Can't locate Crypt/PasswdMD5.pm in @INC (you may need to install the Crypt::PasswdMD5 module) (@INC contains: /etc/perl /usr/local/lib/x86_64-linux-gnu/perl/5.20.2 /usr/local/share/perl/5.20.2 /usr/lib/x86_64-linux-gnu/perl5/5.20 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl/5.20 /usr/share/perl/5.20 /usr/local/lib/site_perl .) at /etc/exim4/perl-exim.pl line 4."
	fields = grammar:match(log)
end

local function spamd()
    local grammar = syslog_parser.get_prog_grammar('spamd')
	local log
	local fields

	log = 'result: Y 53 - HEADER_FROM_DIFFERENT_DOMAINS,HTML_MESSAGE,KAM_BADIPHTTP,NORMAL_HTTP_TO_IP,PW_EMLSYS,PW_MACROSITE,PW_MACROSITE2,RCVD_IN_DNSWL_LOW,SPF_SOFTFAIL,T_DKIM_INVALID,URI_DQ_UNSUB scantime=5.3,size=14850,user=debian-spamd,uid=111,required_score=6.5,rhost=ppi.ds.planet-work.net,raddr=10.3.1.25,rport=35650,mid=<8010df25dd9623c6941c75018bd2ca50@137.74.8.4>,autolearn=disabled'
	fields = grammar:match(log)
	assert(fields.flag == 'Y', fields.flag)
	assert(fields.mail_scantime == 5.3, fields.mail_scantime)
	assert(fields.mail_bytes == 14850, fields.mail_bytes)
	assert(fields.mail_spamscore == 53, fields.mail_spamscore)
    assert(fields.mail_msgId == "8010df25dd9623c6941c75018bd2ca50@137.74.8.4", fields.mail_msgId)

	log = 'result: . -11 - HTML_FONT_LOW_CONTRAST,HTML_MESSAGE,KAM_UNSUB1,MIME_HTML_ONLY,RCVD_IN_DNSWL_NONE,RCVD_IN_IADB_DK,RCVD_IN_IADB_DOPTIN,RCVD_IN_IADB_LISTED,RCVD_IN_IADB_OPTIN,RCVD_IN_IADB_OPTIN_GT50,RCVD_IN_IADB_RDNS,RCVD_IN_IADB_SENDERID,RCVD_IN_IADB_SPF,RCVD_IN_MSPIKE_H3,RCVD_IN_MSPIKE_WL,RCVD_IN_RP_CERTIFIED,RCVD_IN_RP_SAFE,RP_MATCHES_RCVD,SPF_HELO_PASS,SPF_PASS,T_DKIM_INVALID,URIBL_BLOCKED scantime=4.0,size=11609,user=debian-spamd,uid=111,required_score=6.5,rhost=acf.local.ds.planet-work.net,raddr=10.3.0.178,rport=48522,mid=<201704241203000962.9468.75078@jobrapidoalert.com>,autolearn=disabled'
	fields = grammar:match(log)
	assert(fields.flag == '.', fields.flag)
	assert(fields.mail_spamscore == -11, fields.mail_spamscore)
    assert(fields.mail_msgId == "201704241203000962.9468.75078@jobrapidoalert.com", fields.mail_msgId)

end

local function sshd()
	local grammar = syslog_parser.get_prog_grammar('sshd')
	local log
	local fields

	log = 'refused connect from 157.121.175.149 (157.121.175.149)'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "157.121.175.149", fields.remoteAddr)

	log = "Starting session: subsystem 'sftp' for sncf-news from 100.242.160.208 port 60066"
	fields = grammar:match(log)
	assert(fields.remoteAddr == "100.242.160.208", fields.remoteAddr)
	assert(fields.remotePort == 60066, fields.remotePort)
	assert(fields.user == "sncf-news", fields.user)

	log = 'Connection from 2a01:648::3 port 61108 on 2a01:648::a1 port 22'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "2a01:648::3", fields.remoteAddr)


	log = 'Accepted publickey for nagios from 2a01:648::3 port 13378 ssh2: RSA 5b:20:96:8b:21:ff:55:5b:05:2a:9d:2e:9d:66:ee:f2'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "2a01:648::3", fields.remoteAddr)
	assert(fields.ssh_key == "5b:20:96:8b:21:ff:55:5b:05:2a:9d:2e:9d:66:ee:f2", fields.ssh_key)


	log = 'Closing connection to 228.77.212.238 port 12431'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "228.77.212.238", fields.remoteAddr)


	log = 'Connection closed by 228.77.212.238'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "228.77.212.238", fields.remoteAddr)

	log = 'Connection closed by 192.168.34.3 port 10008 [preauth]'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "192.168.34.3", fields.remoteAddr)


	log = 'Failed publickey for webmaster from 228.77.212.238 port 30674 ssh2: RSA 3d:85:41:08:58:17:24:a8:cb:eb:99:84:61:51:e6:0e'
	fields = grammar:match(log)
	assert(fields.remoteAddr == "228.77.212.238", fields.remoteAddr)
	assert(fields.remotePort == 30674, fields.remotePort)
	assert(fields.user == "webmaster", fields.user)
	assert(fields.ssh_key == "3d:85:41:08:58:17:24:a8:cb:eb:99:84:61:51:e6:0e", fields.ssh_key)


	log = 'Starting session: command for nagios from 192.168.34.3 port 7684'
	fields = grammar:match(log)
	--debug(log,fields)
	assert(fields.remoteAddr == "192.168.34.3", fields.remoteAddr)
	
	log = 'Set /proc/self/oom_score_adj to 0'
	--debug(log,fields)
	fields = grammar:match(log)
	assert(fields ~= nil,"")
	
    
	--debug(log,fields)

end

local function bash_hist()
	local grammar = syslog_parser.get_prog_grammar('bash')
	local log
	local fields

	log = 'HISTORY: PID=24137 UID=0 emacs daemon.pl'
	fields = grammar:match(log)
	assert(fields.pid == 24137, fields.pid)
	assert(fields.uid ==0, fields.uid)
end

local function exim_bulk()
    local fn = '/tmp/exim.log'
    local fh = io.open(fn, "rb")
	if fh == nil then return 0 end
    for line in fh:lines() do
    local grammar = syslog_parser.get_prog_grammar('exim')
        fields = grammar:match(line)
		if fields == nil then
		    debug(line,fields)
	    end  
    end
    fh:close()
end
	
	

apache_error()
apache_error_bulk()
nginx_error()
proftpd()
dovecot()
dovecot_bulk()
exim()
exim_bulk()
spamd()
sshd()
bash_hist()
