-- This Source Code Form is subject to the terms of the MIT License

-- Copyright 2016 Frédéric VANNIÈRE <f.vanniere@planet-work.com>

--[[

# Syslog Basic Decoder Module
## Decoder Configuration Table
```lua
-- template (string) - The 'template' configuration string from rsyslog.conf
-- see http://rsyslog-5-8-6-doc.neocities.org/rsyslog_conf_templates.html
-- Default:
-- template = "<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag:1:32%%msg:::sp-if-no-1st-sp%%msg%" -- RSYSLOG_TraditionalForwardFormat
```
## Functions
### decode
Decode and inject the resulting message
*Arguments*
- data (string) - syslog message
- default_headers (optional table) - Heka message table containing the default
  header values to use, if they are not populated by the decoder. If 'Fields'
  is specified it should be in the hashed based format see:
  http://mozilla-services.github.io/lua_sandbox/heka/message.html
*Return*
- (nil, string) or throws an error on invalid data or an inject message failure
    - nil - if the decode was successful
    - string - error message if the decode failed (e.g. no match)
--]]



-- Imports
local syslog = require "lpeg.syslog"
local syslog_message = require "lpeg.syslog_message"
local syslog_parser = require"lpeg.syslog_parser"
local clf = require "lpeg.common_log_format"
local dt = require "lpeg.date_time"
local io = require"io"
local circular_buffer = require "circular_buffer"

local pw = require"pwlib"
local os = require"os"


local geoip = require"geoip"
local geoip_country = require 'geoip.country'
local geoip_country_filename = "/usr/share/GeoIP/GeoIP.dat"
local geoip_countryv6_filename = "/usr/share/GeoIP/GeoIPv6.dat"
local geoip_country_lookup =  geoip_country.open(geoip_country_filename,geoip.MEMORY_CACHE)
local geoip_country_lookup6 =  geoip_country.open(geoip_countryv6_filename,geoip.MEMORY_CACHE,geoip.COUNTRY_V6)


local template  = read_config("syslog_template") or "<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msgid% %msg%"
local grammar   = syslog.build_rsyslog_grammar(template)

-- invalid structured data due to longer sd-name than allowed by RFC (UUID=36 > 32), msg containts structured data + msg
local msg_grammar = syslog_parser.get_prog_grammar("syslog_structured_data")

local pairs = pairs
local ipairs = ipairs
local type  = type
local tonumber = tonumber
local pcall = pcall
local string = string

local inject_message = inject_message
local debug = debug

local msg = {}

local loghost_id = read_config("loghost_id") or '34200'
local flood_cb = circular_buffer.new(1440, 1, 120)

local M = {}

setfenv(1, M) -- Remove external access to contain everything in the module


function decode(data)
    local fields = grammar:match(data)
    if not fields then return "parse failed: " .. data end

	local fields_msg = msg_grammar:match(fields.msg)
    if not fields_msg then return "struct data parse failed for " .. fields.msg end

    fields.msg = fields_msg[2].msg
    structured_data = fields_msg[1]
	-- debug("FIELDS", fields)

    -- tenant_id@pw =  structured_data.id

    if fields.pri then
        msg.Severity = fields.pri.severity
        fields.syslogfacility = fields.pri.facility
        fields.pri = nil
    else
        msg.Severity = fields.syslogseverity or fields["syslogseverity-text"]
        or fields.syslogpriority or fields["syslogpriority-text"]

        fields.syslogseverity = nil
        fields["syslogseverity-text"] = nil
        fields.syslogpriority = nil
        fields["syslogpriority-text"] = nil
    end

    if fields.syslogtag then
        fields.programname = fields.syslogtag.programname
        msg.Pid = tonumber(fields.syslogtag.pid)
        fields.syslogtag = nil
    end

    msg.Hostname = fields.hostname or fields.source
    fields.hostname = nil
    fields.source = nil

    msg.Payload = fields.msg
    fields.msg = nil
	msg.Fields = {}
	msg.Fields.message = msg.Payload

	-- add Tenant
	tenant, tenant_id = pw.get_tenant(msg.Hostname)
	if tenant_id then
		--[[
		if not string.find(tenant_id .. "@" .. loghost_id, structured_data) then
			pwlib.debug("[syslog_decoder] bad tenant_id from " .. msg.Hostname)
			--return 0
		end
		]]--
	end
	msg.Fields.tenant = tenant



	msg.Fields.appname = fields['app-name']
	msg.Pid = tonumber(fields['procid'])
	msg.Type = 'syslog'
	msg.Logger = 'syslog'
	msg.Timestamp = os.date("%Y-%m-%dT%H:%M:%S%z",fields.timestamp/1e9)
	msg.EnvVersion = 1

	msg.Fields.timestamp = msg.Timestamp

	-- Parse data from Application
	
	if msg.Payload:sub(1,4) == 'pam_' then
	    app_grammar = syslog_message.get_wildcard_grammar('PAM')
	else
	    app_grammar =  syslog_parser.get_prog_grammar(msg.Fields.appname)
	end

	if app_grammar == nil then
		app_grammar =  syslog_message.get_prog_grammar(msg.Fields.appname)
	end

    local apache_cf = '$http_host $remote_addr - $remote_user [$time_local] "$request_method $request_uri $server_protocol" $status $bytes_sent "$http_referer" "$http_user_agent"'
	if msg.Fields.appname == "nginx-access" then
		if msg.Payload:sub(-1,-1) == '"' then
		    nginx_cf = apache_cf
		else
			nginx_cf = apache_cf .. ' $request_time' 
		end
        app_grammar = clf.build_nginx_grammar(nginx_cf)
	elseif msg.Fields.appname == "apache-access" then
        app_grammar = clf.build_nginx_grammar(apache_cf)
	end

	-- No need to parse named/bind
    if msg.Fields.appname == 'named' then app_grammar = nil end


	-- Flood protection
	if msg.Fields.appname == "php" then
        local x = string.match(msg.Payload,"] PHP .*")
	    if x ~= nil then
		    hash = pw.hash(x)
			--flood_cb:
        end
	end


	exclude_fields = {1,2,3,4,5,6,7,
	                  'cron_detail','cron_event', 
					  'remoteAddr2',
					  'eximRouter','eximTls','eximRemoteRes','eximTransport',
					  'eximBounce','eximLogMsg','eximMailto',
					  'nginx_connection','nginx_tid','apache_module','phpErrDetails',
					  'ftp_args','ftp_cwd','ftp_message',
					  'mail_machinename', 'mail_session','mailto'
				     }
	if app_grammar then
		newfields = app_grammar:match(msg.Payload)
		if newfields == nil then
			msg.Fields.hs_error = "Parser error"
			--pw.debug("Failed to parse for " .. msg.Fields.appname .. ': '.. msg.Payload)
		else
		    --debug("FIELDS", newfields)
			for k, v in pairs(newfields) do

				for i,x in ipairs(exclude_fields) do
					if k == x then v = nil end
				end

				if k == "remote_addr" then
					k = "remoteAddr"
					v = v.value
				elseif k == 1 or k == 2 then v = nil
				elseif k == "http_user_agent" then k = "http_userAgent"
				elseif k == "status" then k = "http_status"
				elseif k == "bytes_sent" then k = "http_outBytes";  v = v.value
				elseif k == "request_time" then k = "http_requestTime";  v = v.value
				elseif k == "server_protocol" then k = "http_protocol"
				elseif k == "request_method" then k = "http_method"
				elseif k == "request_uri" then k = "http_uri"
				elseif k == "remote_user" and v == "-" then v = ""; k = "http_remoteUser"
				elseif k == "remote_user" then k = "http_remoteUser"
				elseif k == "pid" then msg.Pid = v ; v = nil
				elseif k == "php_severity" then msg.Fields.appname = 'php'
				elseif k == "cron_username" then k = 'user'
				elseif k == "user_name" then k = 'user'
				elseif k == "eximUser" then k = 'user'
				end

				if k == "timestamp" then
					if msg.Fields.appname == "apache-error" 
						or msg.Fields.appname == "php" 
						or msg.Fields.appname == "exim" 
						or msg.Fields.appname == "nginx-error" then
						v = pw.ts_to_datetime_cest(v,msg.Hostname)
					else
						v = pw.ts_to_datetime(v,msg.Hostname)
					end
				elseif k == "time" then
					v = pw.ts_to_datetime(v,msg.Hostname)
					k = "timestamp"
				end
				msg.Fields[k] = v
			end
		end
	else
		--debug("No grammar for " .. msg.Fields.appname)
	end

	msg.Timestamp = msg.Fields.timestamp
	msg.Fields.message = msg.Payload
	msg.Payload = nil



	-- add User
	if msg.Fields.user == nil then
		if msg.Fields.host then
			msg.Fields.vhost, msg.Fields.user = pw.get_user_vhost_from_host(msg.Fields.host, tenant)
	    elseif msg.Fields.uid then 
			msg.Fields.user = pw.get_user_from_uid(msg.Fields.uid, tenant)
		elseif msg.Fields.filename then
			local x = string.match(msg.Fields.filename, "/home/([a-z0-9_-.]*)/")
			msg.Fields.user = x
		end

		if msg.Fields.user == nil and msg.Fields.mail_login ~= nil then
			msg.Fields.user = pw.get_user_from_login(msg.Fields.mail_login, tenant)
		elseif msg.Fields.user == nil and msg.Fields.ftp_login ~= nil then
			msg.Fields.user = pw.get_user_from_login(msg.Fields.ftp_login, tenant)
		end
	end

	-- add Vhost
	if msg.Fields.http_host then

	    -- Cleanup fields
    	if msg.Fields.http_remoteUser == "" then msg.Fields.http_remoteUser = nil end
	    if msg.Fields.http_referer == "-" then msg.Fields.http_referer = "" end

		msg.Fields.http_vhost, user2 = pw.get_user_vhost_from_host(msg.Fields.http_host,tenant)
		if msg.Fields.user and user2 ~= msg.Fields.user then
			msg.Fields.hs_error = "Bad user"
			--pw.debug("Error : bad USER from logs " .. user2 .. " ~= " .. msg.Fields.user .. ": " .. msg.Fields.message)
		end
		if msg.Fields.user == nil then
			msg.Fields.user = user2
		end
	end
	-- add Country
	if msg.Fields.remoteAddr and string.len(msg.Fields.remoteAddr) > 7 then
		msg.Fields.remoteCountry = pw.getCountry(msg.Fields.remoteAddr)
	end

	
	if msg == nil then
		pw.debug("ERROR, empty message")
	else
        err = pcall(inject_message,msg)
		if err then
			--OK
		else
            pw.debug("ERROR, NIL for "..msg.Fields.message)
		end
    end
end

return M
