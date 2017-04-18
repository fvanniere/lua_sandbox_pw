
TEST_MODE = 1

redis = {}
redisclient = {}

redis_data = {
	["HOST_IP/kaa"] = "kaa;kaa;00c29c75ddb34f81a193b4567989918d;172.16.5.148,10.3.0.46,2a01:648:0:5::148",
	["HOST_IP/10.3.0.3"] = "nemo;tenant2;9cf8100376bf476594287cc7260aa636;172.16.4.13,192.168.3.56,10.3.0.3,192.168.3.33,2a01:648::13",
	["HOST_IP/2a01:648::4"] = "mutu;tenant1;7106d636681c49418439e227e81bdb60;172.16.4.4,2a01:648::4",
	["HOST/tenant1/pw.fr"] = "webmaster;www.pw.fr",
	["ZONE/tenant1/pw.fr"] = "webmaster",
}

function redis.connect()
	return redisclient
end

function redisclient.auth(key)
end

function redisclient.get(foo, key)
	local res = redis_data[key]
	if res then return res end
	io.write("REDIS GET ".. key .."\n")

	return "????;***;###"
end

function inject_message(msg)
end

local pwlib = require "pwlib"
local io = require"io"

local geoip = require"geoip"
local geoip_country = require 'geoip.country'

cache = pwlib.new_cache()

local function debug(log,fields)
    io.write("==================================================================\n")
    io.write(log.."\n")
    io.write("==================================================================\n")
    if fields == nil then
        io.write("ERRROR, no match\n")
    else
       for k, v in pairs( fields ) do
           io.write(k .. " = ".. v .. "\n")
       end
    end
end

local function get_funcs()
	tenant, tenant_id = pwlib.get_tenant('kaa')
	assert(tenant == 'kaa', tenant)
	assert(tenant_id == '00c29c75ddb34f81a193b4567989918d', tenant_id)

	tenant, tenant_id = pwlib.get_tenant('10.3.0.3')
	assert(tenant == 'tenant2', tenant)
	assert(tenant_id == '9cf8100376bf476594287cc7260aa636', tenant_id)

	tenant, tenant_id = pwlib.get_tenant('2a01:648::4')
	assert(tenant == 'tenant1', tenant)
	assert(tenant_id == '7106d636681c49418439e227e81bdb60', tenant_id)

    vh, user = pwlib.get_user_vhost_from_host("pw.fr","tenant1")
	assert(vh == 'www.pw.fr', vh)
	assert(user == 'webmaster', user)

	user = pwlib.get_user_from_domain("pw.fr","tenant1")
	assert(user == 'webmaster', user)

	--user = pwlib.get_user_from_uid("1002","kaa")

	user = pwlib.get_user_from_login("webmaster@pw.fr","tenant1")
	assert(user == 'webmaster', user)

	user = pwlib.get_user_from_login("webmaster%pw.fr","tenant1")
	assert(user == 'webmaster', user)

	user = pwlib.get_user_from_login("webmaster","kaa")
	assert(user == 'webmaster', user)

    hash = pwlib.hash("coucou")
	assert(hash == 4038781895, hash)

    hash = pwlib.hash("Hello World")
	assert(hash == 1243066710, hash)
end

local function test_geoip()

	local geoip_country_filename = "/usr/share/GeoIP/GeoIP.dat"
	local geoip_countryv6_filename = "/usr/share/GeoIP/GeoIPv6.dat"
	local geoip_city_filename = "/usr/share/GeoIP/GeoIPCity.dat"

	local geoip_country_lookup =  geoip_country.open(geoip_country_filename,geoip.MEMORY_CACHE)
	local geoip_country_lookup6 =  geoip_country.open(geoip_countryv6_filename,geoip.MEMORY_CACHE,geoip.COUNTRY_V6)


	local results = {
		["63.245.213.17"] = "US",
		["2a00:1450:4001:81b::2004"] = "IE",
		["2a01:648::1"] = "FR",
		["80.15.190.207"] = "FR",
		["10.3.0.1"] = "--",
	}

    for ip, cc in pairs(results) do
        if string.match(ip, ":") then
            res = geoip_country_lookup6:query_by_addr6(ip)
        else
            res = geoip_country_lookup:query_by_addr(ip)
        end
        assert(res.code == cc, res.code)
    end



end


get_funcs()
test_geoip()



