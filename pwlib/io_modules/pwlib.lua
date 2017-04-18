--[[


Planet-Work helper lib for messages processing


]]--

local inject_message = inject_message
local read_config = read_config
local os = require "os"
local io = require "io"
local string = require "string"
local math = require "math"
local bit32 = require "bit32"

local geoip = require"geoip"
local geoip_country = require 'geoip.country'
local geoip_country_filename = "/usr/share/GeoIP/GeoIP.dat"
local geoip_countryv6_filename = "/usr/share/GeoIP/GeoIPv6.dat"
local geoip_country_lookup =  geoip_country.open(geoip_country_filename,geoip.MEMORY_cache)
local geoip_country_lookup6 =  geoip_country.open(geoip_countryv6_filename,geoip.MEMORY_cache,geoip.COUNTRY_V6)


if TEST_MODE == 1 then
    redis = redis
else
    redis = require 'redis'
end

local redis = redis
local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring

local counter = 0

local M = {}
local cachetimeout = read_config('cache_timeout') or 900

cache = nil

setfenv(1, M)


local redis_params = read_config('redis') or {
    host = '127.0.0.1',
    port = 6379,
    auth = nil
}

local blacklist_url = read_config('blacklist_url')

redis_client = redis.connect(redis_params)
if redis_params.auth ~= nil then
    redis_client:auth(redis_params.auth)
end

function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end



function M.error(message)
   local msg =  {}
   msg.Type = "hindsight.log"
   msg.Severity = 3
   msg.Payload = message
   inject_message(msg)
end

function M.info(message) 
   local msg =  {}
   msg.Type = "hindsight.log"
   msg.Severity = 6
   msg.Payload = message
   inject_message(msg)
end

function M.debug(message) 
   local msg =  {}
   msg.Type = "hindsight.log"
   msg.Severity = 7
   msg.Payload = message
   inject_message(msg)
end

function M.debug_f(fields) 
    if pretty then
        pretty.dump(fields)
    end
end

function M.blacklist_ip(ip,bl)
    local reqbody = "what="..ip.."&blname="..bl

    r, c, h = http.request {
       method = "POST",
       url = blacklist_url,
       source = ltn12.source.string(reqbody),
       headers = {
           ['Content-type'] = 'application/x-www-form-urlencoded',
           ["content-length"] = tostring(#reqbody)
       }
    }
end



function M.getCountry(ip)
    local res

	local cachekey = "COUNTRY/"..ip
	local cvalue = cache:get(cachekey)
	if cvalue then return cvalue end

	if string.match(ip, ":") then
		res = geoip_country_lookup6:query_by_addr6(ip)
		--res = { code = '??'}
	else
		res = geoip_country_lookup:query_by_addr(ip)
	end
    cache:set(cachekey,res.code)
	return res["code"]
end

-- Returns tenant and tenant_id
function M.get_tenant(hostname)
    if hostname == nil then
        return "",""
    end
    -- in local cache ?
    local cachekey = "HOST_IP/"..hostname
	local cvalue = cache:get(cachekey)
	if cvalue then return cvalue[1], cvalue[2] end

   local res = redis_client:get(cachekey)
   if res then
        local data  = string.split(res,";")
        cache:set(cachekey,{data[2], data[3]})
        return data[2], data[3]
   else
      return nil,"Tenant not found"
   end
end

function M.get_user_vhost_from_host(http_host,tenant)
    if tenant == nil then
        return http_host, ""
    end

    local cachekey = "HOST/" .. tenant .. "/" .. http_host
	local cvalue = cache:get(cachekey)
	if cvalue then return cvalue[1], cvalue[2] end

    res = redis_client:get(cachekey)
    if res then
        data  = res:split(';')
	    cache:set(cachekey,{data[2], data[1]})
        return data[2], data[1]
    else
	    cache:set(cachekey,{http_host, ""})
        return http_host, ""
    end
end

function M.get_user_from_login(login,tenant)
    if not tenant then
       return nil
    end
    local res = string.match(login,"@.*")
    if res == nil then
	   res = string.match(login,"%%.*")
	end
	if res == nil then
		return login
	end
    return M.get_user_from_domain(string.sub(res,2), tenant)
end

function M.get_user_from_domain(domain,tenant)
    if not tenant then
        return ""
    end

    local cachekey = "ZONE/" .. tenant .. "/" .. domain
	local cvalue = cache:get(cachekey)
	if cvalue == "" then return nil end
	if cvalue then return cvalue end

    local res = redis_client:get(cachekey)
    if res then
		cache:set(cachekey,res)
        return res
   else
       cache:set(cachekey,"")
       return nil
   end
end




function M.get_user_from_uid(uid,tenant)
    if not tenant then
         return ""
    end
    local cachekey = "USER/"..tenant.."/"..uid
	local cvalue = cache:get(key)
	if cvalue then return cvalue end
    res = redis_client:get(cachekey)
    if res then
        data  = res:split(';')
		cache:set(cachekey,data[1])
        return data[1]
    else
        return ""
    end
end



function M.cache_set(self, key, val)
	local now = os.time()
	--[[
	if type(val) == "string" then
        M.debug("CACHE SET[".. self.cache_id .. "]::"..key.."="..val)
	elseif type(val) == "table" then
        M.debug("CACHE SET[".. self.cache_id .. "]::"..key.."="..val[1]..";"..val[2])
	else
        M.debug("CACHE SET[".. self.cache_id .. "]::"..key.."=ERROR NIL")
	end
	]]--
	self.cache[key] = {
        value = val, 
	    expire = (now + cachetimeout)
	}
end

function M.cache_get(self, key)
	counter = counter + 1
	if counter % 100000 == 0 then cache:cleanup() end
	if self.cache[key] ~= nil then
        --M.debug("CACHE GET[".. self.cache_id .. "]::"..key .. " IN CACHE")
		return self.cache[key].value
	end
    --M.debug("CACHE GET[".. self.cache_id .. "]::"..key .. " NOT FOUND")
	return nil
end

function M.cache_cleanup(self)
    --M.debug("CACHE CLEAN[".. self.cache_id .. "] :: ".. os.time() .. ":::".. counter)
    local now = os.time()
    for k,v in pairs(self.cache) do
        if v.expire < now then
		    --M.debug("CACHE DELETE".. self.cache_id .. "] :: ".. k .. " " .. v.expire .. ">" .. now)
            self.cache[k] = nil
        end
    end
end

function M.new_cache() 
	cache = {
		cache = {},
		cache_id = math.floor(math.random()*1000),
		cleanup = M.cache_cleanup,
		last_cleanup = os.time(),
		set = M.cache_set,
		get = M.cache_get,
	}
	return cache
end

local CRC32 = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
}

local xor = bit32.bxor
local lshift = bit32.lshift
local rshift = bit32.rshift
local band = bit32.band

function M.hash(str)
    str = tostring(str)
    local count = string.len(str)
    local crc = 2 ^ 32 - 1
    local i = 1

    while count > 0 do
        local byte = string.byte(str, i)
        crc = xor(rshift(crc, 8), CRC32[xor(band(crc, 0xFF), byte) + 1])
        i = i + 1
        count = count - 1
    end
    crc = xor(crc, 0xFFFFFFFF)
    -- dirty hack for bitop return number < 0
    if crc < 0 then crc = crc + 2 ^ 32 end

    return crc
end



function M.ts_to_datetime(ts,hostname)
   res = os.date("%Y-%m-%dT%H:%M:%S%z",ts/1e9)
   return res
end

function M.ts_to_datetime_cest(ts,hostname)
   --res = os.date("%Y-%m-%dT%H:%M:%S%z",ts/1e9)
   res = os.date("%Y-%m-%dT%H:%M:%S+0200",ts/1e9)
   return res
end


return M
