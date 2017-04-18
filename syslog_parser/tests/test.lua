
TEST_MODE = 1

redis = {}
redisclient = {}

function redis.connect()
	return redisclient
end

function redisclient.get(key)
	return "XXXXX"
end

function redisclient.auth(key)
end

function debug(log,fields)
	if log then
		io.write("==================================================================\n")
		io.write(log.."\n")
		io.write("==================================================================\n")
	else
		io.write("==================================================================\n")
	end

	if fields == nil then
		io.write("ERRROR, no match\n")
	else
	   for k, v in pairs( fields ) do
		   if type(v) == "table" then
    		   io.write(k .. " = \n")
			   for k2, v2 in pairs( v ) do
			       io.write("    " .. k2 .. " = ".. v2 .. "\n")
			   end
		   else
    		   io.write(k .. " = ".. v .. "\n")
		   end
	   end
	end
end

function inject_message(msg)
end

pwlib = require"pwlib"

cache = pwlib.new_cache()

f = loadfile"test_parser.lua"
f()

f = loadfile"test_decoder.lua"
f()


