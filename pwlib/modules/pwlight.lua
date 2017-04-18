--[[

Planet-Work helper lib for messages processing


]]--

local inject_message = inject_message

local M = {}
setfenv(1, M)


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


return M
