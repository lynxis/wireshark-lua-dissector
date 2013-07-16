
hapd = Proto("HostAPD","HostAPd test driver")

function hapd.dissector(buffer, pinfo, tree)
    local commands = {}
    commands["SCAN"] = {}
    commands["SCANRESP"] = {[0] = "mac", [1] = "data", [2]="flag"}

    local buffer_str = buffer(0, buffer:len()):string()

    local cmdlen = string.find(buffer_str, ' ')
    if cmdlen == nil then
        cmdlen = buffer:len()
    else
        cmdlen = cmdlen -1
    end

    local cmd = tostring(buffer(0, cmdlen):string())

    -- dissector
    pinfo.cols.protocol = "HAPD"
    local subtree = tree:add(hapd, buffer(),"HAPD driver")
    subtree:add(buffer(0, cmdlen), "command: " .. buffer(0, cmdlen):string())
    -- loop over cmd
    
    local command = commands[cmd]

    if cmd == "EAPOL" then
        debug("EAPOL received")
        local wpan_dis = Dissector.get("eth")
        wpan_dis:call(buffer(6):tvb(), pinfo, tree)
    end

    if command ~= nil then
        local strpos = cmdlen + 2
        for key, fieldname in pairs(command) do
            local datalen = string.find(string.sub(buffer_str, strpos, buffer:len()), ' ')
            if datalen == nil then
                break
            end
            subtree:add(buffer(strpos -1, datalen), fieldname .. ": " .. buffer(strpos -1, datalen):string())
            strpos = strpos + datalen
        end
    end

end
udp_table = DissectorTable.get("udp.port")
udp_table:add(4223, hapd)

