
odin = Proto("odin2hostapd","Odin 2 HostAPd for eapol")

local cmds = { "EAPOL_RECV", "EAPOL_SEND", "PING", "PING_RESPONSE", "AUTHORIZE", "SET_HW_KEY" }

local f = odin.fields
f.version = ProtoField.uint8("odin.version", "Version")
f.command = ProtoField.uint8("odin.name", "Command", nil, cmds)
f.length = ProtoField.uint16("odin.length", "Length")
f.sta = ProtoField.ether("odin.sta", "Station")
f.bssid = ProtoField.ether("odin.bssid", "AP BSSID")
f.pingid = ProtoField.uint8("odin.pingid", "Ping Session ID - will be included into response")
f.payload = ProtoField.bytes("odin.payload", "Payload")

function odin.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 then
        return
    end

    local version = buffer(0, 1)
    local cmd_buf = buffer(1, 1)
    local len_buf = buffer(2, 2)
    local sta_buf = buffer(4, 6)
    local bssid_buf = buffer(10, 6)
    local payload = nil

    if buffer:len() >= 16 then
        payload = buffer(16)
    end
    local cmd = buffer(1, 1):uint()
    local len = buffer(2, 4):uint()

    -- dissector
    pinfo.cols.protocol = "odin"
    local subtree = tree:add(odin, buffer(),"odin 2 hostapd")
    subtree:add(f.version, version)
    subtree:add(f.command, cmd_buf)
    subtree:add(f.length, len_buf)
    subtree:add(f.sta, sta_buf)
    subtree:add(f.bssid, bssid_buf)
    subtree:add(f.payload, payload)

    if cmd == 1 or cmd == 2 then
        local wpan_dis = Dissector.get("eapol")
        wpan_dis:call(payload:tvb(), pinfo, tree)
    end
end
udp_table = DissectorTable.get("udp.port")
udp_table:add(9987, odin)

