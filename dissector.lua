-- SLDP (Simple Layer-2 Discovery Protocol) Dissector
-- Author: Lyton Mshanga
-- Architecture: Cross-Device IPv4 <-> IPv6 Translation Binding

local sldp_proto = Proto("sldp", "SLDP Cross-Device Translation Protocol")

-- Dissector Fields
local f_sender_mac = ProtoField.ether("sldp.sender_mac", "Origin Hardware MAC")
local f_origin_v4  = ProtoField.ipv4("sldp.origin_v4", "Origin IPv4 (Host A)")
local f_target_v6  = ProtoField.ipv6("sldp.target_v6", "Target IPv6 (Host B)")
local f_flags      = ProtoField.uint16("sldp.flags", "Control Flags", base.HEX)

sldp_proto.fields = { f_sender_mac, f_origin_v4, f_target_v6, f_flags }

function sldp_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 28 then return end

    pinfo.cols.protocol = "SLDP"

    -- Binary Payload Extraction
    local mac_raw   = buffer(0, 6)
    local v4_raw    = buffer(6, 4)
    local v6_raw    = buffer(10, 16)
    local flags_raw = buffer(26, 2)

    local flags_val = flags_raw:uint()
    local v4_str    = tostring(v4_raw:ipv4())
    local v6_str    = tostring(v6_raw:ipv6())

    -- Dynamic Info Column Summary
    if flags_val == 0x0001 then
        pinfo.cols.info = string.format("Translation Request | Host A IPv4 (%s) seeking IPv6 Target", v4_str)
    elseif flags_val == 0x0002 then
        pinfo.cols.info = string.format("Cross-Device Bound | Host A (%s) <===> Host B (%s)", v4_str, v6_str)
    else
        pinfo.cols.info = string.format("SLDP Unknown Flag (0x%04X)", flags_val)
    end

    -- Packet Tree Construction
    local subtree = tree:add(sldp_proto, buffer(), "SLDP Cross-Device Translation Payload")
    subtree:add(f_origin_v4, v4_raw)
    subtree:add(f_target_v6, v6_raw)
    subtree:add(f_flags, flags_raw)
    subtree:add(f_sender_mac, mac_raw)
end

-- Register Dissector to EtherType 0x88B5
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x88b5, sldp_proto)
