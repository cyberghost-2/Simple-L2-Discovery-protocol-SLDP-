-- SLDP (Simple Layer-2 Discovery Protocol) Dissector
-- Revision 3.1 — aligned with 46-byte payload / explicit type tags
--
-- Wire format (46-byte SLDP payload, EtherType 0x88B5):
--   Offset  Size  Field
--   0       6     Origin MAC
--   6       1     Src Type   (0x04 = IPv4, 0x06 = IPv6)
--   7       16    Source IP  (IPv4 in first 4 bytes, or native IPv6)
--   23      1     Tgt Type   (0x00 = unset, 0x04 / 0x06)
--   24      16    Target IP  (zeroed in probes)
--   40      1     Version    (0x01)
--   41      1     Message Type (0x01 = probe, 0x02 = response)
--   42      4     Reserved

local sldp_proto = Proto("sldp", "SLDP Cross-Device Translation Protocol")

-- Field definitions
local f_origin_mac = ProtoField.ether ("sldp.origin_mac", "Origin MAC")
local f_src_type   = ProtoField.uint8 ("sldp.src_type",   "Src Type", base.HEX,
    { [0x04] = "IPv4", [0x06] = "IPv6" })
local f_src_ipv4   = ProtoField.ipv4  ("sldp.src_ipv4",   "Source IPv4")
local f_src_ipv6   = ProtoField.ipv6  ("sldp.src_ipv6",   "Source IPv6")
local f_tgt_type   = ProtoField.uint8 ("sldp.tgt_type",   "Tgt Type", base.HEX,
    { [0x00] = "Unset", [0x04] = "IPv4", [0x06] = "IPv6" })
local f_tgt_ipv4   = ProtoField.ipv4  ("sldp.tgt_ipv4",   "Target IPv4")
local f_tgt_ipv6   = ProtoField.ipv6  ("sldp.tgt_ipv6",   "Target IPv6")
local f_version    = ProtoField.uint8 ("sldp.version",    "Version", base.HEX)
local f_msg_type   = ProtoField.uint8 ("sldp.msg_type",   "Message Type", base.HEX,
    { [0x01] = "DISCOVERY_REQ", [0x02] = "DISCOVERY_RESP" })
local f_reserved   = ProtoField.bytes ("sldp.reserved",   "Reserved")

sldp_proto.fields = {
    f_origin_mac, f_src_type, f_src_ipv4, f_src_ipv6,
    f_tgt_type, f_tgt_ipv4, f_tgt_ipv6,
    f_version, f_msg_type, f_reserved,
}

-- Helpers
local function fmt_ip(buf, type_tag)
    if type_tag == 0x04 then
        return tostring(buf(0, 4):ipv4())
    elseif type_tag == 0x06 then
        return tostring(buf:ipv6())
    end
    return "<unset>"
end

function sldp_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 46 then return end

    pinfo.cols.protocol = "SLDP"

    -- Slice the payload
    local origin_mac  = buffer(0, 6)
    local src_type_b  = buffer(6, 1)
    local src_ip_raw  = buffer(7, 16)
    local tgt_type_b  = buffer(23, 1)
    local tgt_ip_raw  = buffer(24, 16)
    local version_b   = buffer(40, 1)
    local msg_type_b  = buffer(41, 1)
    local reserved_b  = buffer(42, 4)

    local src_type    = src_type_b:uint()
    local tgt_type    = tgt_type_b:uint()
    local version     = version_b:uint()
    local msg_type    = msg_type_b:uint()

    local src_ip_str  = fmt_ip(src_ip_raw, src_type)
    local tgt_ip_str  = fmt_ip(tgt_ip_raw, tgt_type)

    -- Info column
    if version ~= 0x01 then
        pinfo.cols.info = string.format("SLDP unknown version 0x%02X", version)
    elseif msg_type == 0x01 then
        pinfo.cols.info = string.format(
            "DISCOVERY_REQ | src %s (%s) seeking opposite-family peer",
            src_ip_str,
            src_type == 0x04 and "IPv4" or "IPv6")
    elseif msg_type == 0x02 then
        pinfo.cols.info = string.format(
            "DISCOVERY_RESP | %s (%s) <===> %s (%s)",
            src_ip_str, src_type == 0x04 and "IPv4" or "IPv6",
            tgt_ip_str, tgt_type == 0x04 and "IPv4" or (tgt_type == 0x06 and "IPv6" or "unset"))
    else
        pinfo.cols.info = string.format("SLDP unknown message type 0x%02X", msg_type)
    end

    -- Tree
    local subtree = tree:add(sldp_proto, buffer(), "SLDP Cross-Device Translation Payload")

    subtree:add(f_origin_mac, origin_mac)
    subtree:add(f_src_type,   src_type_b)

    if src_type == 0x04 then
        subtree:add(f_src_ipv4, src_ip_raw(0, 4))
    elseif src_type == 0x06 then
        subtree:add(f_src_ipv6, src_ip_raw)
    end

    subtree:add(f_tgt_type, tgt_type_b)

    if tgt_type == 0x04 then
        subtree:add(f_tgt_ipv4, tgt_ip_raw(0, 4))
    elseif tgt_type == 0x06 then
        subtree:add(f_tgt_ipv6, tgt_ip_raw)
    end

    subtree:add(f_version,  version_b)
    subtree:add(f_msg_type, msg_type_b)
    subtree:add(f_reserved, reserved_b)
end

-- Register to EtherType 0x88B5
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x88b5, sldp_proto)
