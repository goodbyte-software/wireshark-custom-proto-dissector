-- Our protocol object
excom_proto = Proto('excom-proto', 'EXample COMmunication protocol')

-- Helper function for ProtoField names
local function field(field_name)
    return string.format('%s.%s', excom_proto.name, field_name)
end

-- RequestType enum
local request_type = {
    REQ_DISPLAY = 1,
    REQ_LED = 2,
}
-- Mapping of RequestType value to name
local request_type_names = {}
for name, value in pairs(request_type) do
    request_type_names[value] = name
end

-- Define field types available in our protocol, as a table to easily reference them later
local fields = {
    id = ProtoField.uint32(field('id'), 'Request ID', base.DEC),
    -- request_t
    type = ProtoField.uint8(field('type'), 'Request type', base.HEX, request_type_names),
    -- response_t
    status = ProtoField.bool(field('status'), 'Response status'),
}

-- Add all the types to Proto.fields list
for _, proto_field in pairs(fields) do
    table.insert(excom_proto.fields, proto_field)
end

-- Dissector callback, called for each packet
excom_proto.dissector = function(buf, pinfo, root)
    -- arguments:
    -- buf: packet's buffer (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
    -- pinfo: packet information (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
    -- root: node of packet details tree (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)

    -- Set name of the protocol
    pinfo.cols.protocol:set(excom_proto.name)

    -- Add new tree node for our protocol details
    local tree = root:add(excom_proto, buf())

    -- Extract message ID, this is the same for request_t and response_t
    -- `id` is of type uint32_t, so get a sub-slice: buf(offset=0, length=4)
    local id_buf = buf(0, 4)
    tree:add_le(fields.id, id_buf)

    -- request_t
    local type_data = buf(4, 1)
    tree:add_le(fields.type, type_data)
end

-- Register our protocol to be automatically used for traffic on port 9000
local tcp_port = DissectorTable.get('tcp.port')
tcp_port:add(9000, excom_proto)
