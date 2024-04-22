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
    -- display_request_t
    display_text_length = ProtoField.uint32(field('display.text_length'), 'Text length', base.DEC),
    display_text = ProtoField.string(field('display.text'), 'Text', base.ASCII),
    -- led_request_t
    led_id = ProtoField.uint16(field('led.id'), 'LED ID', base.DEC),
    led_state = ProtoField.bool(field('led.state'), 'LED state'),

    -- special fields to provide information about matching request/response
    request = ProtoField.framenum(field('request'), 'Request', base.NONE, frametype.REQUEST),
    response = ProtoField.framenum(field('response'), 'Response', base.NONE, frametype.RESPONSE),
}

-- Add all the types to Proto.fields list
for _, proto_field in pairs(fields) do
    table.insert(excom_proto.fields, proto_field)
end

-- TCP port on which to dissect our protocol
local server_port = 9000

-- Mappings of request/response ID to frame numbers
local id2frame = {
    request = {}, -- request id -> request frame number
    response = {}, -- response id -> response frame number
}

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
    local id = id_buf:uint()

    if pinfo.dst_port == server_port then
        -- request_t
        local type_data = buf(4, 1)
        tree:add_le(fields.type, type_data)

        -- request_data_t depending on the `type` field
        local type = type_data:le_uint()
        if type == request_type.REQ_DISPLAY then
            -- display_request_t
            local len_buf = buf(5, 4)
            tree:add_le(fields.display_text_length, len_buf)
            tree:add_le(fields.display_text, buf(9, len_buf:le_uint()))
        elseif type == request_type.REQ_LED then
            -- led_request_t
            tree:add_le(fields.led_id, buf(5, 2))
            tree:add_le(fields.led_state, buf(7, 1))
        end

        -- On first dissection run (pinfo.visited=false) store mapping from request id to frame number
        if not pinfo.visited then
            id2frame.request[id_buf:uint()] = pinfo.number
        end

        -- If possible add information about matching response
        if id2frame.response[id] then
            tree:add_le(fields.response, id2frame.response[id])
        end
    else
        -- response_t
        tree:add_le(fields.status, buf(4, 1))

        if not pinfo.visited then
            id2frame.response[id_buf:uint()] = pinfo.number
        end
        if id2frame.request[id] then
            tree:add_le(fields.request, id2frame.request[id])
        end
    end
end

-- Register our protocol to be automatically used for traffic on port 9000
local tcp_port = DissectorTable.get('tcp.port')
tcp_port:add(server_port, excom_proto)
