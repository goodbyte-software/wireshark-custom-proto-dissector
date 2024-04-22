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

-- Helper function for taking message data from buffer and configuring pinfo in case we need more data
local function msg_consumer(buf, pinfo)
    local obj = {
        msg_offset = 0, -- offset in buf to start of the current message
        msg_taken = 0, -- number of bytes consumed from current message
        not_enough = false,
    }

    obj.next_msg = function()
        obj.msg_offset = obj.msg_offset + obj.msg_taken
        obj.msg_taken = 0
    end

    obj.take_next = function(n)
        if obj.not_enough then -- subsequent calls
            return
        end

        -- If not enough data in the buffer then wait for next packet with correct offset
        if buf:len() - (obj.msg_offset + obj.msg_taken) < n then
            pinfo.desegment_offset = obj.msg_offset
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            obj.not_enough = true
            return
        end

        local data = buf:range(obj.msg_offset + obj.msg_taken, n)
        obj.msg_taken = obj.msg_taken + n
        return data
    end

    obj.current_msg_buf = function()
        return buf:range(obj.msg_offset, obj.msg_taken)
    end

    return obj
end

-- Dissector callback, called for each packet
excom_proto.dissector = function(buf, pinfo, root)
    -- arguments:
    -- buf: packet's buffer (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
    -- pinfo: packet information (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
    -- root: node of packet details tree (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)

    -- Set name of the protocol
    pinfo.cols.protocol:set(excom_proto.name)

    -- Construct TCP reassembly helper
    local consumer = msg_consumer(buf, pinfo)

    -- TCP reasasembly - loop through all messages in the packet
    while true do
        consumer.next_msg()

        -- Deferred adding of tree fields
        local tree_add = {}

        -- Extract request/response ID
        local id_buf = consumer.take_next(4)
        if not id_buf then
            return -- not enough data, take_next has configured pinfo to request more data
        end

        table.insert(tree_add, {fields.id, id_buf})
        local id = id_buf:uint()

        -- Distinguish request/response
        if pinfo.dst_port == server_port then
            -- request_t
            local type_buf = consumer.take_next(1)
            if not type_buf then
                return
            end

            table.insert(tree_add, {fields.type, type_buf})

            -- request_data_t depending on the `type` field
            local type = type_buf:le_uint()
            if type == request_type.REQ_DISPLAY then
                -- display_request_t
                local len_buf = consumer.take_next(4)
                local text_buf = len_buf and consumer.take_next(len_buf:le_uint())
                if not text_buf then
                    return
                end
                table.insert(tree_add, {fields.display_text_length, len_buf})
                table.insert(tree_add, {fields.display_text, text_buf})
            elseif type == request_type.REQ_LED then
                -- led_request_t
                local id_buf = consumer.take_next(2)
                local state_buf = consumer.take_next(1)
                if not state_buf then
                    return
                end
                table.insert(tree_add, {fields.led_id, id_buf})
                table.insert(tree_add, {fields.led_state, state_buf})
            end

            -- On first dissection run (pinfo.visited=false) store mapping from request id to frame number
            if not pinfo.visited then
                id2frame.request[id_buf:uint()] = pinfo.number
            end

            -- If possible add information about matching response
            if id2frame.response[id] then
                table.insert(tree_add, {fields.response, id2frame.response[id]})
            end
        else
            -- response_t
            local status_buf = consumer.take_next(1)
            table.insert(tree_add, {fields.status, status_buf})

            if not pinfo.visited then
                id2frame.response[id_buf:uint()] = pinfo.number
            end
            if id2frame.request[id] then
                table.insert(tree_add, {fields.request, id2frame.request[id]})
            end
        end

        -- Add tree node for this message only if we reached this place
        local tree = root:add(excom_proto, consumer.current_msg_buf())
        for _, to_add in ipairs(tree_add) do
            tree:add_le(to_add[1], to_add[2])
        end
    end
end

-- Register our protocol to be automatically used for traffic on port 9000
local tcp_port = DissectorTable.get('tcp.port')
tcp_port:add(server_port, excom_proto)
