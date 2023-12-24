-- wireshark_seer2msg_ciphertext.lua

-- 常量定义
local onlineserver_tel_ip = Address.ipv4("118.89.150.183")
local onlineserver_cnc_ip = Address.ipv4("118.89.149.189")
local onlineserver_port = "1201-1276"
local key = ByteArray.new("74616f6d65655f73656572325f6b5f7e23")
local key_len = key:len()

-- 创建一个新的协议
seer2msg_ciphertext_proto = Proto("seer2msg_ciphertext", "Seer2 Message Ciphertext Protocol")
local length_field = ProtoField.uint32("seer2msg_ciphertext.length", "Length", base.DEC)
local commandId_field = ProtoField.int16("seer2msg_ciphertext.commandId", "Command ID", base.DEC)
local encrypted_data_field = ProtoField.bytes("seer2msg_ciphertext.encrypted_body", "Ciphertext Message")
local decrypted_data_field = ProtoField.string("seer2msg_ciphertext.decrypted_body", "Decrypted Message")

local userId_field = ProtoField.uint32("seer2msg_cleartext.userId", "User ID", base.DEC, nil, nil, "little-endian")
local sequenceIndex_field = ProtoField.uint32("seer2msg_cleartext.sequenceIndex", "Sequence Index", base.DEC, nil, nil, "little-endian")
local statusCode_field = ProtoField.uint32("seer2_clientmsg_cleartext.statusCode", "Status Code", base.DEC, nil, nil, "little-endian")
local checksum_field = ProtoField.uint32("seer2msg_cleartext.checksum", "Checksum", base.DEC, nil, nil, "little-endian")
local msgbody_field = ProtoField.bytes("seer2msg_cleartext.seer2msgbody", "Message Body", base.DOT)

seer2msg_ciphertext_proto.fields = { length_field, commandId_field, encrypted_data_field, decrypted_data_field,
userId_field,sequenceIndex_field,statusCode_field,checksum_field,msgbody_field
}

local function seer2msg_dissector_clientmsg(buffer, pinfo, tree)
    local subtree = tree:add(seer2msg_ciphertext_proto, buffer(), "Seer2 Client Ciphertext Request Data")
    -- 解析字段值
    local userId = buffer(0, 4):le_uint()
    local sequenceIndex = buffer(4, 4):le_uint()
    local checksum = buffer(8, 4):le_uint()
    local msgbody = buffer(12)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(userId_field, userId)
    subtree:add(sequenceIndex_field, sequenceIndex)
    subtree:add(checksum_field, checksum)
    subtree:add(msgbody_field, msgbody)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Client Request(Ciphertext)"
    pinfo.cols.info:append(string.format(", User ID: %d, Sequence Index: %d, Checksum: %d",
        userId, sequenceIndex, checksum))
end

local function seer2msg_dissector_servermsg(buffer, pinfo, tree)
    local subtree = tree:add(seer2msg_ciphertext_proto, buffer(), "Seer2 Server Response Ciphertext Data")
    -- 解析字段值
    local userId = buffer(0, 4):le_uint()
    local sequenceIndex = buffer(4, 4):le_uint()
    local statusCode = buffer(8, 4):le_uint()
    local msgbody = buffer(12)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(userId_field, userId)
    subtree:add(sequenceIndex_field, sequenceIndex)
    subtree:add(statusCode_field, statusCode)
    subtree:add(msgbody_field, msgbody)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Server Response(Ciphertext)"
    pinfo.cols.info:append(string.format(", User ID: %d, Sequence Index: %d, Status Code: %d",
        userId, sequenceIndex, statusCode))
end

local function processMsg(buffer, pinfo, tree)
    local subtree = tree:add(seer2msg_ciphertext_proto, buffer(), "Seer2 Message Encrypted")

    -- 解析字段
    local length = buffer(0, 4):le_uint()
    local commandId = buffer(4, 2):le_int()
    local encrypted_bytes = buffer(6):bytes()

    -- 将字段添加到子树中
    subtree:add(length_field, length):append_text(" bytes"):set_generated()
    subtree:add(commandId_field, commandId):set_generated()
    subtree:add(encrypted_data_field, buffer(6)):set_generated()

    -- 解密逻辑：第一次处理
    local decrypted_bytes_part1 = ByteArray.new()
    decrypted_bytes_part1:set_size(encrypted_bytes:len() - 1)
    for i = 0, decrypted_bytes_part1:len() - 1 do
        local result_high5bit = bit.lshift(encrypted_bytes:get_index(i + 1), 3)
        result_high5bit = bit.band(result_high5bit, 0xF8)
        local result_low3bit = bit.rshift(bit.band(encrypted_bytes:get_index(i), 0xE0), 5)
        result_low3bit = bit.band(result_low3bit, 0x07)
        local result_byte = bit.bor(result_high5bit, result_low3bit)
        result_byte = bit.band(result_byte, 0xFF)
        decrypted_bytes_part1:set_index(i, result_byte)
    end

    -- 解密逻辑：第二次处理
    local decrypted_bytes = ByteArray.new()
    decrypted_bytes:set_size(decrypted_bytes_part1:len())
    for i = 0, decrypted_bytes_part1:len() - 1 do
        local ki = i % key_len
        decrypted_bytes:set_index(i, bit.bxor(decrypted_bytes_part1:get_index(i), key:get_index(ki)))
    end
    local decrypted_bytes_tvb = decrypted_bytes:tvb()

    -- 将解密消息添加到子树中
    local decrypted_body_tree = subtree:add(decrypted_data_field, decrypted_bytes:tohex())
    decrypted_body_tree:set_generated()

    -- 在协议详情中显示字段值
    pinfo.cols.protocol = "Seer2 Message (Ciphertext)"
    pinfo.cols.info = string.format("Seer2 Message Encrypted Protocol Length: %d, Command ID: %d", length, commandId)

    -- 分发处理消息
    if pinfo.src == onlineserver_tel_ip or pinfo.src == onlineserver_cnc_ip then
        seer2msg_dissector_servermsg(decrypted_bytes_tvb, pinfo, decrypted_body_tree)
    end
    if pinfo.dst == onlineserver_tel_ip or pinfo.dst == onlineserver_cnc_ip then
        seer2msg_dissector_clientmsg(decrypted_bytes_tvb, pinfo, decrypted_body_tree)
    end
end


-- 解析 TCP payload
function seer2msg_ciphertext_proto.dissector(buffer, pinfo, tree)
    -- 检查源IP和目的IP并筛选掉我们不需要解析的包
    if not (
        pinfo.src == onlineserver_tel_ip or pinfo.dst == onlineserver_tel_ip
        or pinfo.src == onlineserver_cnc_ip or pinfo.dst == onlineserver_cnc_ip
    ) then
        -- 返回0表示这个流不属于我们
        return 0
    end

    -- TCP 流重组
    local tvb_len = buffer:len()
    local offset = pinfo.desegment_offset or 0

    while offset < tvb_len do
        -- 检查是否有足够的数据来解析消息长度
        if tvb_len - offset < 4 then
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end

        -- 检查是否有足够的数据来解析整个消息
        local msglen = buffer(offset, 4):le_uint()
        if tvb_len - offset < msglen then
            -- 消息不完整，等待更多切片
            pinfo.desegment_offset = offset
            pinfo.desegment_len = msglen - (tvb_len - offset)
            return
        end

        -- 处理消息
        processMsg(buffer:range(offset, msglen), pinfo, tree)

        offset = offset + msglen
    end

end

-- 将协议与TCP端口关联
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(onlineserver_port, seer2msg_ciphertext_proto)
