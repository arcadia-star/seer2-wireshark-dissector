-- wireshark_seer2msg_ciphertext.lua

-- 常量定义
local ONLINESERVER_TEL_IP = Address.ipv4("118.89.150.183")
local ONLINESERVER_CNC_IP = Address.ipv4("118.89.149.189")
local ONLINESERVER_PORT  = "1201-1276"
local XOR_KEY = ByteArray.new("74616f6d65655f73656572325f6b5f7e23")
local XOR_KEY_LEN = XOR_KEY:len()

-- 创建一个新的协议
SEER2MSG_CIPHERTEXT_PROTO = Proto("seer2msg_ciphertext", "Seer2 Message Ciphertext Protocol")
local FIELDS = {
    LENGTH = ProtoField.uint32("seer2msg_ciphertext.length", "Length", base.DEC),
    COMMAND_ID = ProtoField.int16("seer2msg_ciphertext.commandId", "Command ID", base.DEC),
    ENCRYPTED_DATA = ProtoField.bytes("seer2msg_ciphertext.encrypted_body", "Ciphertext Message"),
    DECRYPTED_DATA = ProtoField.string("seer2msg_ciphertext.decrypted_body", "Decrypted Message"),
    
    USER_ID = ProtoField.uint32("seer2msg_cleartext.userId", "User ID", base.DEC),
    SEQUENCE_INDEX = ProtoField.uint32("seer2msg_cleartext.sequenceIndex", "Sequence Index", base.DEC),
    STATUS_CODE = ProtoField.uint32("seer2_clientmsg_cleartext.statusCode", "Status Code", base.DEC),
    CHECKSUM = ProtoField.uint32("seer2msg_cleartext.checksum", "Checksum", base.DEC),
    MSGBODY = ProtoField.bytes("seer2msg_cleartext.seer2msgbody", "Message Body", base.SPACE),
}
SEER2MSG_CIPHERTEXT_PROTO.fields = FIELDS

local function seer2msg_dissector_clientmsg(buffer, pinfo, tree)
    local subtree = tree:add(SEER2MSG_CIPHERTEXT_PROTO, buffer(), "Seer2 Client Ciphertext Request Data")
    -- 解析字段值
    local userId = buffer(0, 4):le_uint()
    local sequenceIndex = buffer(4, 4):le_uint()
    local checksum = buffer(8, 4):le_uint()
    local msgbody = buffer(12)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(FIELDS.USER_ID, userId)
    subtree:add(FIELDS.SEQUENCE_INDEX, sequenceIndex)
    subtree:add(FIELDS.CHECKSUM, checksum)
    subtree:add(FIELDS.MSGBODY, msgbody)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Client Request(Ciphertext)"
    pinfo.cols.info:append(string.format(", User ID: %d, Sequence Index: %d, Checksum: %d",
        userId, sequenceIndex, checksum))
end

local function seer2msg_dissector_servermsg(buffer, pinfo, tree)
    local subtree = tree:add(SEER2MSG_CIPHERTEXT_PROTO, buffer(), "Seer2 Server Response Ciphertext Data")
    -- 解析字段值
    local userId = buffer(0, 4):le_uint()
    local sequenceIndex = buffer(4, 4):le_uint()
    local statusCode = buffer(8, 4):le_uint()
    local msgbody = buffer(12)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(FIELDS.USER_ID, userId)
    subtree:add(FIELDS.SEQUENCE_INDEX, sequenceIndex)
    subtree:add(FIELDS.STATUS_CODE, statusCode)
    subtree:add(FIELDS.MSGBODY, msgbody)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Server Response(Ciphertext)"
    pinfo.cols.info:append(string.format(", User ID: %d, Sequence Index: %d, Status Code: %d",
        userId, sequenceIndex, statusCode))
end

local function processMsg(buffer, pinfo, tree)
    local subtree = tree:add(SEER2MSG_CIPHERTEXT_PROTO, buffer(), "Seer2 Message Encrypted")

    -- 解析字段
    local length = buffer(0, 4):le_uint()
    local commandId = buffer(4, 2):le_int()
    local encrypted_bytes = buffer(6):bytes()

    -- 将字段添加到子树中
    subtree:add(FIELDS.LENGTH, length):append_text(" bytes"):set_generated()
    subtree:add(FIELDS.COMMAND_ID, commandId):set_generated()
    subtree:add(FIELDS.ENCRYPTED_DATA, buffer(6)):set_generated()

    -- 解密逻辑
    local decrypted_bytes = ByteArray.new()
    decrypted_bytes:set_size(encrypted_bytes:len() - 1)
    for i = 0, decrypted_bytes:len() - 1 do
        local result_high5bit = bit.lshift(encrypted_bytes:get_index(i + 1), 3)
        result_high5bit = bit.band(result_high5bit, 0xF8)
        local result_low3bit = bit.rshift(bit.band(encrypted_bytes:get_index(i), 0xE0), 5)
        result_low3bit = bit.band(result_low3bit, 0x07)
        local result_byte = bit.bor(result_high5bit, result_low3bit)
        result_byte = bit.bxor(result_byte, XOR_KEY:get_index(i % XOR_KEY_LEN))
        result_byte = bit.band(result_byte, 0xFF)
        decrypted_bytes:set_index(i, result_byte)
    end
    local decrypted_bytes_tvb = decrypted_bytes:tvb()

    -- 将解密消息添加到子树中
    local decrypted_body_tree = subtree:add(FIELDS.DECRYPTED_DATA, decrypted_bytes:tohex())
    decrypted_body_tree:set_generated()

    -- 在协议详情中显示字段值
    pinfo.cols.protocol = "Seer2 Message (Ciphertext)"
    pinfo.cols.info = string.format("Seer2 Message Encrypted Protocol Length: %d, Command ID: %d", length, commandId)

    -- 分发处理消息
    if pinfo.src == ONLINESERVER_TEL_IP or pinfo.src == ONLINESERVER_CNC_IP then
        seer2msg_dissector_servermsg(decrypted_bytes_tvb, pinfo, decrypted_body_tree)
    end
    if pinfo.dst == ONLINESERVER_TEL_IP or pinfo.dst == ONLINESERVER_CNC_IP then
        seer2msg_dissector_clientmsg(decrypted_bytes_tvb, pinfo, decrypted_body_tree)
    end
end


-- 解析 TCP payload
function SEER2MSG_CIPHERTEXT_PROTO.dissector(buffer, pinfo, tree)
    -- 检查源IP和目的IP并筛选掉我们不需要解析的包
    if not (
        pinfo.src == ONLINESERVER_TEL_IP or pinfo.dst == ONLINESERVER_TEL_IP
        or pinfo.src == ONLINESERVER_CNC_IP or pinfo.dst == ONLINESERVER_CNC_IP
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
tcp_table:add(ONLINESERVER_PORT , SEER2MSG_CIPHERTEXT_PROTO)
