-- wireshark_seer2msg_cleartext.lua

-- 常量定义
local LOGINSERVER_TEL_IP = "118.89.150.43" -- http://ctsr2login.61.com/ip.txt
local LOGINSERVER_CNC_IP = "118.89.150.23" -- http://cncsr2login.61.com/ip.txt
local LOGINSERVER_PORT = 1863

-- Creating protocol SEER2MSG_CLEARTEXT_PROTO
SEER2MSG_CLEARTEXT_PROTO = Proto("seer2msg_cleartext", "Seer2 Message Cleartext")
local F_LENGTH = ProtoField.uint32("seer2msg_cleartext.length", "Length", base.DEC)
local F_COMMAND_ID = ProtoField.uint16("seer2msg_cleartext.commandId", "Command ID", base.DEC)
local F_USER_ID = ProtoField.uint32("seer2msg_cleartext.userId", "User ID", base.DEC)
local F_SEQUENCE_INDEX = ProtoField.uint32("seer2msg_cleartext.sequenceIndex", "Sequence Index", base.DEC)
local F_STATUS_CODE = ProtoField.uint32("seer2_clientmsg_cleartext.statusCode", "Status Code", base.DEC)
local F_CHECKSUM = ProtoField.uint32("seer2msg_cleartext.checksum", "Checksum", base.DEC)
local F_MSGBODY = ProtoField.bytes("seer2msg_cleartext.seer2msgbody", "Message Body", base.SPACE)
SEER2MSG_CLEARTEXT_PROTO.fields = {
    F_LENGTH, 
    F_COMMAND_ID, 
    F_USER_ID, 
    F_SEQUENCE_INDEX, 
    F_STATUS_CODE, 
    F_CHECKSUM, 
    F_MSGBODY
}

-- Creating protocol SEER2MSG_CLEARTEXT_105_PROTO
SEER2MSG_CLEARTEXT_105_PROTO = Proto("seer2msg_cleartext_105", "Seer2 Message Client Cleartext 105")
local F_SESSION = ProtoField.bytes("seer2msg.session", "Session", base.SPACE)
local F_TMCID = ProtoField.uint16("seer2msg.tmcid", "TMCID", base.DEC)
SEER2MSG_CLEARTEXT_105_PROTO.fields = {
    F_SESSION,
    F_TMCID,
}

-- Creating protocol SEER2MSG_CLEARTEXT_106_PROTO
SEER2MSG_CLEARTEXT_106_PROTO = Proto("seer2msg_cleartext_106", "Seer2 Message Client Cleartext 106")
local F_106_START_SERVER_ID = ProtoField.uint16("seer2msg_cleartext.seer2msgbody_106_startServerId", "GetRangedServerList startServerId", base.DEC)
local F_106_END_SERVER_ID = ProtoField.uint16("seer2msg_cleartext.seer2msgbody_106_endServerId", "GetRangedServerList endServerId", base.DEC)
SEER2MSG_CLEARTEXT_106_PROTO.fields = {
    F_106_START_SERVER_ID,
    F_106_END_SERVER_ID
}

-- Creating protocol SEER2MSG_CLEARTEXT_SERVERINFO_PROTO
SEER2MSG_CLEARTEXT_SERVERINFO_PROTO = Proto("seer2msg_cleartext_serverInfo", "Seer2 Message Cleartext Server Info")
local F_SERVER_INFO_SERVER_ID = ProtoField.uint16("seer2msg_cleartext.server_id", "Server ID", base.DEC)
local F_SERVER_INFO_SERVER_IP = ProtoField.string("seer2msg_cleartext.server_ip", "Server IP")
local F_SERVER_INFO_SERVER_PORT = ProtoField.uint16("seer2msg_cleartext.server_port", "Server Port", base.DEC)
local F_SERVER_INFO_USER_COUNT = ProtoField.uint32("seer2msg_cleartext.user_count", "User Count", base.DEC)
local F_SERVER_INFO_FRIEND_COUNT = ProtoField.uint8("server_info.friend_count", "Friend Count", base.DEC)
local F_SERVER_INFO_IS_NEW_SVR = ProtoField.uint8("seer2msg_cleartext.is_new_svr", "Is New Server", base.DEC)
SEER2MSG_CLEARTEXT_SERVERINFO_PROTO.fields = {
    F_SERVER_INFO_SERVER_ID,
    F_SERVER_INFO_SERVER_IP,
    F_SERVER_INFO_SERVER_PORT,
    F_SERVER_INFO_USER_COUNT,
    F_SERVER_INFO_FRIEND_COUNT,
    F_SERVER_INFO_IS_NEW_SVR
}

local function seer2msg_dissector_clientmsg_103(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_clientmsg_111(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_clientmsg_105(buffer, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_105_PROTO, buffer(), "Seer2 Client Cleartext Request 105 Body Data")
    -- 解析字段值
    local range_session = buffer(0, 16)
    local range_tmcid = buffer(16, 4)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(F_SESSION, range_session)
    subtree:add_le(F_TMCID, range_tmcid)
end

-- GetRangedServerList
local function seer2msg_dissector_clientmsg_106(buffer, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_106_PROTO, buffer(), "Seer2 Client Cleartext Request 106 Body Data")
    -- 解析字段值
    local range_startServerId = buffer(0, 2)
    local range_endServerId = buffer(2, 2)

    -- 将字段添加到 Wireshark 界面中
    subtree:add_le(F_106_START_SERVER_ID, range_startServerId)
    subtree:add_le(F_106_END_SERVER_ID, range_endServerId)
end

local function seer2msg_dissector_clientmsg(buffer, pinfo, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_PROTO, buffer(), "Seer2 Client Cleartext Request Data")
    -- 解析字段值
    local range_length = buffer(0, 4)
    local range_commandId = buffer(4, 2)
    local range_userId = buffer(6, 4)
    local range_sequenceIndex = buffer(10, 4)
    local range_checksum = buffer(14, 4)
    local range_msgbody = buffer(18)
    local length = range_length:le_uint()
    local commandId = range_commandId:le_uint()
    local userId = range_userId:le_uint()
    local sequenceIndex = range_sequenceIndex:le_uint()
    local checksum = range_checksum:le_uint()

    -- 将字段添加到 Wireshark 界面中
    subtree:add(F_LENGTH, range_length, length)
    subtree:add(F_COMMAND_ID, range_commandId, commandId)
    subtree:add(F_USER_ID, range_userId, userId)
    subtree:add(F_SEQUENCE_INDEX, range_sequenceIndex, sequenceIndex)
    subtree:add(F_CHECKSUM, range_checksum, checksum)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Client Request(Cleartext)"
    pinfo.cols.info = string.format("Length: %d, Command ID: %d, User ID: %d, Sequence Index: %d, Checksum: %d",
        length, commandId, userId, sequenceIndex, checksum)
    
    -- 解析msgbody
    local body_subtree = subtree:add(F_MSGBODY, range_msgbody, "Seer2 Client Request Cleartext Body Data")
    if commandId == 103 then
        seer2msg_dissector_clientmsg_103(range_msgbody, subtree)
    elseif commandId == 111 then
        seer2msg_dissector_clientmsg_111(range_msgbody, subtree)
    elseif commandId == 105 then
        seer2msg_dissector_clientmsg_105(range_msgbody, subtree)
    elseif commandId == 106 then
        seer2msg_dissector_clientmsg_106(range_msgbody, subtree)
    end
end


local function seer2msg_dissector_servermsg_103(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_servermsg_111(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_servermsg_ServerInfo(buffer, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_SERVERINFO_PROTO, buffer(), "Server Info Protocol Data")

    subtree:add_le(F_SERVER_INFO_SERVER_ID, buffer(0, 2))
    subtree:add(F_SERVER_INFO_SERVER_IP, buffer(2, 15))
    subtree:add_le(F_SERVER_INFO_SERVER_PORT, buffer(18, 2))
    subtree:add_le(F_SERVER_INFO_USER_COUNT, buffer(20, 4))
    subtree:add(F_SERVER_INFO_FRIEND_COUNT, buffer(24, 1))
    subtree:add(F_SERVER_INFO_IS_NEW_SVR, buffer(25, 1))
end

local function seer2msg_dissector_servermsg_OnlineServerListInfo(buffer, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_SERVERINFO_PROTO, buffer:range(4), "Seer2 Online Server List Protocol Data")
    -- 解析字段值
    local recommendedServerCount = buffer(0, 4):le_int()
    local i = 0
    local offset = 4
    while i < recommendedServerCount do
        seer2msg_dissector_servermsg_ServerInfo(buffer:range(offset, 26), subtree)
        offset = offset + 26
        i = i + 1
    end
end

local function seer2msg_dissector_servermsg_105(buffer, tree)
    local serverTotalCount = buffer(0, 4):le_uint()
    seer2msg_dissector_servermsg_OnlineServerListInfo(buffer:range(4), tree)
end

-- GetRangedServerList
local function seer2msg_dissector_servermsg_106(buffer, tree)
    seer2msg_dissector_servermsg_OnlineServerListInfo(buffer, tree)
end


local function seer2msg_dissector_servermsg(buffer, pinfo, tree)
    local subtree = tree:add(SEER2MSG_CLEARTEXT_PROTO, buffer(), "Seer2 Server Response Cleartext Data")
    -- 解析字段值
    local range_length = buffer(0, 4)
    local range_commandId = buffer(4, 2)
    local range_userId = buffer(6, 4)
    local range_sequenceIndex = buffer(10, 4)
    local range_statusCode = buffer(14, 4)
    local range_msgbody = buffer(18)
    local length = range_length:le_uint()
    local commandId = range_commandId:le_uint()
    local userId = range_userId:le_uint()
    local sequenceIndex = range_sequenceIndex:le_uint()
    local statusCode = range_statusCode:le_uint()

    -- 将字段添加到 Wireshark 界面中
    subtree:add(F_LENGTH, range_length, length)
    subtree:add(F_COMMAND_ID, range_commandId, commandId)
    subtree:add(F_USER_ID, range_userId, userId)
    subtree:add(F_SEQUENCE_INDEX, range_sequenceIndex, sequenceIndex)
    subtree:add(F_STATUS_CODE, range_statusCode, statusCode)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Server Response(Cleartext)"
    pinfo.cols.info = string.format("Length: %d, Command ID: %d, User ID: %d, Sequence Index: %d, Status Code: %d",
        length, commandId, userId, sequenceIndex, statusCode)

    -- 解析msgbody
    local body_subtree = subtree:add(F_MSGBODY, range_msgbody, "Seer2 Server Response Cleartext Body Data")
    if commandId == 103 then
        seer2msg_dissector_servermsg_103(range_msgbody, body_subtree)
    elseif commandId == 111 then
        seer2msg_dissector_servermsg_111(range_msgbody, body_subtree)
    elseif commandId == 105 then
        seer2msg_dissector_servermsg_105(range_msgbody, body_subtree)
    elseif commandId == 106 then
        seer2msg_dissector_servermsg_106(range_msgbody, body_subtree)
    end
end

-- 解析 TCP payload
function SEER2MSG_CLEARTEXT_PROTO.dissector(buffer, pinfo, tree)
    -- 检查源端口和目的端口并筛选掉我们不需要解析的包
    if pinfo.src_port ~= 1863 and pinfo.dst_port ~= 1863 then
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

        -- 分发处理消息（服务器消息）
        if pinfo.src_port == 1863 then
            seer2msg_dissector_servermsg(buffer:range(offset, msglen), pinfo, tree)
        end

        -- 分发处理消息（客户端消息）
        if pinfo.dst_port == 1863 then
            seer2msg_dissector_clientmsg(buffer:range(offset, msglen), pinfo, tree)
        end

        offset = offset + msglen
    end

end

-- 将协议绑定到 TCP 端口
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGINSERVER_PORT, SEER2MSG_CLEARTEXT_PROTO)
