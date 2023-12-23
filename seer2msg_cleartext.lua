-- wireshark_seer2msg_cleartext.lua

-- 创建协议
seer2msg_cleartext_proto = Proto("seer2msg_cleartext", "Seer2 Message Cleartext")
local f_length = ProtoField.uint32("seer2msg_cleartext.length", "Length", base.DEC, nil, nil, "little-endian")
local f_commandId = ProtoField.uint16("seer2msg_cleartext.commandId", "Command ID", base.DEC, nil, nil, "little-endian")
local f_userId = ProtoField.uint32("seer2msg_cleartext.userId", "User ID", base.DEC, nil, nil, "little-endian")
local f_sequenceIndex = ProtoField.uint32("seer2msg_cleartext.sequenceIndex", "Sequence Index", base.DEC, nil, nil, "little-endian")
local f_statusCode = ProtoField.uint32("seer2_clientmsg_cleartext.statusCode", "Status Code", base.DEC, nil, nil, "little-endian")
local f_checksum = ProtoField.uint32("seer2msg_cleartext.checksum", "Checksum", base.DEC, nil, nil, "little-endian")
local f_seer2msgbody = ProtoField.bytes("seer2msg_cleartext.seer2msgbody", "Seer2 Message Body", base.SPACE)
seer2msg_cleartext_proto.fields = {
    f_length, 
    f_commandId, 
    f_userId, 
    f_sequenceIndex, 
    f_statusCode, 
    f_checksum, 
    f_seer2msgbody
}

seer2msg_cleartext_105_proto = Proto("seer2msg_cleartext_105", "Seer2 Message Client Cleartext 105")
local f_session = ProtoField.bytes("seer2msg.session", "Session", base.SPACE)
local f_tmcid = ProtoField.uint16("seer2msg.tmcid", "TMCID", base.DEC, nil, nil, "little-endian")
seer2msg_cleartext_105_proto.fields = {
    f_session,
    f_tmcid,
}

seer2msg_cleartext_106_proto = Proto("seer2msg_cleartext_106", "Seer2 Message Client Cleartext 106")
local f_106_startServerId = ProtoField.uint16("seer2msg_cleartext.seer2msgbody_106_startServerId", "GetRangedServerList startServerId", base.DEC, nil, nil, "little-endian")
local f_106_endServerId = ProtoField.uint16("seer2msg_cleartext.seer2msgbody_106_endServerId", "GetRangedServerList endServerId", base.DEC, nil, nil, "little-endian")
seer2msg_cleartext_106_proto.fields = {
    f_106_startServerId,
    f_106_endServerId
}

seer2msg_cleartext_serverInfo_proto = Proto("seer2msg_cleartext_serverInfo", "Seer2 Message Cleartext Server Info")
local f_serverInfo_server_id = ProtoField.uint16("seer2msg_cleartext.server_id", "Server ID", base.DEC)
local f_serverInfo_server_ip = ProtoField.string("seer2msg_cleartext.server_ip", "Server IP")
local f_serverInfo_server_port = ProtoField.uint16("seer2msg_cleartext.server_port", "Server Port", base.DEC)
local f_serverInfo_user_count = ProtoField.uint32("seer2msg_cleartext.user_count", "User Count", base.DEC)
local f_serverInfo_friend_count = ProtoField.uint8("server_info.friend_count", "Friend Count", base.DEC)
local f_serverInfo_is_new_svr = ProtoField.uint8("seer2msg_cleartext.is_new_svr", "Is New Server", base.DEC)
seer2msg_cleartext_serverInfo_proto.fields = {
    f_serverInfo_server_id,
    f_serverInfo_server_ip,
    f_serverInfo_server_port,
    f_serverInfo_user_count,
    f_serverInfo_friend_count,
    f_serverInfo_is_new_svr
}

local function seer2msg_dissector_clientmsg_103(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_clientmsg_111(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_clientmsg_105(buffer, tree)
    local subtree = tree:add(seer2msg_cleartext_106_proto, buffer(), "Seer2 Client Cleartext Request 105 Body Data")
    -- 解析字段值
    local session = buffer(0, 16)
    local tmcid = buffer(16, 4):le_int()

    -- 将字段添加到 Wireshark 界面中
    subtree:add(f_session, session)
    subtree:add(f_tmcid, tmcid)
end

-- GetRangedServerList
local function seer2msg_dissector_clientmsg_106(buffer, tree)
    local subtree = tree:add(seer2msg_cleartext_106_proto, buffer(), "Seer2 Client Cleartext Request 106 Body Data")
    -- 解析字段值
    local startServerId = buffer(0, 2):le_uint()
    local endServerId = buffer(2, 2):le_uint()

    -- 将字段添加到 Wireshark 界面中
    subtree:add(f_106_startServerId, startServerId)
    subtree:add(f_106_endServerId, endServerId)
end

local function seer2msg_dissector_clientmsg(buffer, pinfo, tree)
    local subtree = tree:add(seer2msg_cleartext_proto, buffer(), "Seer2 Client Cleartext Request Data")
    -- 解析字段值
    local length = buffer(0, 4):le_uint()
    local commandId = buffer(4, 2):le_uint()
    local userId = buffer(6, 4):le_uint()
    local sequenceIndex = buffer(10, 4):le_uint()
    local checksum = buffer(14, 4):le_uint()
    local seer2msgbody = buffer(18)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(f_length, length)
    subtree:add(f_commandId, commandId)
    subtree:add(f_userId, userId)
    subtree:add(f_sequenceIndex, sequenceIndex)
    subtree:add(f_checksum, checksum)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Client Request(Cleartext)"
    pinfo.cols.info = string.format("Length: %d, Command ID: %d, User ID: %d, Sequence Index: %d, Checksum: %d",
        length, commandId, userId, sequenceIndex, checksum)
    
    -- 解析msgbody
    local body_subtree = subtree:add(f_seer2msgbody, seer2msgbody, "Seer2 Client Request Cleartext Body Data")
    if commandId == 103 then
        seer2msg_dissector_clientmsg_103(seer2msgbody, subtree)
    elseif commandId == 111 then
        seer2msg_dissector_clientmsg_111(seer2msgbody, subtree)
    elseif commandId == 105 then
        seer2msg_dissector_clientmsg_105(seer2msgbody, subtree)
    elseif commandId == 106 then
        seer2msg_dissector_clientmsg_106(seer2msgbody, subtree)
    end
end


local function seer2msg_dissector_servermsg_103(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_servermsg_111(buffer, tree)
    -- Todo
end

local function seer2msg_dissector_servermsg_ServerInfo(buffer, tree)
    local subtree = tree:add(seer2msg_cleartext_serverInfo_proto, buffer(), "Server Info Protocol Data")

    subtree:add_le(f_serverInfo_server_id, buffer(0, 2))
    subtree:add(f_serverInfo_server_ip, buffer(2, 15))
    subtree:add_le(f_serverInfo_server_port, buffer(18, 2))
    subtree:add_le(f_serverInfo_user_count, buffer(20, 4))
    subtree:add(f_serverInfo_friend_count, buffer(24, 1))
    subtree:add(f_serverInfo_is_new_svr, buffer(25, 1))
end

local function seer2msg_dissector_servermsg_OnlineServerListInfo(buffer, tree)
    local subtree = tree:add(seer2msg_cleartext_serverInfo_proto, buffer:range(4), "Seer2 Online Server List Protocol Data")
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
    local subtree = tree:add(seer2msg_cleartext_proto, buffer(), "Seer2 Server Response Cleartext Data")
    -- 解析字段值
    local length = buffer(0, 4):le_uint()
    local commandId = buffer(4, 2):le_uint()
    local userId = buffer(6, 4):le_uint()
    local sequenceIndex = buffer(10, 4):le_uint()
    local statusCode = buffer(14, 4):le_uint()
    local seer2msgbody = buffer(18)

    -- 将字段添加到 Wireshark 界面中
    subtree:add(f_length, length)
    subtree:add(f_commandId, commandId)
    subtree:add(f_userId, userId)
    subtree:add(f_sequenceIndex, sequenceIndex)
    subtree:add(f_statusCode, statusCode)

    -- 显示解析的信息
    pinfo.cols.protocol = "Seer2 Server Response(Cleartext)"
    pinfo.cols.info = string.format("Length: %d, Command ID: %d, User ID: %d, Sequence Index: %d, Status Code: %d",
        length, commandId, userId, sequenceIndex, statusCode)

    -- 解析msgbody
    local body_subtree = subtree:add(f_seer2msgbody, seer2msgbody, "Seer2 Server Response Cleartext Body Data")
    if commandId == 103 then
        seer2msg_dissector_servermsg_103(seer2msgbody, body_subtree)
    elseif commandId == 111 then
        seer2msg_dissector_servermsg_111(seer2msgbody, body_subtree)
    elseif commandId == 105 then
        seer2msg_dissector_servermsg_105(seer2msgbody, body_subtree)
    elseif commandId == 106 then
        seer2msg_dissector_servermsg_106(seer2msgbody, body_subtree)
    end
end

-- 解析 TCP payload
function seer2msg_cleartext_proto.dissector(buffer, pinfo, tree)
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
tcp_port:add(1863, seer2msg_cleartext_proto)
