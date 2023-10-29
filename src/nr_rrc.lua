
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_bcch_bch_dissector = Dissector.get("nr-rrc.bcch.bch")

-- 解析函数
function parse_nr_rrc_bcch_bch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_bcch_bch_tree = tree:add(nr_rrc_bcch_bch_dissector, buffer(), "nr_rrc_bcch_bch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_bcch_bch_dissector:call(buffer, pinfo, nr_rrc_bcch_bch_tree)
end

-- 创建一个新的协议
local nr_rrc_bcch_bch_protocol = Proto("NR_RRC_BCCH_BCH", "NR_RRC_BCCH_BCH")

-- 将解析函数注册到协议
nr_rrc_bcch_bch_protocol.dissector = parse_nr_rrc_bcch_bch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, nr_rrc_bcch_bch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_cellgroupconfig_msg_dissector = Dissector.get("nr-rrc.cellgroupconfig_msg")

-- 解析函数
function parse_nr_rrc_cellgroupconfig_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_cellgroupconfig_msg_tree = tree:add(nr_rrc_cellgroupconfig_msg_dissector, buffer(), "nr_rrc_cellgroupconfig_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_cellgroupconfig_msg_dissector:call(buffer, pinfo, nr_rrc_cellgroupconfig_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_cellgroupconfig_msg_protocol = Proto("NR_RRC_CELLGROUPCONFIG_MSG", "NR_RRC_CELLGROUPCONFIG_MSG")

-- 将解析函数注册到协议
nr_rrc_cellgroupconfig_msg_protocol.dissector = parse_nr_rrc_cellgroupconfig_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10002, nr_rrc_cellgroupconfig_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_cg_configinfo_dissector = Dissector.get("nr-rrc.cg_configinfo")

-- 解析函数
function parse_nr_rrc_cg_configinfo_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_cg_configinfo_tree = tree:add(nr_rrc_cg_configinfo_dissector, buffer(), "nr_rrc_cg_configinfo")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_cg_configinfo_dissector:call(buffer, pinfo, nr_rrc_cg_configinfo_tree)
end

-- 创建一个新的协议
local nr_rrc_cg_configinfo_protocol = Proto("NR_RRC_CG_CONFIGINFO", "NR_RRC_CG_CONFIGINFO")

-- 将解析函数注册到协议
nr_rrc_cg_configinfo_protocol.dissector = parse_nr_rrc_cg_configinfo_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10003, nr_rrc_cg_configinfo_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_dl_ccch_dissector = Dissector.get("nr-rrc.dl.ccch")

-- 解析函数
function parse_nr_rrc_dl_ccch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_dl_ccch_tree = tree:add(nr_rrc_dl_ccch_dissector, buffer(), "nr_rrc_dl_ccch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_dl_ccch_dissector:call(buffer, pinfo, nr_rrc_dl_ccch_tree)
end

-- 创建一个新的协议
local nr_rrc_dl_ccch_protocol = Proto("NR_RRC_DL_CCCH", "NR_RRC_DL_CCCH")

-- 将解析函数注册到协议
nr_rrc_dl_ccch_protocol.dissector = parse_nr_rrc_dl_ccch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10004, nr_rrc_dl_ccch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_bcch_dl_sch_dissector = Dissector.get("nr-rrc.bcch.dl.sch")

-- 解析函数
function parse_nr_rrc_bcch_dl_sch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_bcch_dl_sch_tree = tree:add(nr_rrc_bcch_dl_sch_dissector, buffer(), "nr_rrc_bcch_dl_sch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_bcch_dl_sch_dissector:call(buffer, pinfo, nr_rrc_bcch_dl_sch_tree)
end

-- 创建一个新的协议
local nr_rrc_bcch_dl_sch_protocol = Proto("NR_RRC_BCCH_DL_SCH", "NR_RRC_BCCH_DL_SCH")

-- 将解析函数注册到协议
nr_rrc_bcch_dl_sch_protocol.dissector = parse_nr_rrc_bcch_dl_sch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10001, nr_rrc_bcch_dl_sch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_dl_ccch_msg_msg_dissector = Dissector.get("nr-rrc.dl.ccch_msg_msg")

-- 解析函数
function parse_nr_rrc_dl_ccch_msg_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_dl_ccch_msg_msg_tree = tree:add(nr_rrc_dl_ccch_msg_msg_dissector, buffer(), "nr_rrc_dl_ccch_msg_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_dl_ccch_msg_msg_dissector:call(buffer, pinfo, nr_rrc_dl_ccch_msg_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_dl_ccch_msg_msg_protocol = Proto("NR_RRC_DL_CCCH_MSG_MSG", "NR_RRC_DL_CCCH_MSG_MSG")

-- 将解析函数注册到协议
nr_rrc_dl_ccch_msg_msg_protocol.dissector = parse_nr_rrc_dl_ccch_msg_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10005, nr_rrc_dl_ccch_msg_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_dl_dcch_dissector = Dissector.get("nr-rrc.dl.dcch")

-- 解析函数
function parse_nr_rrc_dl_dcch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_dl_dcch_tree = tree:add(nr_rrc_dl_dcch_dissector, buffer(), "nr_rrc_dl_dcch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_dl_dcch_dissector:call(buffer, pinfo, nr_rrc_dl_dcch_tree)
end

-- 创建一个新的协议
local nr_rrc_dl_dcch_protocol = Proto("NR_RRC_DL_DCCH", "NR_RRC_DL_DCCH")

-- 将解析函数注册到协议
nr_rrc_dl_dcch_protocol.dissector = parse_nr_rrc_dl_dcch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10006, nr_rrc_dl_dcch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_dl_dcch_msg_msg_dissector = Dissector.get("nr-rrc.dl.dcch_msg_msg")

-- 解析函数
function parse_nr_rrc_dl_dcch_msg_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_dl_dcch_msg_msg_tree = tree:add(nr_rrc_dl_dcch_msg_msg_dissector, buffer(), "nr_rrc_dl_dcch_msg_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_dl_dcch_msg_msg_dissector:call(buffer, pinfo, nr_rrc_dl_dcch_msg_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_dl_dcch_msg_msg_protocol = Proto("NR_RRC_DL_DCCH_MSG_MSG", "NR_RRC_DL_DCCH_MSG_MSG")

-- 将解析函数注册到协议
nr_rrc_dl_dcch_msg_msg_protocol.dissector = parse_nr_rrc_dl_dcch_msg_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10007, nr_rrc_dl_dcch_msg_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_handoverpreparationinformation_msg_dissector = Dissector.get("nr-rrc.handoverpreparationinformation_msg")

-- 解析函数
function parse_nr_rrc_handoverpreparationinformation_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_handoverpreparationinformation_msg_tree = tree:add(nr_rrc_handoverpreparationinformation_msg_dissector, buffer(), "nr_rrc_handoverpreparationinformation_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_handoverpreparationinformation_msg_dissector:call(buffer, pinfo, nr_rrc_handoverpreparationinformation_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_handoverpreparationinformation_msg_protocol = Proto("NR_RRC_HANDOVERPREPARATIONINFORMATION_MSG", "NR_RRC_HANDOVERPREPARATIONINFORMATION_MSG")

-- 将解析函数注册到协议
nr_rrc_handoverpreparationinformation_msg_protocol.dissector = parse_nr_rrc_handoverpreparationinformation_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10009, nr_rrc_handoverpreparationinformation_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_mcch_dissector = Dissector.get("nr-rrc.mcch")

-- 解析函数
function parse_nr_rrc_mcch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_mcch_tree = tree:add(nr_rrc_mcch_dissector, buffer(), "nr_rrc_mcch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_mcch_dissector:call(buffer, pinfo, nr_rrc_mcch_tree)
end

-- 创建一个新的协议
local nr_rrc_mcch_protocol = Proto("NR_RRC_MCCH", "NR_RRC_MCCH")

-- 将解析函数注册到协议
nr_rrc_mcch_protocol.dissector = parse_nr_rrc_mcch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10010, nr_rrc_mcch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_handovercommand_msg_dissector = Dissector.get("nr-rrc.handovercommand_msg")

-- 解析函数
function parse_nr_rrc_handovercommand_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_handovercommand_msg_tree = tree:add(nr_rrc_handovercommand_msg_dissector, buffer(), "nr_rrc_handovercommand_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_handovercommand_msg_dissector:call(buffer, pinfo, nr_rrc_handovercommand_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_handovercommand_msg_protocol = Proto("NR_RRC_HANDOVERCOMMAND_MSG", "NR_RRC_HANDOVERCOMMAND_MSG")

-- 将解析函数注册到协议
nr_rrc_handovercommand_msg_protocol.dissector = parse_nr_rrc_handovercommand_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10008, nr_rrc_handovercommand_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_measgapconfig_msg_dissector = Dissector.get("nr-rrc.measgapconfig_msg")

-- 解析函数
function parse_nr_rrc_measgapconfig_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_measgapconfig_msg_tree = tree:add(nr_rrc_measgapconfig_msg_dissector, buffer(), "nr_rrc_measgapconfig_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_measgapconfig_msg_dissector:call(buffer, pinfo, nr_rrc_measgapconfig_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_measgapconfig_msg_protocol = Proto("NR_RRC_MEASGAPCONFIG_MSG", "NR_RRC_MEASGAPCONFIG_MSG")

-- 将解析函数注册到协议
nr_rrc_measgapconfig_msg_protocol.dissector = parse_nr_rrc_measgapconfig_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10012, nr_rrc_measgapconfig_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_pcch_dissector = Dissector.get("nr-rrc.pcch")

-- 解析函数
function parse_nr_rrc_pcch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_pcch_tree = tree:add(nr_rrc_pcch_dissector, buffer(), "nr_rrc_pcch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_pcch_dissector:call(buffer, pinfo, nr_rrc_pcch_tree)
end

-- 创建一个新的协议
local nr_rrc_pcch_protocol = Proto("NR_RRC_PCCH", "NR_RRC_PCCH")

-- 将解析函数注册到协议
nr_rrc_pcch_protocol.dissector = parse_nr_rrc_pcch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10013, nr_rrc_pcch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_rrc_reconf_dissector = Dissector.get("nr-rrc.rrc_reconf")

-- 解析函数
function parse_nr_rrc_rrc_reconf_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_rrc_reconf_tree = tree:add(nr_rrc_rrc_reconf_dissector, buffer(), "nr_rrc_rrc_reconf")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_rrc_reconf_dissector:call(buffer, pinfo, nr_rrc_rrc_reconf_tree)
end

-- 创建一个新的协议
local nr_rrc_rrc_reconf_protocol = Proto("NR_RRC_RRC_RECONF", "NR_RRC_RRC_RECONF")

-- 将解析函数注册到协议
nr_rrc_rrc_reconf_protocol.dissector = parse_nr_rrc_rrc_reconf_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10015, nr_rrc_rrc_reconf_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_radiobearerconfig_dissector = Dissector.get("nr-rrc.radiobearerconfig")

-- 解析函数
function parse_nr_rrc_radiobearerconfig_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_radiobearerconfig_tree = tree:add(nr_rrc_radiobearerconfig_dissector, buffer(), "nr_rrc_radiobearerconfig")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_radiobearerconfig_dissector:call(buffer, pinfo, nr_rrc_radiobearerconfig_tree)
end

-- 创建一个新的协议
local nr_rrc_radiobearerconfig_protocol = Proto("NR_RRC_RADIOBEARERCONFIG", "NR_RRC_RADIOBEARERCONFIG")

-- 将解析函数注册到协议
nr_rrc_radiobearerconfig_protocol.dissector = parse_nr_rrc_radiobearerconfig_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10014, nr_rrc_radiobearerconfig_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_rrc_reconf_msg_dissector = Dissector.get("nr-rrc.rrc_reconf_msg")

-- 解析函数
function parse_nr_rrc_rrc_reconf_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_rrc_reconf_msg_tree = tree:add(nr_rrc_rrc_reconf_msg_dissector, buffer(), "nr_rrc_rrc_reconf_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_rrc_reconf_msg_dissector:call(buffer, pinfo, nr_rrc_rrc_reconf_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_rrc_reconf_msg_protocol = Proto("NR_RRC_RRC_RECONF_MSG", "NR_RRC_RRC_RECONF_MSG")

-- 将解析函数注册到协议
nr_rrc_rrc_reconf_msg_protocol.dissector = parse_nr_rrc_rrc_reconf_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10016, nr_rrc_rrc_reconf_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_measconfig_msg_dissector = Dissector.get("nr-rrc.measconfig_msg")

-- 解析函数
function parse_nr_rrc_measconfig_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_measconfig_msg_tree = tree:add(nr_rrc_measconfig_msg_dissector, buffer(), "nr_rrc_measconfig_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_measconfig_msg_dissector:call(buffer, pinfo, nr_rrc_measconfig_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_measconfig_msg_protocol = Proto("NR_RRC_MEASCONFIG_MSG", "NR_RRC_MEASCONFIG_MSG")

-- 将解析函数注册到协议
nr_rrc_measconfig_msg_protocol.dissector = parse_nr_rrc_measconfig_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10011, nr_rrc_measconfig_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_capabilityrat_containerlist_dissector = Dissector.get("nr-rrc.ue_capabilityrat_containerlist")

-- 解析函数
function parse_nr_rrc_ue_capabilityrat_containerlist_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_capabilityrat_containerlist_tree = tree:add(nr_rrc_ue_capabilityrat_containerlist_dissector, buffer(), "nr_rrc_ue_capabilityrat_containerlist")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_capabilityrat_containerlist_dissector:call(buffer, pinfo, nr_rrc_ue_capabilityrat_containerlist_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_capabilityrat_containerlist_protocol = Proto("NR_RRC_UE_CAPABILITYRAT_CONTAINERLIST", "NR_RRC_UE_CAPABILITYRAT_CONTAINERLIST")

-- 将解析函数注册到协议
nr_rrc_ue_capabilityrat_containerlist_protocol.dissector = parse_nr_rrc_ue_capabilityrat_containerlist_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10019, nr_rrc_ue_capabilityrat_containerlist_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_scch_dissector = Dissector.get("nr-rrc.scch")

-- 解析函数
function parse_nr_rrc_scch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_scch_tree = tree:add(nr_rrc_scch_dissector, buffer(), "nr_rrc_scch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_scch_dissector:call(buffer, pinfo, nr_rrc_scch_tree)
end

-- 创建一个新的协议
local nr_rrc_scch_protocol = Proto("NR_RRC_SCCH", "NR_RRC_SCCH")

-- 将解析函数注册到协议
nr_rrc_scch_protocol.dissector = parse_nr_rrc_scch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10018, nr_rrc_scch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_sbcch_sl_bch_dissector = Dissector.get("nr-rrc.sbcch.sl.bch")

-- 解析函数
function parse_nr_rrc_sbcch_sl_bch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_sbcch_sl_bch_tree = tree:add(nr_rrc_sbcch_sl_bch_dissector, buffer(), "nr_rrc_sbcch_sl_bch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_sbcch_sl_bch_dissector:call(buffer, pinfo, nr_rrc_sbcch_sl_bch_tree)
end

-- 创建一个新的协议
local nr_rrc_sbcch_sl_bch_protocol = Proto("NR_RRC_SBCCH_SL_BCH", "NR_RRC_SBCCH_SL_BCH")

-- 将解析函数注册到协议
nr_rrc_sbcch_sl_bch_protocol.dissector = parse_nr_rrc_sbcch_sl_bch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10017, nr_rrc_sbcch_sl_bch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_nr_cap_dissector = Dissector.get("nr-rrc.ue_nr_cap")

-- 解析函数
function parse_nr_rrc_ue_nr_cap_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_nr_cap_tree = tree:add(nr_rrc_ue_nr_cap_dissector, buffer(), "nr_rrc_ue_nr_cap")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_nr_cap_dissector:call(buffer, pinfo, nr_rrc_ue_nr_cap_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_nr_cap_protocol = Proto("NR_RRC_UE_NR_CAP", "NR_RRC_UE_NR_CAP")

-- 将解析函数注册到协议
nr_rrc_ue_nr_cap_protocol.dissector = parse_nr_rrc_ue_nr_cap_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10022, nr_rrc_ue_nr_cap_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_mrdc_cap_dissector = Dissector.get("nr-rrc.ue_mrdc_cap")

-- 解析函数
function parse_nr_rrc_ue_mrdc_cap_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_mrdc_cap_tree = tree:add(nr_rrc_ue_mrdc_cap_dissector, buffer(), "nr_rrc_ue_mrdc_cap")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_mrdc_cap_dissector:call(buffer, pinfo, nr_rrc_ue_mrdc_cap_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_mrdc_cap_protocol = Proto("NR_RRC_UE_MRDC_CAP", "NR_RRC_UE_MRDC_CAP")

-- 将解析函数注册到协议
nr_rrc_ue_mrdc_cap_protocol.dissector = parse_nr_rrc_ue_mrdc_cap_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10020, nr_rrc_ue_mrdc_cap_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_mrdc_cap_msg_dissector = Dissector.get("nr-rrc.ue_mrdc_cap_msg")

-- 解析函数
function parse_nr_rrc_ue_mrdc_cap_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_mrdc_cap_msg_tree = tree:add(nr_rrc_ue_mrdc_cap_msg_dissector, buffer(), "nr_rrc_ue_mrdc_cap_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_mrdc_cap_msg_dissector:call(buffer, pinfo, nr_rrc_ue_mrdc_cap_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_mrdc_cap_msg_protocol = Proto("NR_RRC_UE_MRDC_CAP_MSG", "NR_RRC_UE_MRDC_CAP_MSG")

-- 将解析函数注册到协议
nr_rrc_ue_mrdc_cap_msg_protocol.dissector = parse_nr_rrc_ue_mrdc_cap_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10021, nr_rrc_ue_mrdc_cap_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_radio_access_cap_info_msg_dissector = Dissector.get("nr-rrc.ue_radio_access_cap_info_msg")

-- 解析函数
function parse_nr_rrc_ue_radio_access_cap_info_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_radio_access_cap_info_msg_tree = tree:add(nr_rrc_ue_radio_access_cap_info_msg_dissector, buffer(), "nr_rrc_ue_radio_access_cap_info_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_radio_access_cap_info_msg_dissector:call(buffer, pinfo, nr_rrc_ue_radio_access_cap_info_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_radio_access_cap_info_msg_protocol = Proto("NR_RRC_UE_RADIO_ACCESS_CAP_INFO_MSG", "NR_RRC_UE_RADIO_ACCESS_CAP_INFO_MSG")

-- 将解析函数注册到协议
nr_rrc_ue_radio_access_cap_info_msg_protocol.dissector = parse_nr_rrc_ue_radio_access_cap_info_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10025, nr_rrc_ue_radio_access_cap_info_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_radio_paging_info_dissector = Dissector.get("nr-rrc.ue_radio_paging_info")

-- 解析函数
function parse_nr_rrc_ue_radio_paging_info_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_radio_paging_info_tree = tree:add(nr_rrc_ue_radio_paging_info_dissector, buffer(), "nr_rrc_ue_radio_paging_info")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_radio_paging_info_dissector:call(buffer, pinfo, nr_rrc_ue_radio_paging_info_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_radio_paging_info_protocol = Proto("NR_RRC_UE_RADIO_PAGING_INFO", "NR_RRC_UE_RADIO_PAGING_INFO")

-- 将解析函数注册到协议
nr_rrc_ue_radio_paging_info_protocol.dissector = parse_nr_rrc_ue_radio_paging_info_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10026, nr_rrc_ue_radio_paging_info_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_radio_access_cap_info_dissector = Dissector.get("nr-rrc.ue_radio_access_cap_info")

-- 解析函数
function parse_nr_rrc_ue_radio_access_cap_info_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_radio_access_cap_info_tree = tree:add(nr_rrc_ue_radio_access_cap_info_dissector, buffer(), "nr_rrc_ue_radio_access_cap_info")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_radio_access_cap_info_dissector:call(buffer, pinfo, nr_rrc_ue_radio_access_cap_info_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_radio_access_cap_info_protocol = Proto("NR_RRC_UE_RADIO_ACCESS_CAP_INFO", "NR_RRC_UE_RADIO_ACCESS_CAP_INFO")

-- 将解析函数注册到协议
nr_rrc_ue_radio_access_cap_info_protocol.dissector = parse_nr_rrc_ue_radio_access_cap_info_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10024, nr_rrc_ue_radio_access_cap_info_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ul_ccch_dissector = Dissector.get("nr-rrc.ul.ccch")

-- 解析函数
function parse_nr_rrc_ul_ccch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ul_ccch_tree = tree:add(nr_rrc_ul_ccch_dissector, buffer(), "nr_rrc_ul_ccch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ul_ccch_dissector:call(buffer, pinfo, nr_rrc_ul_ccch_tree)
end

-- 创建一个新的协议
local nr_rrc_ul_ccch_protocol = Proto("NR_RRC_UL_CCCH", "NR_RRC_UL_CCCH")

-- 将解析函数注册到协议
nr_rrc_ul_ccch_protocol.dissector = parse_nr_rrc_ul_ccch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10027, nr_rrc_ul_ccch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ue_nr_cap_msg_dissector = Dissector.get("nr-rrc.ue_nr_cap_msg")

-- 解析函数
function parse_nr_rrc_ue_nr_cap_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ue_nr_cap_msg_tree = tree:add(nr_rrc_ue_nr_cap_msg_dissector, buffer(), "nr_rrc_ue_nr_cap_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ue_nr_cap_msg_dissector:call(buffer, pinfo, nr_rrc_ue_nr_cap_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_ue_nr_cap_msg_protocol = Proto("NR_RRC_UE_NR_CAP_MSG", "NR_RRC_UE_NR_CAP_MSG")

-- 将解析函数注册到协议
nr_rrc_ue_nr_cap_msg_protocol.dissector = parse_nr_rrc_ue_nr_cap_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10023, nr_rrc_ue_nr_cap_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ul_ccch1_dissector = Dissector.get("nr-rrc.ul.ccch1")

-- 解析函数
function parse_nr_rrc_ul_ccch1_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ul_ccch1_tree = tree:add(nr_rrc_ul_ccch1_dissector, buffer(), "nr_rrc_ul_ccch1")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ul_ccch1_dissector:call(buffer, pinfo, nr_rrc_ul_ccch1_tree)
end

-- 创建一个新的协议
local nr_rrc_ul_ccch1_protocol = Proto("NR_RRC_UL_CCCH1", "NR_RRC_UL_CCCH1")

-- 将解析函数注册到协议
nr_rrc_ul_ccch1_protocol.dissector = parse_nr_rrc_ul_ccch1_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10028, nr_rrc_ul_ccch1_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ul_ccch_msg_msg_dissector = Dissector.get("nr-rrc.ul.ccch_msg_msg")

-- 解析函数
function parse_nr_rrc_ul_ccch_msg_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ul_ccch_msg_msg_tree = tree:add(nr_rrc_ul_ccch_msg_msg_dissector, buffer(), "nr_rrc_ul_ccch_msg_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ul_ccch_msg_msg_dissector:call(buffer, pinfo, nr_rrc_ul_ccch_msg_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_ul_ccch_msg_msg_protocol = Proto("NR_RRC_UL_CCCH_MSG_MSG", "NR_RRC_UL_CCCH_MSG_MSG")

-- 将解析函数注册到协议
nr_rrc_ul_ccch_msg_msg_protocol.dissector = parse_nr_rrc_ul_ccch_msg_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10029, nr_rrc_ul_ccch_msg_msg_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ul_dcch_dissector = Dissector.get("nr-rrc.ul.dcch")

-- 解析函数
function parse_nr_rrc_ul_dcch_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ul_dcch_tree = tree:add(nr_rrc_ul_dcch_dissector, buffer(), "nr_rrc_ul_dcch")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ul_dcch_dissector:call(buffer, pinfo, nr_rrc_ul_dcch_tree)
end

-- 创建一个新的协议
local nr_rrc_ul_dcch_protocol = Proto("NR_RRC_UL_DCCH", "NR_RRC_UL_DCCH")

-- 将解析函数注册到协议
nr_rrc_ul_dcch_protocol.dissector = parse_nr_rrc_ul_dcch_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10030, nr_rrc_ul_dcch_protocol)
                
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_rrc_ul_dcch_msg_msg_dissector = Dissector.get("nr-rrc.ul.dcch_msg_msg")

-- 解析函数
function parse_nr_rrc_ul_dcch_msg_msg_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_rrc_ul_dcch_msg_msg_tree = tree:add(nr_rrc_ul_dcch_msg_msg_dissector, buffer(), "nr_rrc_ul_dcch_msg_msg")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_rrc_ul_dcch_msg_msg_dissector:call(buffer, pinfo, nr_rrc_ul_dcch_msg_msg_tree)
end

-- 创建一个新的协议
local nr_rrc_ul_dcch_msg_msg_protocol = Proto("NR_RRC_UL_DCCH_MSG_MSG", "NR_RRC_UL_DCCH_MSG_MSG")

-- 将解析函数注册到协议
nr_rrc_ul_dcch_msg_msg_protocol.dissector = parse_nr_rrc_ul_dcch_msg_msg_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10031, nr_rrc_ul_dcch_msg_msg_protocol)
                