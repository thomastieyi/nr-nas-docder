-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local nr_mac_dissector = Dissector.get("mac-nr")

-- 解析函数
function parse_nr_mac_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local nr_mac_tree = tree:add(nr_mac_dissector, buffer(), "nr_mac")

    -- 调用nas_5gs解析器函数来解析PDU
    nr_mac_dissector:call(buffer, pinfo, nr_mac_tree)
end

-- 创建一个新的协议
local nr_mac_protocol = Proto("NR_mac", "NR_mac")

-- 将解析函数注册到协议
nr_mac_protocol.dissector = parse_nr_mac_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, nr_mac_protocol)