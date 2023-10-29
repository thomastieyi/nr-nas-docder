const fs = require('fs');
let nr_rrc =  [   "nr-rrc.bcch.bch",
"nr-rrc.bcch.dl.sch",
"nr-rrc.cellgroupconfig_msg",
"nr-rrc.cg_configinfo",
"nr-rrc.dl.ccch",
"nr-rrc.dl.ccch_msg_msg",
"nr-rrc.dl.dcch",
"nr-rrc.dl.dcch_msg_msg",
"nr-rrc.handovercommand_msg",
"nr-rrc.handoverpreparationinformation_msg",
"nr-rrc.mcch",
"nr-rrc.measconfig_msg",
"nr-rrc.measgapconfig_msg",
"nr-rrc.pcch",
"nr-rrc.radiobearerconfig",
"nr-rrc.rrc_reconf",
"nr-rrc.rrc_reconf_msg",
"nr-rrc.sbcch.sl.bch",
"nr-rrc.scch",
"nr-rrc.ue_capabilityrat_containerlist",
"nr-rrc.ue_mrdc_cap",
"nr-rrc.ue_mrdc_cap_msg",
"nr-rrc.ue_nr_cap",
"nr-rrc.ue_nr_cap_msg",
"nr-rrc.ue_radio_access_cap_info",
"nr-rrc.ue_radio_access_cap_info_msg",
"nr-rrc.ue_radio_paging_info",
"nr-rrc.ul.ccch",
"nr-rrc.ul.ccch1",
"nr-rrc.ul.ccch_msg_msg",
"nr-rrc.ul.dcch",
"nr-rrc.ul.dcch_msg_msg"]


let fill = (o_name,name , name_upper, port) =>{
    let tmp = `
-- 在Wireshark菜单栏中选择"Tools" -> "Lua" -> "Evaluate"，然后将以下代码粘贴到弹出的窗口中。

-- 导入Wireshark的nas_5gs解析器
local {{name}}_dissector = Dissector.get("{{o_name}}")

-- 解析函数
function parse_{{name}}_pdu(buffer, pinfo, tree)
    -- 创建一个新的根节点
    local {{name}}_tree = tree:add({{name}}_dissector, buffer(), "{{name}}")

    -- 调用nas_5gs解析器函数来解析PDU
    {{name}}_dissector:call(buffer, pinfo, {{name}}_tree)
end

-- 创建一个新的协议
local {{name}}_protocol = Proto("{{name_upper}}", "{{name_upper}}")

-- 将解析函数注册到协议
{{name}}_protocol.dissector = parse_{{name}}_pdu

-- 将协议添加到Wireshark的解析器表中
local udp_port = DissectorTable.get("udp.port")
udp_port:add({{port}}, {{name}}_protocol)
                `
    tmp = tmp.replace(/{{name}}/g, name);
    tmp = tmp.replace(/{{name_upper}}/g,name_upper);
    tmp = tmp.replace(/{{port}}/g,port);
    tmp = tmp.replace(/{{o_name}}/g,o_name);
    return tmp
}
nr_rrc.forEach((v,k)=>{
    let name = v.split('-').join('_').split('.').join("_")
    let name_upper = name.toLocaleUpperCase()
    let port = 10000 + k
    fs.writeFile('nr_rrc.lua', fill(v,name,name_upper,port), { flag: 'a+' }, function(err) {
        if (err) {
            console.log('写入文件时发生错误：', err);
        } else {
        }
    });
})

try {
    // 解析JSON数据

    // 生成枚举或常量类型
    let output = '';
    nr_rrc.forEach((item, index) => {
        const constantName = item.replace(/\W+/g, '_').toUpperCase();
        const constantValue = 10000 + index;
        output += `#define ${constantName} ${constantValue}\n`;
    });

    // 将生成的内容写入文件
    fs.writeFile('output.h', output, function(err) {
        if (err) {
            console.log('写入文件时发生错误：', err);
        } else {
            console.log('文件生成成功！');
        }
    });
} catch (error) {
    console.log('解析JSON时发生错误：', error);
}
