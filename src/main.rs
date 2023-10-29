use std::{fs::File, time::{SystemTime, UNIX_EPOCH, self}, io::{self, BufRead}, net::UdpSocket, thread};

use pcap_file::{pcap, TsResolution, Endianness};
use serde_json;

use std::fmt;

#[derive(Debug)]
enum NrRrc {
    NrRrcBcchBch = 10000,
    NrRrcBcchDlSch,
    NrRrcCellGroupConfigMsg,
    NrRrcCgConfigInfo,
    NrRrcDlCcch,
    NrRrcDlCcchMsgMsg,
    NrRrcDlDcch,
    NrRrcDlDcchMsgMsg,
    NrRrcHandoverCommandMsg,
    NrRrcHandoverPreparationInformationMsg,
    NrRrcMcch,
    NrRrcMeasConfigMsg,
    NrRrcMeasGapConfigMsg,
    NrRrcPcch,
    NrRrcRadioBearerConfig,
    NrRrcRrcReconf,
    NrRrcRrcReconfMsg,
    NrRrcSbcchSlBch,
    NrRrcScch,
    NrRrcUeCapabilityRatContainerList,
    NrRrcUeMrdcCap,
    NrRrcUeMrdcCapMsg,
    NrRrcUeNrCap,
    NrRrcUeNrCapMsg,
    NrRrcUeRadioAccessCapInfo,
    NrRrcUeRadioAccessCapInfoMsg,
    NrRrcUeRadioPagingInfo,
    NrRrcUlCcch,
    NrRrcUlCcch1,
    NrRrcUlCcchMsgMsg,
    NrRrcUlDcch,
    NrRrcUlDcchMsgMsg,
}

impl fmt::Display for NrRrc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            NrRrc::NrRrcBcchBch => "NrRrcBcchBch",
            NrRrc::NrRrcBcchDlSch => "NrRrcBcchDlSch",
            NrRrc::NrRrcCellGroupConfigMsg => "NrRrcCellGroupConfigMsg",
            NrRrc::NrRrcCgConfigInfo => "NrRrcCgConfigInfo",
            NrRrc::NrRrcDlCcch => "NrRrcDlCcch",
            NrRrc::NrRrcDlCcchMsgMsg => "NrRrcDlCcchMsgMsg",
            NrRrc::NrRrcDlDcch => "NrRrcDlDcch",
            NrRrc::NrRrcDlDcchMsgMsg => "NrRrcDlDcchMsgMsg",
            NrRrc::NrRrcHandoverCommandMsg => "NrRrcHandoverCommandMsg",
            NrRrc::NrRrcHandoverPreparationInformationMsg => "NrRrcHandoverPreparationInformationMsg",
            NrRrc::NrRrcMcch => "NrRrcMcch",
            NrRrc::NrRrcMeasConfigMsg => "NrRrcMeasConfigMsg",
            NrRrc::NrRrcMeasGapConfigMsg => "NrRrcMeasGapConfigMsg",
            NrRrc::NrRrcPcch => "NrRrcPcch",
            NrRrc::NrRrcRadioBearerConfig => "NrRrcRadioBearerConfig",
            NrRrc::NrRrcRrcReconf => "NrRrcRrcReconf",
            NrRrc::NrRrcRrcReconfMsg => "NrRrcRrcReconfMsg",
            NrRrc::NrRrcSbcchSlBch => "NrRrcSbcchSlBch",
            NrRrc::NrRrcScch => "NrRrcScch",
            NrRrc::NrRrcUeCapabilityRatContainerList => "NrRrcUeCapabilityRatContainerList",
            NrRrc::NrRrcUeMrdcCap => "NrRrcUeMrdcCap",
            NrRrc::NrRrcUeMrdcCapMsg => "NrRrcUeMrdcCapMsg",
            NrRrc::NrRrcUeNrCap => "NrRrcUeNrCap",
            NrRrc::NrRrcUeNrCapMsg => "NrRrcUeNrCapMsg",
            NrRrc::NrRrcUeRadioAccessCapInfo => "NrRrcUeRadioAccessCapInfo",
            NrRrc::NrRrcUeRadioAccessCapInfoMsg => "NrRrcUeRadioAccessCapInfoMsg",
            NrRrc::NrRrcUeRadioPagingInfo => "NrRrcUeRadioPagingInfo",
            NrRrc::NrRrcUlCcch => "NrRrcUlCcch",
            NrRrc::NrRrcUlCcch1 => "NrRrcUlCcch1",
            NrRrc::NrRrcUlCcchMsgMsg => "NrRrcUlCcchMsgMsg",
            NrRrc::NrRrcUlDcch => "NrRrcUlDcch",
            NrRrc::NrRrcUlDcchMsgMsg => "NrRrcUlDcchMsgMsg",
        })
    }
}


// 将HEX32字符串解析成u8 vec
fn parse_hex32_string_to_u8_vec(hex_str: &str) -> Vec<u8> {
    // 定义结果vec
    let mut result = Vec::new();

    // 分割字符串
    let hex_bytes = hex_str.split_whitespace();

    // 迭代分割后的字节字符串
    for hex_byte in hex_bytes {
        // 将每个字节解析成u8
        let byte = u8::from_str_radix(hex_byte, 16).unwrap();

        // 添加到结果vec
        result.push(byte);
    }

    // 返回结果vec
    result
}
fn nas_5gs_decoder(nas_hex: Vec<u8>) -> Result<serde_json::Value, serde_json::Error> {
    let prefix: Vec<u8>  = vec![0x00,0x0c,0x00,0x07,0x6e,0x61,0x73,0x2d,0x35,0x67,0x73,0x00,0x00,0x00,0x00];
    let mut result = prefix.clone();
    result.extend(nas_hex);
    let header = pcap_file::pcap::PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: pcap_file::DataLink::WIRESHARK_UPPER_PDU,
        ts_resolution: TsResolution::MicroSecond,
        endianness: Endianness::native(),
    };
    let file = File::create("a.pcap").unwrap();
    let mut writer = pcap_file::pcap::PcapWriter::with_header(file,header ).unwrap();
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    writer
                        .write_packet(
                            &pcap::PcapPacket { timestamp: now, orig_len: result.len() as u32, data: std::borrow::Cow::Borrowed(&result) }
                        )
                        .unwrap();
    let mut tshark_process = std::process::Command::new("tshark")
        .args(["-V", "-T", "json", "-r", "a.pcap"])
        .stdout(std::process::Stdio::piped())
        .spawn().unwrap();
    let stdout = tshark_process.stdout.as_mut().unwrap();
    let output = io::BufReader::new(stdout).lines();
    let output_str = output.collect::<Result<Vec<_>, _>>().unwrap()
    .join("\n");
    let res: serde_json::Value =  serde_json::from_str(&output_str).unwrap_or_default();
    Ok(res)
}
fn main() {
    while true {
        let now1 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    let nas_pdu_estab = "7e 00 68 01 00 65 2e 01 01 c2 11 00 09 01 00 06 31 3f 01 01 ff 01 06 06 13 88 04 7a 12 59 32 29 05 01 ac 1a 64 65 22 01 01 79 00 06 01 20 41 01 01 09 7b 00 18 80 80 21 0a 03 00 00 0a 81 06 08 08 08 08 00 0d 04 08 08 08 08 00 11 00 25 1c 09 69 69 6e 74 65 72 6e 65 74 06 6d 6e 63 30 30 31 06 6d 63 63 30 30 31 04 67 70 72 73 12 01";
    let nas_en = "7E 02 74 B6 46 1E 03 7E 00 68 01 00 30 2E 0A 01 C2 11 00 09 01 00 06 31 31 01 01 FF 01 06 03 F4 24 03 F4 24 29 05 01 0A 2D 00 02 22 01 01 79 00 06 01 20 41 01 01 05 25 04 03 69 6D 73 12 0A";
    let nr_rrc_bcch = "7c 80 0c 0a 0a 30 00 40 48 0b 00 83 83 40 06 82 8c 01 10 12 02 c0 20 e0 d0 01 c0 20 12 0c 00 42 01 82 19 d5 61 09 a0 30 00 00 62 0c 08 96 6b fa 47 70 40 20 00 02 22 83 f2 02 15 00 08 00 00 88 a0 00 80 41 b2 35 21 94 4b e6 42 b1 20 74 2c 0f 06 39 00 38 80 00 0c 43 87 02 25 99 40 44 04 33 33 57 5e 90 51 13 bc 19 b8 53 70 e6 e2 4d c5 9b 8d 37 1e 6e 44 dd 80 be 02 6b 37 5f c9 2a 03 80 09 28 0a 00 45 35 4d cc 50 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    let nr_rrc_ulccch = "10 00 00 00 00 06";
    let nr_rrc_dlccch = "20 40 20 c7 01 12 b8 01 60 02 1e f5 f9 00 20 cb d8 00 f8 44 60 aa 0f 34 08 41 ac 59 70 24 98 19 50 01 1f ff ff ff ff ff 96 ee a0 ee 10 04 00 00 44 50 6e 28 84 00 02 48 ac 84 08 09 64 01 34 01 35 d8 a0 6c 44 29 18 0c 65 52 38 e4 56 1d 28 80 4c d4 41 24 06 42 1c 02 25 40 06 05 08 43 23 3c 4d e0 c2 33 9e 47 49 34 14 9a 08 40 06 08 56 30 e6 e2 4d e3 ff 51 8c a5 29 44 a0 70 00 08 6c 00 00 00 40 08 00 3f 42 1d a2 68 84 56 00 02 60";
    let nr_rrc_uldcch = "10 00 45 df 80 10 5e 40 03 40 59 3c 04 7c 3f c0 00 01 4d 9d 09 8a 0b 80 bc 3c 00";
    let nr_rrc_dldcch = "28 88 ef c0 08 40 20 2e e0 01 7e 4c 9e 02 22 20 08 3c 8c 15 51 8a 80 e8 0c 9e 02 20 24 05 82 a0 a0 80 20 00 00 06 20 a0 80 20 00 00 04 20 42 20 0b c0 20 a6 82 80 60 22 3e 00 60 82 3f 20 60 44 3e 00 61 04 3e 40 62 13 3f 20";
    let nr_rrc_dldcch2 = "00 88 80 4d 00 d0 01 0e f5 18 00 14 01 80 a0 09 40 00 b1 c2 7d 48 37 24 20 03 5b f0 03 40 08 03 19 70 08 0e 10 90 00 48 08 00 31 89 00 08 0f f8 08 30 09 38 80 09 38 82 c9 99 48 48 10 bb e0 f3 15 aa cd 05 d9 10 20 08 00 00 03 c8 00 30 09 02 08 08 08 2b d8 01 3c 00 00 08 81 20 70 03 30 80 00 00 00 00 00 00 00 00 00 00 c0 00 08 81 20 70 03 30 80 00 00 00 00 00 00 00 00 00 00 41 28 20 1b 4b 6b 98 90 08";

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    // 目标IP地址和端口
    let target_ip = "115.25.41.203";
    let target_port_nas = 1234;
    let target_port_rrc = 1235;
    let hex = parse_hex32_string_to_u8_vec(nas_en);
    let hex2 = parse_hex32_string_to_u8_vec(nas_pdu_estab);
    let now2 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");


    // socket.send_to(&hex2, format!("{}:{}", target_ip, target_port_nas))
    // .expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_bcch), format!("{}:{}", target_ip,NrRrc::NrRrcBcchBch as u32 )).expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_ulccch), format!("{}:{}", target_ip,NrRrc::NrRrcUlCcch as u32 )).expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_dlccch), format!("{}:{}", target_ip,NrRrc::NrRrcDlCcch as u32 )).expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_uldcch), format!("{}:{}", target_ip,NrRrc::NrRrcUlDcch as u32)).expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_dldcch), format!("{}:{}", target_ip,NrRrc::NrRrcDlDcch as u32)).expect("Failed to send data");
    socket.send_to(&parse_hex32_string_to_u8_vec(nr_rrc_dldcch2), format!("{}:{}", target_ip,NrRrc::NrRrcDlDcch as u32 )).expect("Failed to send data");
    // println!("{:#?} \ndecoded time {:#?}",nas_5gs_decoder(hex).unwrap(), now2 - now1);
    // println!("{:#?} \ndecoded time {:#?}",nas_5gs_decoder(hex2).unwrap(), now2 - now1);
    thread::sleep(time::Duration::from_secs(1));
    }
    

}
