use std::{fs::File, time::{SystemTime, UNIX_EPOCH}, io::{self, BufRead}};

use pcap_file::{pcap, TsResolution, Endianness};
use serde_json;
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
    // while true {
        let now1 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    let a = "7e 00 68 01 00 65 2e 01 01 c2 11 00 09 01 00 06 31 3f 01 01 ff 01 06 06 13 88 04 7a 12 59 32 29 05 01 ac 1a 64 65 22 01 01 79 00 06 01 20 41 01 01 09 7b 00 18 80 80 21 0a 03 00 00 0a 81 06 08 08 08 08 00 0d 04 08 08 08 08 00 11 00 25 1c 09 69 69 6e 74 65 72 6e 65 74 06 6d 6e 63 30 30 31 06 6d 63 63 30 30 31 04 67 70 72 73 12 01";
    let hex = parse_hex32_string_to_u8_vec(a);
    let now2 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    println!("{} decoded time {:#?}",nas_5gs_decoder(hex).unwrap(), now2 - now1);
    // }
    

}
