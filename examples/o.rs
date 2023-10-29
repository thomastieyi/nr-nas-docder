use std::fmt;

#[derive(Debug)]
enum MyEnum {
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

impl fmt::Display for MyEnum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            MyEnum::NrRrcBcchBch => "NrRrcBcchBch",
            MyEnum::NrRrcBcchDlSch => "NrRrcBcchDlSch",
            MyEnum::NrRrcCellGroupConfigMsg => "NrRrcCellGroupConfigMsg",
            MyEnum::NrRrcCgConfigInfo => "NrRrcCgConfigInfo",
            MyEnum::NrRrcDlCcch => "NrRrcDlCcch",
            MyEnum::NrRrcDlCcchMsgMsg => "NrRrcDlCcchMsgMsg",
            MyEnum::NrRrcDlDcch => "NrRrcDlDcch",
            MyEnum::NrRrcDlDcchMsgMsg => "NrRrcDlDcchMsgMsg",
            MyEnum::NrRrcHandoverCommandMsg => "NrRrcHandoverCommandMsg",
            MyEnum::NrRrcHandoverPreparationInformationMsg => "NrRrcHandoverPreparationInformationMsg",
            MyEnum::NrRrcMcch => "NrRrcMcch",
            MyEnum::NrRrcMeasConfigMsg => "NrRrcMeasConfigMsg",
            MyEnum::NrRrcMeasGapConfigMsg => "NrRrcMeasGapConfigMsg",
            MyEnum::NrRrcPcch => "NrRrcPcch",
            MyEnum::NrRrcRadioBearerConfig => "NrRrcRadioBearerConfig",
            MyEnum::NrRrcRrcReconf => "NrRrcRrcReconf",
            MyEnum::NrRrcRrcReconfMsg => "NrRrcRrcReconfMsg",
            MyEnum::NrRrcSbcchSlBch => "NrRrcSbcchSlBch",
            MyEnum::NrRrcScch => "NrRrcScch",
            MyEnum::NrRrcUeCapabilityRatContainerList => "NrRrcUeCapabilityRatContainerList",
            MyEnum::NrRrcUeMrdcCap => "NrRrcUeMrdcCap",
            MyEnum::NrRrcUeMrdcCapMsg => "NrRrcUeMrdcCapMsg",
            MyEnum::NrRrcUeNrCap => "NrRrcUeNrCap",
            MyEnum::NrRrcUeNrCapMsg => "NrRrcUeNrCapMsg",
            MyEnum::NrRrcUeRadioAccessCapInfo => "NrRrcUeRadioAccessCapInfo",
            MyEnum::NrRrcUeRadioAccessCapInfoMsg => "NrRrcUeRadioAccessCapInfoMsg",
            MyEnum::NrRrcUeRadioPagingInfo => "NrRrcUeRadioPagingInfo",
            MyEnum::NrRrcUlCcch => "NrRrcUlCcch",
            MyEnum::NrRrcUlCcch1 => "NrRrcUlCcch1",
            MyEnum::NrRrcUlCcchMsgMsg => "NrRrcUlCcchMsgMsg",
            MyEnum::NrRrcUlDcch => "NrRrcUlDcch",
            MyEnum::NrRrcUlDcchMsgMsg => "NrRrcUlDcchMsgMsg",
        })
    }
}

fn main() {
    let my_var = MyEnum::NrRrcDlDcch;
    println!("枚举变量: {}", my_var);
    println!("常量值: {}", my_var as u32);
}
