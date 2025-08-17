use crate::data_structures::{Stack, TondiScript};
use crate::error::ExecError;
use serde::{Deserialize, Serialize};

/// 脚本执行步骤的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionStep {
    /// 步骤编号
    pub step: usize,
    /// 操作码
    pub opcode: String,
    /// 操作码值
    pub opcode_value: u8,
    /// 当前栈状态
    pub stack: Vec<String>,
    /// 备用栈状态
    pub altstack: Vec<String>,
    /// 条件栈状态
    pub condition_stack: Vec<bool>,
    /// 操作码计数
    pub op_count: usize,
}

/// 脚本执行结果的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// 执行是否成功
    pub success: bool,
    /// 错误信息（如果有）
    pub error: Option<String>,
    /// 最终栈状态
    pub final_stack: Vec<String>,
    /// 最终栈大小
    pub final_stack_size: usize,
    /// 执行的操作码数量
    pub total_ops: usize,
    /// 执行时间（毫秒）
    pub execution_time_ms: u64,
}

/// 脚本信息的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptInfo {
    /// 脚本长度
    pub length: usize,
    /// 十六进制表示
    pub hex: String,
    /// 字节数据
    pub bytes: Vec<u8>,
    /// 操作码列表
    pub opcodes: Vec<OpcodeInfo>,
}

/// 操作码信息的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct OpcodeInfo {
    /// 操作码名称
    pub name: String,
    /// 操作码值
    pub value: u8,
    /// 操作码描述
    pub description: String,
    /// 操作码类型
    pub opcode_type: OpcodeType,
    /// 数据长度（如果是数据推送）
    pub data_length: Option<usize>,
}

/// 操作码类型
#[derive(Debug, Serialize, Deserialize)]
pub enum OpcodeType {
    /// 常量
    Constant,
    /// 栈操作
    Stack,
    /// 逻辑操作
    Logic,
    /// 算术操作
    Arithmetic,
    /// 哈希操作
    Hash,
    /// 签名操作
    Signature,
    /// 时间锁定
    TimeLock,
    /// 数据推送
    DataPush,
    /// 控制流
    ControlFlow,
    /// 其他
    Other,
}

/// 栈的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct StackInfo {
    /// 栈大小
    pub size: usize,
    /// 栈内容
    pub items: Vec<StackItem>,
}

/// 栈项的JSON表示
#[derive(Debug, Serialize, Deserialize)]
pub struct StackItem {
    /// 数据
    pub data: String,
    /// 数据类型
    pub data_type: StackItemType,
    /// 十六进制表示
    pub hex: String,
    /// 长度
    pub length: usize,
}

/// 栈项类型
#[derive(Debug, Serialize, Deserialize)]
pub enum StackItemType {
    /// 空数据
    Empty,
    /// 数字
    Number,
    /// 字符串
    String,
    /// 十六进制
    Hex,
    /// 公钥
    PublicKey,
    /// 签名
    Signature,
    /// 哈希
    Hash,
    /// 其他
    Other,
}

/// 将栈转换为JSON友好的格式
pub fn stack_to_json(stack: &Stack) -> StackInfo {
    let items: Vec<StackItem> = stack
        .as_ref()
        .iter()
        .map(|item| {
            let hex = hex::encode(item);
            let data_type = classify_stack_item(item);
            let data = match data_type {
                StackItemType::Empty => "".to_string(),
                StackItemType::Number => {
                    if let Ok(num) = crate::utils::read_scriptint(item, 4, true) {
                        num.to_string()
                    } else {
                        hex.clone()
                    }
                }
                StackItemType::String => {
                    if item.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
                        String::from_utf8_lossy(item).to_string()
                    } else {
                        hex.clone()
                    }
                }
                _ => hex.clone(),
            };

            StackItem {
                data,
                data_type,
                hex,
                length: item.len(),
            }
        })
        .collect();

    StackInfo {
        size: stack.len(),
        items,
    }
}

/// 将脚本转换为JSON友好的格式
pub fn script_to_json(script: &TondiScript) -> ScriptInfo {
    let bytes = script.as_bytes();
    let opcodes = parse_opcodes(bytes);

    ScriptInfo {
        length: script.len(),
        hex: hex::encode(bytes),
        bytes: bytes.to_vec(),
        opcodes,
    }
}

/// 解析操作码
fn parse_opcodes(script_bytes: &[u8]) -> Vec<OpcodeInfo> {
    let mut opcodes = Vec::new();
    let mut i = 0;

    while i < script_bytes.len() {
        let opcode = script_bytes[i];
        i += 1;

        if opcode <= 75 {
            // 数据推送
            if i + opcode as usize <= script_bytes.len() {
                let data_length = opcode as usize;
                opcodes.push(OpcodeInfo {
                    name: format!("PUSH_{}", data_length),
                    value: opcode,
                    description: format!("推送 {} 字节数据", data_length),
                    opcode_type: OpcodeType::DataPush,
                    data_length: Some(data_length),
                });
                i += data_length;
            }
        } else {
            // 操作码
            let (name, description, opcode_type) = get_opcode_info(opcode);
            opcodes.push(OpcodeInfo {
                name,
                value: opcode,
                description,
                opcode_type,
                data_length: None,
            });
        }
    }

    opcodes
}

/// 获取操作码信息
fn get_opcode_info(opcode: u8) -> (String, String, OpcodeType) {
    match opcode {
        // 常量
        0x00 => ("OP_0".to_string(), "推入空数据".to_string(), OpcodeType::Constant),
        0x51..=0x60 => {
            let n = opcode - 0x50;
            (format!("OP_{}", n), format!("推入数字 {}", n), OpcodeType::Constant)
        }
        0x4f => ("OP_1NEGATE".to_string(), "推入 -1".to_string(), OpcodeType::Constant),

        // 栈操作
        0x76 => ("OP_DUP".to_string(), "复制栈顶元素".to_string(), OpcodeType::Stack),
        0x77 => ("OP_NIP".to_string(), "删除栈顶第二个元素".to_string(), OpcodeType::Stack),
        0x78 => ("OP_OVER".to_string(), "复制栈顶第二个元素到栈顶".to_string(), OpcodeType::Stack),
        0x79 => ("OP_PICK".to_string(), "复制栈中指定位置的元素到栈顶".to_string(), OpcodeType::Stack),
        0x7a => ("OP_ROLL".to_string(), "移动栈中指定位置的元素到栈顶".to_string(), OpcodeType::Stack),
        0x7b => ("OP_ROT".to_string(), "旋转栈顶三个元素".to_string(), OpcodeType::Stack),
        0x7c => ("OP_SWAP".to_string(), "交换栈顶两个元素".to_string(), OpcodeType::Stack),
        0x7d => ("OP_TUCK".to_string(), "复制栈顶元素到栈顶第二个位置".to_string(), OpcodeType::Stack),

        // 逻辑操作
        0x87 => ("OP_EQUAL".to_string(), "比较两个元素是否相等".to_string(), OpcodeType::Logic),
        0x88 => ("OP_EQUALVERIFY".to_string(), "比较两个元素是否相等，失败则终止".to_string(), OpcodeType::Logic),
        0x69 => ("OP_VERIFY".to_string(), "验证栈顶元素是否为真".to_string(), OpcodeType::Logic),

        // 哈希操作
        0xa6 => ("OP_RIPEMD160".to_string(), "计算RIPEMD160哈希".to_string(), OpcodeType::Hash),
        0xa7 => ("OP_SHA1".to_string(), "计算SHA1哈希".to_string(), OpcodeType::Hash),
        0xa8 => ("OP_SHA256".to_string(), "计算SHA256哈希".to_string(), OpcodeType::Hash),
        0xa9 => ("OP_HASH160".to_string(), "计算HASH160（SHA256+RIPEMD160）".to_string(), OpcodeType::Hash),
        0xaa => ("OP_HASH256".to_string(), "计算双重SHA256哈希".to_string(), OpcodeType::Hash),

        // 签名操作
        0xac => ("OP_CHECKSIG".to_string(), "验证ECDSA签名".to_string(), OpcodeType::Signature),
        0xad => ("OP_CHECKSIGVERIFY".to_string(), "验证ECDSA签名，失败则终止".to_string(), OpcodeType::Signature),
        0xae => ("OP_CHECKMULTISIG".to_string(), "验证多重签名".to_string(), OpcodeType::Signature),
        0xaf => ("OP_CHECKMULTISIGVERIFY".to_string(), "验证多重签名，失败则终止".to_string(), OpcodeType::Signature),

        // 时间锁定
        0xb1 => ("OP_CHECKLOCKTIMEVERIFY".to_string(), "检查锁定时间".to_string(), OpcodeType::TimeLock),
        0xb2 => ("OP_CHECKSEQUENCEVERIFY".to_string(), "检查序列号".to_string(), OpcodeType::TimeLock),

        // 控制流
        0x63 => ("OP_IF".to_string(), "条件执行开始".to_string(), OpcodeType::ControlFlow),
        0x67 => ("OP_ELSE".to_string(), "条件执行分支".to_string(), OpcodeType::ControlFlow),
        0x68 => ("OP_ENDIF".to_string(), "条件执行结束".to_string(), OpcodeType::ControlFlow),
        0x6a => ("OP_RETURN".to_string(), "终止执行".to_string(), OpcodeType::ControlFlow),

        // 其他
        _ => (format!("OP_UNKNOWN_{:02x}", opcode), "未知操作码".to_string(), OpcodeType::Other),
    }
}

/// 分类栈项类型
fn classify_stack_item(data: &[u8]) -> StackItemType {
    if data.is_empty() {
        StackItemType::Empty
    } else if data.len() <= 8 && data.iter().all(|&b| b == 0 || b == 0x80) {
        StackItemType::Number
    } else if data.len() == 33 || data.len() == 65 {
        StackItemType::PublicKey
    } else if data.len() >= 70 && data.len() <= 73 {
        StackItemType::Signature
    } else if data.len() == 20 || data.len() == 32 {
        StackItemType::Hash
    } else if data.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        StackItemType::String
    } else {
        StackItemType::Other
    }
}

/// 创建执行步骤的JSON
pub fn create_execution_step(
    step: usize,
    opcode: u8,
    stack: &Stack,
    altstack: &Stack,
    _condition_stack: &crate::data_structures::ConditionStack,
    op_count: usize,
) -> ExecutionStep {
    ExecutionStep {
        step,
        opcode: get_opcode_info(opcode).0,
        opcode_value: opcode,
        stack: stack.as_ref().iter().map(|item| hex::encode(item)).collect(),
        altstack: altstack.as_ref().iter().map(|item| hex::encode(item)).collect(),
        condition_stack: vec![], // 暂时为空，因为ConditionStack没有实现AsRef
        op_count,
    }
}

/// 创建执行结果的JSON
pub fn create_execution_result(
    success: bool,
    error: Option<ExecError>,
    final_stack: &Stack,
    total_ops: usize,
    execution_time_ms: u64,
) -> ExecutionResult {
    ExecutionResult {
        success,
        error: error.map(|e| format!("{:?}", e)),
        final_stack: final_stack.as_ref().iter().map(|item| hex::encode(item)).collect(),
        final_stack_size: final_stack.len(),
        total_ops,
        execution_time_ms,
    }
}
