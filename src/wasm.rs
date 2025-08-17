use crate::data_structures::{Stack, TondiScript};
use crate::error::ExecError;
use crate::{create_executor, ExecCtx, Options, TondiScriptExecutor};
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use console_error_panic_hook;

/// Tondi脚本执行器的WASM包装
#[wasm_bindgen]
pub struct TondiScriptExecutorWasm {
    executor: TondiScriptExecutor,
}

#[wasm_bindgen]
impl TondiScriptExecutorWasm {
    /// 创建新的脚本执行器
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // 设置panic hook
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        let options = Options::default();
        let executor = create_executor(ExecCtx::Legacy, options);

        TondiScriptExecutorWasm { executor }
    }

    /// 从选项创建脚本执行器
    pub fn new_with_options(
        require_minimal: bool,
        verify_cltv: bool,
        verify_csv: bool,
        verify_minimal_if: bool,
        enforce_stack_limit: bool,
        op_cat: bool,
        op_mul: bool,
        op_div: bool,
    ) -> Self {
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        let experimental = crate::Experimental {
            op_cat,
            op_mul,
            op_div,
        };

        let options = Options {
            require_minimal,
            verify_cltv,
            verify_csv,
            verify_minimal_if,
            enforce_stack_limit,
            experimental,
        };

        let executor = create_executor(ExecCtx::Legacy, options);
        TondiScriptExecutorWasm { executor }
    }

    /// 执行脚本
    pub fn execute(&mut self, script_hex: &str) -> Result<ExecutionResultWasm, JsValue> {
        let script = TondiScript::from_hex(script_hex)
            .map_err(|e| JsValue::from_str(&format!("脚本解析失败: {:?}", e)))?;

        let start = std::time::Instant::now();

        match self.executor.execute(&script) {
            Ok(()) => {
                let execution_time_ms = start.elapsed().as_millis() as u64;

                Ok(ExecutionResultWasm {
                    success: true,
                    error: None,
                    final_stack: self.executor.stack().as_ref().iter().map(|item| hex::encode(item)).collect(),
                    final_stack_size: self.executor.stack().len(),
                    total_ops: self.executor.op_count(),
                    execution_time_ms,
                })
            }
            Err(e) => {
                let end = web_sys::window()
                    .and_then(|w| w.performance())
                    .map(|p| p.now())
                    .unwrap_or(0.0);

                let execution_time_ms = ((end - start) * 1000.0) as u64;

                Ok(ExecutionResultWasm {
                    success: false,
                    error: Some(format!("{:?}", e)),
                    final_stack: self.executor.stack().as_ref().iter().map(|item| hex::encode(item)).collect(),
                    final_stack_size: self.executor.stack().len(),
                    total_ops: self.executor.op_count(),
                    execution_time_ms,
                })
            }
        }
    }

    /// 获取当前栈状态
    pub fn get_stack(&self) -> Vec<String> {
        self.executor.stack().as_ref().iter().map(|item| hex::encode(item)).collect()
    }

    /// 获取备用栈状态
    pub fn get_altstack(&self) -> Vec<String> {
        self.executor.altstack().as_ref().iter().map(|item| hex::encode(item)).collect()
    }

    /// 获取操作码计数
    pub fn get_op_count(&self) -> usize {
        self.executor.op_count()
    }

    /// 清空栈
    pub fn clear_stack(&mut self) {
        self.executor.stack_mut().clear();
    }

    /// 清空备用栈
    pub fn clear_altstack(&mut self) {
        self.executor.altstack_mut().clear();
    }

    /// 重置执行器
    pub fn reset(&mut self) {
        self.executor = create_executor(ExecCtx::Legacy, Options::default());
    }
}

/// 执行结果的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct ExecutionResultWasm {
    pub success: bool,
    pub error: Option<String>,
    pub final_stack: Vec<String>,
    pub final_stack_size: usize,
    pub total_ops: usize,
    pub execution_time_ms: u64,
}

/// 脚本信息的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct ScriptInfoWasm {
    pub length: usize,
    pub hex: String,
    pub opcodes: Vec<OpcodeInfoWasm>,
}

/// 操作码信息的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct OpcodeInfoWasm {
    pub name: String,
    pub value: u8,
    pub description: String,
    pub opcode_type: String,
    pub data_length: Option<usize>,
}

/// 栈信息的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct StackInfoWasm {
    pub size: usize,
    pub items: Vec<StackItemWasm>,
}

/// 栈项的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct StackItemWasm {
    pub data: String,
    pub data_type: String,
    pub hex: String,
    pub length: usize,
}

/// 获取操作码名称
fn get_opcode_name(opcode: u8) -> String {
    match opcode {
        0x00 => "OP_0".to_string(),
        0x51..=0x60 => format!("OP_{}", opcode - 0x50),
        0x4f => "OP_1NEGATE".to_string(),
        0x76 => "OP_DUP".to_string(),
        0x77 => "OP_NIP".to_string(),
        0x78 => "OP_OVER".to_string(),
        0x79 => "OP_PICK".to_string(),
        0x7a => "OP_ROLL".to_string(),
        0x7b => "OP_ROT".to_string(),
        0x7c => "OP_SWAP".to_string(),
        0x7d => "OP_TUCK".to_string(),
        0x87 => "OP_EQUAL".to_string(),
        0x88 => "OP_EQUALVERIFY".to_string(),
        0x69 => "OP_VERIFY".to_string(),
        0xa6 => "OP_RIPEMD160".to_string(),
        0xa7 => "OP_SHA1".to_string(),
        0xa8 => "OP_SHA256".to_string(),
        0xa9 => "OP_HASH160".to_string(),
        0xaa => "OP_HASH256".to_string(),
        0xac => "OP_CHECKSIG".to_string(),
        0xad => "OP_CHECKSIGVERIFY".to_string(),
        0xae => "OP_CHECKMULTISIG".to_string(),
        0xaf => "OP_CHECKMULTISIGVERIFY".to_string(),
        0xb1 => "OP_CHECKLOCKTIMEVERIFY".to_string(),
        0xb2 => "OP_CHECKSEQUENCEVERIFY".to_string(),
        0x63 => "OP_IF".to_string(),
        0x67 => "OP_ELSE".to_string(),
        0x68 => "OP_ENDIF".to_string(),
        0x6a => "OP_RETURN".to_string(),
        _ => format!("OP_UNKNOWN_{:02x}", opcode),
    }
}

/// 解析脚本为WASM格式
#[wasm_bindgen]
pub fn parse_script(script_hex: &str) -> Result<ScriptInfoWasm, JsValue> {
    let script = TondiScript::from_hex(script_hex)
        .map_err(|e| JsValue::from_str(&format!("脚本解析失败: {:?}", e)))?;

    let bytes = script.as_bytes();
    let mut opcodes = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let opcode = bytes[i];
        i += 1;

        if opcode <= 75 {
            // 数据推送
            if i + opcode as usize <= bytes.len() {
                let data_length = opcode as usize;
                opcodes.push(OpcodeInfoWasm {
                    name: format!("PUSH_{}", data_length),
                    value: opcode,
                    description: format!("推送 {} 字节数据", data_length),
                    opcode_type: "DataPush".to_string(),
                    data_length: Some(data_length),
                });
                i += data_length;
            }
        } else {
            // 操作码
            let (name, description, opcode_type) = get_opcode_info(opcode);
            opcodes.push(OpcodeInfoWasm {
                name,
                value: opcode,
                description,
                opcode_type,
                data_length: None,
            });
        }
    }

    Ok(ScriptInfoWasm {
        length: script.len(),
        hex: script_hex.to_string(),
        opcodes,
    })
}

/// 获取操作码信息
fn get_opcode_info(opcode: u8) -> (String, String, String) {
    match opcode {
        0x00 => ("OP_0".to_string(), "推入空数据".to_string(), "Constant".to_string()),
        0x51..=0x60 => {
            let n = opcode - 0x50;
            (format!("OP_{}", n), format!("推入数字 {}", n), "Constant".to_string())
        }
        0x4f => ("OP_1NEGATE".to_string(), "推入 -1".to_string(), "Constant".to_string()),
        0x76 => ("OP_DUP".to_string(), "复制栈顶元素".to_string(), "Stack".to_string()),
        0x87 => ("OP_EQUAL".to_string(), "比较两个元素是否相等".to_string(), "Logic".to_string()),
        0x88 => ("OP_EQUALVERIFY".to_string(), "比较两个元素是否相等，失败则终止".to_string(), "Logic".to_string()),
        0x69 => ("OP_VERIFY".to_string(), "验证栈顶元素是否为真".to_string(), "Logic".to_string()),
        0xa9 => ("OP_HASH160".to_string(), "计算HASH160（SHA256+RIPEMD160）".to_string(), "Hash".to_string()),
        0xac => ("OP_CHECKSIG".to_string(), "验证ECDSA签名".to_string(), "Signature".to_string()),
        0x6a => ("OP_RETURN".to_string(), "终止执行".to_string(), "ControlFlow".to_string()),
        _ => (format!("OP_UNKNOWN_{:02x}", opcode), "未知操作码".to_string(), "Other".to_string()),
    }
}

/// 验证脚本
#[wasm_bindgen]
pub fn validate_script(script_hex: &str) -> Result<ValidationResultWasm, JsValue> {
    let script = TondiScript::from_hex(script_hex)
        .map_err(|e| JsValue::from_str(&format!("脚本解析失败: {:?}", e)))?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // 检查脚本长度
    if script.len() > 10000 {
        errors.push("脚本长度超过10000字节限制".to_string());
    }

    // 检查操作码数量
    let bytes = script.as_bytes();
    let opcode_count = bytes.iter().filter(|&&b| b > 0x60).count();
    if opcode_count > 201 {
        errors.push("操作码数量超过201个限制".to_string());
    }

    // 检查数据推送大小
    let mut i = 0;
    while i < bytes.len() {
        let opcode = bytes[i];
        i += 1;

        if opcode <= 75 {
            if i + opcode as usize <= bytes.len() {
                let data_length = opcode as usize;
                if data_length > 520 {
                    errors.push("数据推送超过520字节限制".to_string());
                }
                i += data_length;
            } else {
                errors.push("数据推送长度不足".to_string());
            }
        }
    }

    Ok(ValidationResultWasm {
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}

/// 验证结果的WASM表示
#[wasm_bindgen]
#[derive(Clone)]
pub struct ValidationResultWasm {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// 设置panic hook
#[wasm_bindgen]
pub fn set_panic_hook() {
    #[cfg(feature = "wasm")]
    console_error_panic_hook::set_once();
}
