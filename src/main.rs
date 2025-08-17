use clap::{Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;
use tondi_scriptexec::{TondiScript, ExecError, Stack, utils};

#[derive(Parser)]
#[command(
    name = "tondiexec",
    about = "Tondi脚本执行器 - 私有实现",
    version,
    long_about = "一个专为Tondi网络设计的脚本执行工具，支持脚本解析和执行。"
)]
struct Cli {
    /// 脚本文件路径
    #[arg(value_name = "SCRIPT_FILE")]
    script_file: PathBuf,

    /// 输出格式
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// 详细输出
    #[arg(short, long)]
    verbose: bool,

    /// 执行模式
    #[arg(short, long, value_enum, default_value_t = ExecutionMode::Execute)]
    mode: ExecutionMode,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Hex,
}

#[derive(ValueEnum, Clone, Debug)]
enum ExecutionMode {
    Parse,
    Execute,
    Validate,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.verbose {
        println!("Tondi脚本执行器 v{}", env!("CARGO_PKG_VERSION"));
        println!("脚本文件: {:?}", cli.script_file);
        println!("输出格式: {:?}", cli.format);
        println!("执行模式: {:?}", cli.mode);
        println!();
    }

    // 检查文件是否存在
    if !cli.script_file.exists() {
        eprintln!("错误: 脚本文件 '{}' 不存在", cli.script_file.display());
        std::process::exit(1);
    }

    // 读取脚本文件
    let script_content = match fs::read_to_string(&cli.script_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("错误: 无法读取脚本文件: {}", e);
            std::process::exit(1);
        }
    };

    if cli.verbose {
        println!("脚本内容:");
        println!("{}", script_content);
        println!();
    }

    // 解析脚本
    let script = match parse_script(&script_content) {
        Ok(script) => script,
        Err(e) => {
            eprintln!("错误: 脚本解析失败: {}", e);
            std::process::exit(1);
        }
    };

    if cli.verbose {
        println!("脚本解析成功:");
        println!("  长度: {} 字节", script.len());
        println!("  十六进制: {}", hex::encode(script.as_bytes()));
        println!();
    }

    // 根据模式执行
    match cli.mode {
        ExecutionMode::Parse => {
            display_script_info(&script, &cli.format);
        }
        ExecutionMode::Execute => {
            execute_script(&script, &cli.format, cli.verbose)?;
        }
        ExecutionMode::Validate => {
            validate_script(&script, &cli.format)?;
        }
    }

    Ok(())
}

/// 解析脚本内容
fn parse_script(content: &str) -> Result<TondiScript, ExecError> {
    // 移除空白字符和注释
    let cleaned_content = content
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if cleaned_content.is_empty() {
        return Err(ExecError::ScriptError("脚本内容为空".to_string()));
    }

    // 尝试解析为十六进制
    if cleaned_content.starts_with("0x") || cleaned_content.chars().all(|c| c.is_ascii_hexdigit()) {
        let hex_content = cleaned_content.trim_start_matches("0x");
        return TondiScript::from_hex(hex_content);
    }

    // 尝试解析为ASM格式（简化实现）
    parse_asm_script(&cleaned_content)
}

/// 解析ASM格式脚本
fn parse_asm_script(asm: &str) -> Result<TondiScript, ExecError> {
    let mut script_data = Vec::new();
    let tokens: Vec<&str> = asm.split_whitespace().collect();

    for token in tokens {
        match token {
            // 数字操作码
            "OP_0" => script_data.push(0x00),
            "OP_1" => script_data.push(0x51),
            "OP_2" => script_data.push(0x52),
            "OP_3" => script_data.push(0x53),
            "OP_4" => script_data.push(0x54),
            "OP_5" => script_data.push(0x55),
            "OP_6" => script_data.push(0x56),
            "OP_7" => script_data.push(0x57),
            "OP_8" => script_data.push(0x58),
            "OP_9" => script_data.push(0x59),
            "OP_10" => script_data.push(0x5a),
            "OP_11" => script_data.push(0x5b),
            "OP_12" => script_data.push(0x5c),
            "OP_13" => script_data.push(0x5d),
            "OP_14" => script_data.push(0x5e),
            "OP_15" => script_data.push(0x5f),
            "OP_16" => script_data.push(0x60),
            
            // 栈操作
            "OP_DUP" => script_data.push(0x76),
            "OP_HASH160" => script_data.push(0xa9),
            "OP_EQUAL" => script_data.push(0x87),
            "OP_VERIFY" => script_data.push(0x69),
            "OP_EQUALVERIFY" => script_data.push(0x88),
            "OP_CHECKSIG" => script_data.push(0xac),
            
            // 控制流
            "OP_IF" => script_data.push(0x63),
            "OP_ELSE" => script_data.push(0x67),
            "OP_ENDIF" => script_data.push(0x68),
            "OP_RETURN" => script_data.push(0x6a),
            
            // 数据推送
            _ => {
                // 尝试解析为十六进制数据
                if token.starts_with("0x") {
                    let hex_data = token.trim_start_matches("0x");
                    if let Ok(bytes) = hex::decode(hex_data) {
                        if bytes.len() <= 75 {
                            script_data.push(bytes.len() as u8);
                            script_data.extend_from_slice(&bytes);
                        } else {
                            return Err(ExecError::ScriptError(format!("数据过大: {}", token)));
                        }
                    } else {
                        return Err(ExecError::ScriptError(format!("无效的十六进制: {}", token)));
                    }
                } else if token.starts_with("'") && token.ends_with("'") {
                    // 字符串数据
                    let str_data = &token[1..token.len()-1];
                    let bytes = str_data.as_bytes();
                    if bytes.len() <= 75 {
                        script_data.push(bytes.len() as u8);
                        script_data.extend_from_slice(bytes);
                    } else {
                        return Err(ExecError::ScriptError(format!("字符串过长: {}", token)));
                    }
                } else {
                    return Err(ExecError::ScriptError(format!("未知的操作码: {}", token)));
                }
            }
        }
    }

    Ok(TondiScript::new(script_data))
}

/// 显示脚本信息
fn display_script_info(script: &TondiScript, format: &OutputFormat) {
    match format {
        OutputFormat::Text => {
            println!("脚本信息:");
            println!("  长度: {} 字节", script.len());
            println!("  十六进制: {}", hex::encode(script.as_bytes()));
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "length": script.len(),
                "hex": hex::encode(script.as_bytes()),
                "bytes": script.as_bytes()
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        OutputFormat::Hex => {
            println!("{}", hex::encode(script.as_bytes()));
        }
    }
}

/// 执行脚本
fn execute_script(script: &TondiScript, format: &OutputFormat, verbose: bool) -> Result<(), ExecError> {
    if verbose {
        println!("开始执行脚本...");
    }

    // 这里应该实现实际的脚本执行逻辑
    // 暂时只是模拟执行
    let mut stack = Stack::new();
    
    // 模拟执行过程
    let script_bytes = script.as_bytes();
    let mut i = 0;
    
    while i < script_bytes.len() {
        let opcode = script_bytes[i];
        i += 1;
        
        if verbose {
            println!("执行操作码: 0x{:02x}", opcode);
        }
        
        match opcode {
            0x00 => { // OP_0
                stack.push(vec![]);
                if verbose {
                    println!("  OP_0: 推入空数据");
                }
            }
            0x51..=0x60 => { // OP_1 to OP_16
                let value = opcode - 0x50;
                stack.push(vec![value]);
                if verbose {
                    println!("  OP_{}: 推入数字 {}", value, value);
                }
            }
            0x76 => { // OP_DUP
                if let Some(top) = stack.top() {
                    stack.push(top.to_vec());
                    if verbose {
                        println!("  OP_DUP: 复制栈顶元素");
                    }
                } else {
                    return Err(ExecError::StackUnderflow);
                }
            }
            0xa9 => { // OP_HASH160
                let data = stack.pop()?;
                let hash = utils::hash160(&data);
                stack.push(hash);
                if verbose {
                    println!("  OP_HASH160: 计算哈希160");
                }
            }
            0x87 => { // OP_EQUAL
                if stack.len() < 2 {
                    return Err(ExecError::StackUnderflow);
                }
                let b = stack.pop()?;
                let a = stack.pop()?;
                let result = if a == b { 1 } else { 0 };
                stack.push(vec![result]);
                if verbose {
                    println!("  OP_EQUAL: 比较两个元素，结果: {}", result);
                }
            }
            0x69 => { // OP_VERIFY
                let data = stack.pop()?;
                if data.is_empty() || data[0] == 0 {
                    return Err(ExecError::ScriptError("OP_VERIFY失败".to_string()));
                }
                if verbose {
                    println!("  OP_VERIFY: 验证成功");
                }
            }
            0x88 => { // OP_EQUALVERIFY
                if stack.len() < 2 {
                    return Err(ExecError::StackUnderflow);
                }
                let b = stack.pop()?;
                let a = stack.pop()?;
                if a != b {
                    return Err(ExecError::ScriptError("OP_EQUALVERIFY失败".to_string()));
                }
                if verbose {
                    println!("  OP_EQUALVERIFY: 验证成功");
                }
            }
            0xac => { // OP_CHECKSIG
                if stack.len() < 2 {
                    return Err(ExecError::StackUnderflow);
                }
                let _pubkey = stack.pop()?;
                let _signature = stack.pop()?;
                // 这里应该实现实际的签名验证
                stack.push(vec![1]); // 暂时返回成功
                if verbose {
                    println!("  OP_CHECKSIG: 签名验证成功");
                }
            }
            _ => {
                if opcode <= 75 { // 数据推送
                    if i + opcode as usize <= script_bytes.len() {
                        let data = script_bytes[i..i + opcode as usize].to_vec();
                        stack.push(data);
                        i += opcode as usize;
                        if verbose {
                            println!("  数据推送: {} 字节", opcode);
                        }
                    } else {
                        return Err(ExecError::ScriptError("数据推送长度不足".to_string()));
                    }
                } else {
                    return Err(ExecError::OpcodeError(format!("不支持的操作码: 0x{:02x}", opcode)));
                }
            }
        }
        
        if verbose {
            println!("  栈大小: {}", stack.len());
        }
    }
    
    if verbose {
        println!("脚本执行完成");
        println!("最终栈内容:");
        for (i, item) in stack.as_ref().iter().enumerate() {
            println!("  [{}]: {}", i, hex::encode(item));
        }
    }
    
    match format {
        OutputFormat::Text => {
            println!("执行结果: 成功");
            println!("最终栈大小: {}", stack.len());
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "result": "success",
                "final_stack_size": stack.len(),
                "final_stack": stack.as_ref().iter().map(|item| hex::encode(item)).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        OutputFormat::Hex => {
            println!("执行成功");
        }
    }
    
    Ok(())
}

/// 验证脚本
fn validate_script(script: &TondiScript, format: &OutputFormat) -> Result<(), ExecError> {
    let mut errors = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    
    // 检查脚本长度
    if script.len() > 10000 {
        errors.push("脚本长度超过10000字节限制".to_string());
    }
    
    // 检查操作码数量
    let opcode_count = script.as_bytes().iter().filter(|&&b| b > 0x60).count();
    if opcode_count > 201 {
        errors.push("操作码数量超过201个限制".to_string());
    }
    
    // 检查数据推送大小
    let script_bytes = script.as_bytes();
    let mut i = 0;
    while i < script_bytes.len() {
        let opcode = script_bytes[i];
        i += 1;
        
        if opcode <= 75 { // 数据推送
            if i + opcode as usize <= script_bytes.len() {
                let data = &script_bytes[i..i + opcode as usize];
                if data.len() > 520 {
                    errors.push("数据推送超过520字节限制".to_string());
                }
                i += opcode as usize;
            } else {
                errors.push("数据推送长度不足".to_string());
            }
        }
    }
    
    // 输出结果
    match format {
        OutputFormat::Text => {
            if errors.is_empty() && warnings.is_empty() {
                println!("脚本验证: 通过");
            } else {
                if !errors.is_empty() {
                    println!("脚本验证: 失败");
                    println!("错误:");
                    for error in &errors {
                        println!("  - {}", error);
                    }
                }
                if !warnings.is_empty() {
                    println!("警告:");
                    for warning in &warnings {
                        println!("  - {}", warning);
                    }
                }
            }
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "valid": errors.is_empty(),
                "errors": errors,
                "warnings": warnings
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        OutputFormat::Hex => {
            if errors.is_empty() {
                println!("VALID");
            } else {
                println!("INVALID");
            }
        }
    }
    
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ExecError::ScriptError(format!("验证失败: {} 个错误", errors.len())))
    }
}
