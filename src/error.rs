use std::fmt;

/// Tondi脚本执行错误类型
#[derive(Debug, Clone)]
pub enum ExecError {
    /// 栈下溢
    StackUnderflow,
    /// 栈索引越界
    StackIndexOutOfBounds,
    /// 无效的十六进制字符串
    InvalidHex,
    /// 脚本执行错误
    ScriptError(String),
    /// 操作码错误
    OpcodeError(String),
    /// 签名验证失败
    SignatureVerificationFailed,
    /// 无效的公钥
    InvalidPublicKey,
    /// 无效的签名
    InvalidSignature,
    /// 脚本格式错误
    InvalidScriptFormat,
    /// 交易格式错误
    InvalidTransactionFormat,
    /// 内存不足
    OutOfMemory,
    /// 超时错误
    Timeout,
    /// 未知错误
    Unknown(String),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::StackUnderflow => write!(f, "栈下溢"),
            ExecError::StackIndexOutOfBounds => write!(f, "栈索引越界"),
            ExecError::InvalidHex => write!(f, "无效的十六进制字符串"),
            ExecError::ScriptError(msg) => write!(f, "脚本执行错误: {}", msg),
            ExecError::OpcodeError(msg) => write!(f, "操作码错误: {}", msg),
            ExecError::SignatureVerificationFailed => write!(f, "签名验证失败"),
            ExecError::InvalidPublicKey => write!(f, "无效的公钥"),
            ExecError::InvalidSignature => write!(f, "无效的签名"),
            ExecError::InvalidScriptFormat => write!(f, "脚本格式错误"),
            ExecError::InvalidTransactionFormat => write!(f, "交易格式错误"),
            ExecError::OutOfMemory => write!(f, "内存不足"),
            ExecError::Timeout => write!(f, "超时错误"),
            ExecError::Unknown(msg) => write!(f, "未知错误: {}", msg),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<String> for ExecError {
    fn from(msg: String) -> Self {
        ExecError::Unknown(msg)
    }
}

impl From<&str> for ExecError {
    fn from(msg: &str) -> Self {
        ExecError::Unknown(msg.to_string())
    }
}

impl From<std::io::Error> for ExecError {
    fn from(err: std::io::Error) -> Self {
        ExecError::Unknown(format!("IO错误: {}", err))
    }
}

impl From<hex::FromHexError> for ExecError {
    fn from(_: hex::FromHexError) -> Self {
        ExecError::InvalidHex
    }
}

impl From<secp256k1::Error> for ExecError {
    fn from(_err: secp256k1::Error) -> Self {
        ExecError::InvalidSignature
    }
}

/// 结果类型别名
pub type Result<T> = std::result::Result<T, ExecError>;
