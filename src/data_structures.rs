use crate::ExecError;

/// Tondi脚本执行器使用的栈结构
pub struct Stack {
    data: Vec<Vec<u8>>,
}

impl Stack {
    pub fn new() -> Self {
        Stack { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Stack {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn from_vec(data: Vec<Vec<u8>>) -> Self {
        Stack { data }
    }

    pub fn into_vec(self) -> Vec<Vec<u8>> {
        self.data
    }

    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [Vec<u8>] {
        &mut self.data
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Stack {
    fn clone(&self) -> Self {
        Stack {
            data: self.data.clone(),
        }
    }
}

impl std::ops::Deref for Stack {
    type Target = [Vec<u8>];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for Stack {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

// 为Stack类型添加扩展方法
pub trait StackExt {
    fn top(&self) -> Option<&[u8]>;
    fn pop(&mut self) -> Option<Vec<u8>>;
    fn push(&mut self, item: Vec<u8>);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get(&self, index: usize) -> Option<&[u8]>;
    fn remove(&mut self, index: usize) -> Option<Vec<u8>>;
    fn insert(&mut self, index: usize, item: Vec<u8>);
    fn clear(&mut self);
}

impl StackExt for Stack {
    fn top(&self) -> Option<&[u8]> {
        self.data.last().map(|v| v.as_slice())
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        self.data.pop()
    }

    fn push(&mut self, item: Vec<u8>) {
        self.data.push(item);
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn get(&self, index: usize) -> Option<&[u8]> {
        self.data.get(index).map(|v| v.as_ref())
    }

    fn remove(&mut self, index: usize) -> Option<Vec<u8>> {
        if index < self.data.len() {
            Some(self.data.swap_remove(index))
        } else {
            None
        }
    }

    fn insert(&mut self, index: usize, item: Vec<u8>) {
        if index <= self.data.len() {
            self.data.insert(index, item);
        }
    }

    fn clear(&mut self) {
        self.data.clear()
    }
}

/// 条件栈结构
#[derive(Debug, Clone)]
pub struct ConditionStack {
    data: Vec<bool>,
}

impl ConditionStack {
    /// 创建新的空条件栈
    pub fn new() -> Self {
        ConditionStack { data: Vec::new() }
    }

    /// 从现有数据创建条件栈
    pub fn from_data(data: Vec<bool>) -> Self {
        ConditionStack { data }
    }

    /// 获取栈顶元素
    pub fn top(&self) -> Option<bool> {
        self.data.last().copied()
    }

    /// 弹出栈顶元素
    pub fn pop(&mut self) -> Result<bool, ExecError> {
        self.data.pop().ok_or(ExecError::StackUnderflow)
    }

    /// 将元素推入栈顶
    pub fn push(&mut self, value: bool) {
        self.data.push(value);
    }

    /// 获取栈的大小
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 检查栈是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 获取栈中指定位置的元素
    pub fn get(&self, index: usize) -> Option<bool> {
        self.data.get(index).copied()
    }

    /// 清空栈
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// 获取栈的引用
    pub fn as_ref(&self) -> &[bool] {
        &self.data
    }

    /// 获取栈的可变引用
    pub fn as_mut(&mut self) -> &mut [bool] {
        &mut self.data
    }
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Tondi脚本结构
#[derive(Debug, Clone)]
pub struct TondiScript {
    /// 脚本数据
    pub data: Vec<u8>,
    /// 脚本类型
    pub script_type: ScriptType,
    /// 脚本版本
    pub version: u16,
}

/// 脚本类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptType {
    /// 支付到公钥哈希
    PayToPubKeyHash,
    /// 支付到脚本哈希
    PayToScriptHash,
    /// 多重签名
    MultiSig,
    /// 空输出
    NullData,
    /// 支付到公钥
    PayToPubKey,
    /// 支付到见证公钥哈希
    PayToWitnessPubKeyHash,
    /// 支付到见证脚本哈希
    PayToWitnessScriptHash,
    /// Taproot输出
    Taproot,
    /// 未知类型
    Unknown,
}

impl TondiScript {
    /// 创建新的脚本
    pub fn new(data: Vec<u8>, script_type: ScriptType, version: u16) -> Self {
        TondiScript {
            data,
            script_type,
            version,
        }
    }

    /// 从字节数据创建脚本
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let script_type = Self::detect_script_type(&data);
        TondiScript {
            data,
            script_type,
            version: 0,
        }
    }

    /// 检测脚本类型
    fn detect_script_type(data: &[u8]) -> ScriptType {
        if data.is_empty() {
            return ScriptType::Unknown;
        }

        // 简单的脚本类型检测逻辑
        if data.len() == 25
            && data[0] == 0x76
            && data[1] == 0xA9
            && data[2] == 0x14
            && data[23] == 0x88
            && data[24] == 0xAC
        {
            ScriptType::PayToPubKeyHash
        } else if data.len() == 23 && data[0] == 0xA9 && data[1] == 0x14 && data[22] == 0x87 {
            ScriptType::PayToScriptHash
        } else if data.len() >= 3 && data[0] == 0x51 && data[data.len() - 1] == 0xAE {
            ScriptType::MultiSig
        } else if data.len() >= 2 && data[0] == 0x6A {
            ScriptType::NullData
        } else if data.len() >= 33 && data.len() <= 65 && (data[0] == 0x21 || data[0] == 0x41) {
            ScriptType::PayToPubKey
        } else if data.len() == 22 && data[0] == 0x00 && data[1] == 0x14 {
            ScriptType::PayToWitnessPubKeyHash
        } else if data.len() == 34 && data[0] == 0x00 && data[1] == 0x20 {
            ScriptType::PayToWitnessScriptHash
        } else if data.len() == 34 && data[0] == 0x51 && data[1] == 0x20 {
            ScriptType::Taproot
        } else {
            ScriptType::Unknown
        }
    }

    /// 获取脚本的字节表示
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// 检查脚本是否有效
    pub fn is_valid(&self) -> bool {
        !self.data.is_empty() && self.data.len() <= crate::MAX_SCRIPT_ELEMENT_SIZE
    }

    /// 获取脚本长度
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 检查脚本是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for TondiScript {
    fn default() -> Self {
        Self::new(Vec::new(), ScriptType::Unknown, 0)
    }
}

/// Tondi交易输出
#[derive(Debug, Clone)]
pub struct TondiTxOut {
    pub value: u64,
    pub script_pubkey: TondiScript,
}

impl TondiTxOut {
    /// 创建新的交易输出
    pub fn new(value: u64, script_pubkey: TondiScript) -> Self {
        TondiTxOut {
            value,
            script_pubkey,
        }
    }
}

/// Tondi交易输入
#[derive(Debug, Clone)]
pub struct TondiTxIn {
    pub previous_output: [u8; 32], // 前一个输出的哈希
    pub sequence: u32,
    pub script_sig: TondiScript,
    pub witness: Vec<Vec<u8>>,
}

impl TondiTxIn {
    /// 创建新的交易输入
    pub fn new(
        previous_output: [u8; 32],
        sequence: u32,
        script_sig: TondiScript,
        witness: Vec<Vec<u8>>,
    ) -> Self {
        TondiTxIn {
            previous_output,
            sequence,
            script_sig,
            witness,
        }
    }
}

/// Tondi交易
#[derive(Debug, Clone)]
pub struct TondiTransaction {
    pub version: i32,
    pub inputs: Vec<TondiTxIn>,
    pub outputs: Vec<TondiTxOut>,
    pub lock_time: u32,
}

impl TondiTransaction {
    /// 创建新的交易
    pub fn new(version: i32, lock_time: u32) -> Self {
        TondiTransaction {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time,
        }
    }

    /// 添加输入
    pub fn add_input(&mut self, input: TondiTxIn) {
        self.inputs.push(input);
    }

    /// 添加输出
    pub fn add_output(&mut self, output: TondiTxOut) {
        self.outputs.push(output);
    }
}
