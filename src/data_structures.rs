use crate::ExecError;

/// Tondi脚本执行器使用的栈结构
#[derive(Debug, Clone)]
pub struct Stack {
    data: Vec<Vec<u8>>,
}

impl Stack {
    /// 创建新的空栈
    pub fn new() -> Self {
        Stack { data: Vec::new() }
    }

    /// 从现有数据创建栈
    pub fn from_data(data: Vec<Vec<u8>>) -> Self {
        Stack { data }
    }

    /// 获取栈顶元素
    pub fn top(&self) -> Option<&[u8]> {
        self.data.last().map(|v| v.as_slice())
    }

    /// 获取栈顶元素的可变引用
    pub fn top_mut(&mut self) -> Option<&mut Vec<u8>> {
        self.data.last_mut()
    }

    /// 弹出栈顶元素
    pub fn pop(&mut self) -> Result<Vec<u8>, ExecError> {
        self.data.pop().ok_or(ExecError::StackUnderflow)
    }

    /// 弹出栈顶元素，如果为空则返回默认值
    pub fn pop_or(&mut self, default: Vec<u8>) -> Vec<u8> {
        self.data.pop().unwrap_or(default)
    }

    /// 弹出栈顶元素，如果为空则返回None
    pub fn pop_opt(&mut self) -> Option<Vec<u8>> {
        self.data.pop()
    }

    /// 将元素推入栈顶
    pub fn push(&mut self, data: Vec<u8>) {
        self.data.push(data);
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
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.data.get(index).map(|v| v.as_slice())
    }

    /// 获取栈中指定位置元素的可变引用
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Vec<u8>> {
        self.data.get_mut(index)
    }

    /// 在指定位置插入元素
    pub fn insert(&mut self, index: usize, data: Vec<u8>) -> Result<(), ExecError> {
        if index > self.data.len() {
            return Err(ExecError::StackIndexOutOfBounds);
        }
        self.data.insert(index, data);
        Ok(())
    }

    /// 移除指定位置的元素
    pub fn remove(&mut self, index: usize) -> Result<Vec<u8>, ExecError> {
        if index >= self.data.len() {
            return Err(ExecError::StackIndexOutOfBounds);
        }
        Ok(self.data.remove(index))
    }

    /// 清空栈
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// 获取栈的引用
    pub fn as_ref(&self) -> &[Vec<u8>] {
        &self.data
    }

    /// 获取栈的可变引用
    pub fn as_mut(&mut self) -> &mut [Vec<u8>] {
        &mut self.data
    }

    /// 将栈转换为Vec
    pub fn into_vec(self) -> Vec<Vec<u8>> {
        self.data
    }

    /// 反转栈中元素的顺序
    pub fn reverse(&mut self) {
        self.data.reverse();
    }

    /// 交换栈顶两个元素
    pub fn swap_top(&mut self) -> Result<(), ExecError> {
        if self.data.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let len = self.data.len();
        self.data.swap(len - 1, len - 2);
        Ok(())
    }

    /// 复制栈顶元素
    pub fn dup_top(&mut self) -> Result<(), ExecError> {
        let top = self.top().ok_or(ExecError::StackUnderflow)?;
        self.push(top.to_vec());
        Ok(())
    }

    /// 删除栈顶元素
    pub fn drop_top(&mut self) -> Result<(), ExecError> {
        self.pop()?;
        Ok(())
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<Vec<u8>>> for Stack {
    fn from(data: Vec<Vec<u8>>) -> Self {
        Stack { data }
    }
}

impl From<Vec<u8>> for Stack {
    fn from(data: Vec<u8>) -> Self {
        Stack { data: vec![data] }
    }
}

impl From<&[u8]> for Stack {
    fn from(data: &[u8]) -> Self {
        Stack { data: vec![data.to_vec()] }
    }
}

/// Tondi脚本结构
#[derive(Debug, Clone)]
pub struct TondiScript {
    data: Vec<u8>,
}

impl TondiScript {
    /// 从字节数据创建脚本
    pub fn new(data: Vec<u8>) -> Self {
        TondiScript { data }
    }

    /// 从十六进制字符串创建脚本
    pub fn from_hex(hex: &str) -> Result<Self, ExecError> {
        let data = hex::decode(hex).map_err(|_| ExecError::InvalidHex)?;
        Ok(TondiScript { data })
    }

    /// 获取脚本的字节数据
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// 获取脚本的长度
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 检查脚本是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 将脚本转换为Vec<u8>
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl From<Vec<u8>> for TondiScript {
    fn from(data: Vec<u8>) -> Self {
        TondiScript { data }
    }
}

impl From<&[u8]> for TondiScript {
    fn from(data: &[u8]) -> Self {
        TondiScript { data: data.to_vec() }
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

/// 条件栈，用于处理条件执行
#[derive(Debug, Clone)]
pub struct ConditionStack {
    stack: Vec<bool>,
}

impl ConditionStack {
    /// 创建新的条件栈
    pub fn new() -> Self {
        ConditionStack { stack: Vec::new() }
    }

    /// 推入条件
    pub fn push(&mut self, condition: bool) {
        self.stack.push(condition);
    }

    /// 弹出条件
    pub fn pop(&mut self) -> Option<bool> {
        self.stack.pop()
    }

    /// 获取栈顶条件
    pub fn top(&self) -> Option<bool> {
        self.stack.last().copied()
    }

    /// 检查栈是否为空
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// 获取栈的大小
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// 清空栈
    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}
