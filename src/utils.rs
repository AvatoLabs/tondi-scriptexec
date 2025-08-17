use crate::{data_structures::ConditionStack, error::ExecError};

/// 读取脚本整数
pub fn read_scriptint(data: &[u8], max_size: usize, require_minimal: bool) -> Result<i64, ExecError> {
    if data.is_empty() {
        return Ok(0);
    }

    if data.len() > max_size {
        return Err(ExecError::ScriptError("整数数据过大".to_string()));
    }

    if require_minimal && data.len() > 0 {
        // 检查最小编码
        if data.len() == 1 && data[0] == 0x80 {
            return Ok(0);
        }
        if data.len() == 1 && data[0] == 0 {
            return Ok(0);
        }
        if data.len() > 1 {
            let last_byte = data[data.len() - 1];
            if last_byte == 0x00 && (data[data.len() - 2] & 0x80) == 0 {
                return Err(ExecError::ScriptError("非最小编码".to_string()));
            }
            if last_byte == 0x80 && (data[data.len() - 2] & 0x80) != 0 {
                return Err(ExecError::ScriptError("非最小编码".to_string()));
            }
        }
    }

    let mut result: i64 = 0;
    let mut shift: u32 = 0;

    for &byte in data {
        result |= (byte as i64 & 0xFF) << shift;
        shift += 8;
    }

    // 处理负数
    if data.len() > 0 && (data[data.len() - 1] & 0x80) != 0 {
        result -= 1 << shift;
    }

    Ok(result)
}

/// 将整数转换为脚本字节
pub fn scriptint_to_vec(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }

    let mut result = Vec::new();
    let mut abs_value = value.abs();

    while abs_value > 0 {
        result.push((abs_value & 0xFF) as u8);
        abs_value >>= 8;
    }

    // 处理负数
    if value < 0 {
        if result.len() > 0 && (result[result.len() - 1] & 0x80) != 0 {
            result.push(0x80);
        } else if result.len() > 0 {
            let last_index = result.len() - 1;
            result[last_index] |= 0x80;
        }
    } else if result.len() > 0 && (result[result.len() - 1] & 0x80) != 0 {
        result.push(0x00);
    }

    result
}

/// 检查数据是否为最小编码
pub fn is_minimal_push(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    if data.len() == 1 {
        return data[0] != 0x80;
    }

    if data.len() == 1 && data[0] == 0 {
        return true;
    }

    // 检查前导零
    if data.len() > 1 && data[0] == 0x00 && (data[1] & 0x80) == 0 {
        return false;
    }

    // 检查前导0x80
    if data.len() > 1 && data[0] == 0x80 && (data[1] & 0x80) != 0 {
        return false;
    }

    true
}

/// 计算哈希160（SHA256 + RIPEMD160）
pub fn hash160(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use ripemd::Ripemd160;

    let sha256_hash = Sha256::digest(data);
    let ripemd160_hash = Ripemd160::new().chain_update(&sha256_hash).finalize();
    ripemd160_hash.to_vec()
}

/// 计算SHA256哈希
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hash.to_vec()
}

/// 计算双重SHA256哈希
pub fn sha256d(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    second_hash.to_vec()
}

/// 计算RIPEMD160哈希
pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    use ripemd::Ripemd160;
    use ripemd::digest::Digest;
    let hash = Ripemd160::new().chain_update(data).finalize();
    hash.to_vec()
}

/// 计算Blake3哈希
pub fn blake3(data: &[u8], output_len: usize) -> Vec<u8> {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    let output = hasher.finalize();
    output.as_bytes()[..output_len].to_vec()
}

/// 检查公钥是否有效
pub fn is_valid_public_key(pubkey: &[u8]) -> bool {
    if pubkey.len() != 33 && pubkey.len() != 65 {
        return false;
    }

    if pubkey.len() == 33 {
        // 压缩公钥
        if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
            return false;
        }
    } else if pubkey.len() == 65 {
        // 未压缩公钥
        if pubkey[0] != 0x04 {
            return false;
        }
    }

    true
}

/// 检查签名是否有效
pub fn is_valid_signature(signature: &[u8]) -> bool {
    if signature.len() < 2 {
        return false;
    }

    // 检查长度字节
    let len = signature[0] as usize;
    if len != signature.len() - 1 {
        return false;
    }

    // 检查签名类型
    if signature.len() > 1 {
        let sig_type = signature[1];
        if sig_type != 0x30 {
            return false;
        }
    }

    true
}

/// 条件栈管理器
pub struct ConditionStackManager {
    stack: ConditionStack,
}

impl ConditionStackManager {
    /// 创建新的条件栈管理器
    pub fn new() -> Self {
        ConditionStackManager {
            stack: ConditionStack::new(),
        }
    }

    /// 推入条件
    pub fn push_condition(&mut self, condition: bool) {
        self.stack.push(condition);
    }

    /// 弹出条件
    pub fn pop_condition(&mut self) -> Option<bool> {
        self.stack.pop()
    }

    /// 获取当前条件
    pub fn current_condition(&self) -> bool {
        self.stack.top().unwrap_or(true)
    }

    /// 检查是否应该执行
    pub fn should_execute(&self) -> bool {
        self.stack.top().unwrap_or(true)
    }

    /// 清空条件栈
    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

impl Default for ConditionStackManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 字节数组工具函数
pub mod bytes {
    use super::*;

    /// 连接两个字节数组
    pub fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(a.len() + b.len());
        result.extend_from_slice(a);
        result.extend_from_slice(b);
        result
    }

    /// 反转字节数组
    pub fn reverse(data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        result.reverse();
        result
    }

    /// 检查字节数组是否全为零
    pub fn is_zero(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }

    /// 检查字节数组是否全为指定值
    pub fn is_all(data: &[u8], value: u8) -> bool {
        data.iter().all(|&b| b == value)
    }
}
