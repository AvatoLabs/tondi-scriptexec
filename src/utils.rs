use crate::{data_structures::ConditionStack, error::ExecError};
use tondi_hashes::{Hasher, TransactionHash};

/// 读取脚本整数
pub fn read_scriptint(
    data: &[u8],
    max_size: usize,
    require_minimal: bool,
) -> Result<i64, ExecError> {
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

/// 检查公钥是否有效
pub fn is_valid_public_key(data: &[u8]) -> bool {
    if data.len() != 33 && data.len() != 65 {
        return false;
    }

    if data.len() == 33 {
        // 压缩公钥
        data[0] == 0x02 || data[0] == 0x03
    } else {
        // 未压缩公钥
        data[0] == 0x04
    }
}

/// 计算RIPEMD160哈希 - 使用tondi中的实现
pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    // 使用TransactionHash作为替代，因为tondi主要使用BLAKE3
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// 计算SHA256哈希 - 使用tondi中的实现
pub fn sha256(data: &[u8]) -> Vec<u8> {
    // 使用TransactionHash作为替代，因为tondi主要使用BLAKE3
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// 计算双重SHA256哈希 - 使用tondi中的实现
pub fn sha256d(data: &[u8]) -> Vec<u8> {
    // 使用TransactionHash作为替代，因为tondi主要使用BLAKE3
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// 计算HASH160 (RIPEMD160(SHA256(data))) - 使用tondi中的实现
pub fn hash160(data: &[u8]) -> Vec<u8> {
    // 使用TransactionHash作为替代，因为tondi主要使用BLAKE3
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// 计算Blake3哈希 - 使用tondi中的实现
pub fn blake3(data: &[u8]) -> Vec<u8> {
    // 使用TransactionHash作为替代，因为tondi主要使用BLAKE3
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// 检查条件栈是否应该执行
pub fn should_execute(condition_stack: &ConditionStack) -> bool {
    condition_stack.is_empty() || condition_stack.top().unwrap_or(true)
}

/// 将字节数组转换为十六进制字符串
pub fn bytes_to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// 将十六进制字符串转换为字节数组
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ExecError> {
    hex::decode(hex).map_err(|_| ExecError::InvalidHex)
}

/// 检查字节数组是否全为零
pub fn is_zero(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

/// 检查字节数组是否全为0xFF
pub fn is_ones(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0xFF)
}

/// 将字节数组转换为大端序整数
pub fn bytes_to_int_be(data: &[u8]) -> u64 {
    let mut result = 0u64;
    for &byte in data {
        result = (result << 8) | byte as u64;
    }
    result
}

/// 将字节数组转换为小端序整数
pub fn bytes_to_int_le(data: &[u8]) -> u64 {
    let mut result = 0u64;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as u64) << (i * 8);
    }
    result
}

/// 将整数转换为大端序字节数组
pub fn int_to_bytes_be(value: u64, size: usize) -> Vec<u8> {
    let mut result = vec![0u8; size];
    for i in 0..size {
        result[i] = ((value >> ((size - 1 - i) * 8)) & 0xFF) as u8;
    }
    result
}

/// 将整数转换为小端序字节数组
pub fn int_to_bytes_le(value: u64, size: usize) -> Vec<u8> {
    let mut result = vec![0u8; size];
    for i in 0..size {
        result[i] = ((value >> (i * 8)) & 0xFF) as u8;
    }
    result
}
