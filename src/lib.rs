extern crate alloc;
extern crate core;

use crate::data_structures::{Stack, TondiScript, ConditionStack};
use crate::error::{ExecError, Result};
use crate::signatures::{SignatureVerifier, ScriptSignatureVerifier};
use crate::utils::{read_scriptint, scriptint_to_vec, hash160, sha256, sha256d, ripemd160, blake3};

#[cfg(feature = "serde")]
use serde;

#[macro_use]
mod macros;

mod utils;
mod signatures;
mod error;
mod data_structures;

#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "wasm")]
mod wasm;

/// 最大操作码数量
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// 最大脚本元素大小
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// 最大栈大小
pub const MAX_STACK_SIZE: usize = 1000;

/// 序列锁定时间禁用标志
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// 验证权重偏移（Tapscript专用）
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// 每个通过签名的验证权重（Tapscript专用）
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

/// 多重签名的最大公钥数量
pub const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

/// 实验性功能配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Experimental {
    /// 启用实验性的OP_CAT实现
    pub op_cat: bool,
    /// 启用实验性的OP_MUL实现
    pub op_mul: bool,
    /// 启用实验性的OP_DIV实现
    pub op_div: bool,
}

/// 执行选项配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// 要求数据推送使用最小编码
    pub require_minimal: bool,
    /// 验证OP_CHECKLOCKTIMEVERIFY
    pub verify_cltv: bool,
    /// 验证OP_CHECKSEQUENCEVERIFY
    pub verify_csv: bool,
    /// 验证条件语句使用最小编码
    pub verify_minimal_if: bool,
    /// 强制执行1000个栈项的限制
    pub enforce_stack_limit: bool,
    /// 实验性功能
    pub experimental: Experimental,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            require_minimal: true,
            verify_cltv: true,
            verify_csv: true,
            verify_minimal_if: true,
            enforce_stack_limit: true,
            experimental: Experimental {
                op_cat: true,
                op_mul: false,
                op_div: false,
            },
        }
    }
}

/// 执行上下文
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCtx {
    /// 传统脚本
    Legacy,
    /// 隔离见证v0
    SegwitV0,
    /// Tapscript
    Tapscript,
}

/// 脚本执行器
pub struct TondiScriptExecutor {
    /// 主栈
    stack: Stack,
    /// 备用栈
    altstack: Stack,
    /// 条件栈
    condition_stack: ConditionStack,
    /// 执行选项
    options: Options,
    /// 执行上下文
    ctx: ExecCtx,
    /// 操作码计数器
    op_count: usize,
    /// 签名验证器
    sig_verifier: SignatureVerifier,
    /// 脚本签名验证器
    script_sig_verifier: ScriptSignatureVerifier,
}

impl TondiScriptExecutor {
    /// 创建新的脚本执行器
    pub fn new(ctx: ExecCtx, options: Options) -> Self {
        TondiScriptExecutor {
            stack: Stack::new(),
            altstack: Stack::new(),
            condition_stack: ConditionStack::new(),
            options,
            ctx,
            op_count: 0,
            sig_verifier: SignatureVerifier::new(),
            script_sig_verifier: ScriptSignatureVerifier::new(),
        }
    }

    /// 执行脚本
    pub fn execute(&mut self, script: &TondiScript) -> Result<()> {
        let script_bytes = script.as_bytes();
        let mut pc = 0; // 程序计数器

        while pc < script_bytes.len() {
            if self.op_count >= MAX_OPS_PER_SCRIPT {
                return Err(ExecError::ScriptError("操作码数量超限".to_string()));
            }

            let opcode = script_bytes[pc];
            pc += 1;

            // 处理数据推送
            if opcode <= 75 {
                if pc + opcode as usize <= script_bytes.len() {
                    let data = script_bytes[pc..pc + opcode as usize].to_vec();
                    self.stack.push(data);
                    pc += opcode as usize;
                    continue;
                } else {
                    return Err(ExecError::ScriptError("数据推送长度不足".to_string()));
                }
            }

            // 处理操作码
            self.execute_opcode(opcode)?;
            self.op_count += 1;
        }

        Ok(())
    }

    /// 执行单个操作码
    fn execute_opcode(&mut self, opcode: u8) -> Result<()> {
        match opcode {
            // 常量操作码
            0x00 => self.op_0()?,
            0x51..=0x60 => self.op_push_number(opcode - 0x50)?,
            0x4f => self.op_1negate()?,

            // 栈操作
            0x76 => self.op_dup()?,
            0x77 => self.op_nip()?,
            0x78 => self.op_over()?,
            0x79 => self.op_pick()?,
            0x7a => self.op_roll()?,
            0x7b => self.op_rot()?,
            0x7c => self.op_swap()?,
            0x7d => self.op_tuck()?,
            0x6d => self.op_2drop()?,
            0x6e => self.op_2dup()?,
            0x6f => self.op_3dup()?,
            0x70 => self.op_2over()?,
            0x71 => self.op_2rot()?,
            0x72 => self.op_2swap()?,

            // 条件语句
            0x63 => self.op_if()?,
            0x67 => self.op_else()?,
            0x68 => self.op_endif()?,

            // 逻辑操作
            0x87 => self.op_equal()?,
            0x88 => self.op_equalverify()?,
            0x69 => self.op_verify()?,
            0x9a => self.op_booland()?,
            0x9b => self.op_boolor()?,
            0x9c => self.op_numequal()?,
            0x9d => self.op_numequalverify()?,
            0x9e => self.op_numnotequal()?,
            0x9f => self.op_lessthan()?,
            0xa0 => self.op_greaterthan()?,
            0xa1 => self.op_lessthanorequal()?,
            0xa2 => self.op_greaterthanorequal()?,
            0xa3 => self.op_min()?,
            0xa4 => self.op_max()?,

            // 算术操作
            0x93 => self.op_add()?,
            0x94 => self.op_sub()?,
            0x95 => self.op_mul()?,
            0x96 => self.op_div()?,
            0x97 => self.op_mod()?,
            0x98 => self.op_lshift()?,
            0x99 => self.op_rshift()?,

            // 哈希操作
            0xa6 => self.op_ripemd160()?,
            0xa7 => self.op_sha1()?,
            0xa8 => self.op_sha256()?,
            0xa9 => self.op_hash160()?,
            0xaa => self.op_hash256()?,
            0xab => self.op_codeseparator()?,

            // 签名操作
            0xac => self.op_checksig()?,
            0xad => self.op_checksigverify()?,
            0xae => self.op_checkmultisig()?,
            0xaf => self.op_checkmultisigverify()?,

            // 时间锁定
            0xb1 => self.op_checklocktimeverify()?,
            0xb2 => self.op_checksequenceverify()?,

            // 其他
            0x6a => self.op_return()?,
            0x75 => self.op_depth()?,
            0x7e => self.op_size()?,
            0x7f => self.op_invert()?,
            0x80 => self.op_and()?,
            0x81 => self.op_or()?,
            0x82 => self.op_xor()?,
            0x83 => self.op_equal()?,
            0x84 => self.op_equalverify()?,
            0x85 => self.op_1add()?,
            0x86 => self.op_1sub()?,
            0x8b => self.op_2mul()?,
            0x8c => self.op_2div()?,
            0x8d => self.op_negate()?,
            0x8e => self.op_abs()?,
            0x8f => self.op_not()?,
            0x90 => self.op_0notequal()?,

            _ => return Err(ExecError::OpcodeError(format!("不支持的操作码: 0x{:02x}", opcode))),
        }

        Ok(())
    }

    // 常量操作码实现
    fn op_0(&mut self) -> Result<()> {
        self.stack.push(vec![]);
        Ok(())
    }

    fn op_push_number(&mut self, n: u8) -> Result<()> {
        self.stack.push(vec![n]);
        Ok(())
    }

    fn op_1negate(&mut self) -> Result<()> {
        self.stack.push(vec![0x81]);
        Ok(())
    }

    // 栈操作实现
    fn op_dup(&mut self) -> Result<()> {
        let item = self.stack.top().ok_or(ExecError::StackUnderflow)?;
        self.stack.push(item.to_vec());
        Ok(())
    }

    fn op_nip(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let top = self.stack.pop()?;
        let _ = self.stack.pop()?;
        self.stack.push(top);
        Ok(())
    }

    fn op_over(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let item = self.stack.get(self.stack.len() - 2).ok_or(ExecError::StackIndexOutOfBounds)?;
        self.stack.push(item.to_vec());
        Ok(())
    }

    fn op_pick(&mut self) -> Result<()> {
        let n = self.stack.pop()?;
        let index = read_scriptint(&n, 4, self.options.require_minimal)?;
        if index < 0 || index as usize >= self.stack.len() {
            return Err(ExecError::StackIndexOutOfBounds);
        }
        let item = self.stack.get(index as usize).ok_or(ExecError::StackIndexOutOfBounds)?;
        self.stack.push(item.to_vec());
        Ok(())
    }

    fn op_roll(&mut self) -> Result<()> {
        let n = self.stack.pop()?;
        let index = read_scriptint(&n, 4, self.options.require_minimal)?;
        if index < 0 || index as usize >= self.stack.len() {
            return Err(ExecError::StackIndexOutOfBounds);
        }
        let item = self.stack.remove(index as usize)?;
        self.stack.push(item);
        Ok(())
    }

    fn op_rot(&mut self) -> Result<()> {
        if self.stack.len() < 3 {
            return Err(ExecError::StackUnderflow);
        }
        let top = self.stack.pop()?;
        let second = self.stack.pop()?;
        let third = self.stack.pop()?;
        self.stack.push(second);
        self.stack.push(top);
        self.stack.push(third);
        Ok(())
    }

    fn op_swap(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let top = self.stack.pop()?;
        let second = self.stack.pop()?;
        self.stack.push(top);
        self.stack.push(second);
        Ok(())
    }

    fn op_tuck(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let top = self.stack.pop()?;
        let second = self.stack.pop()?;
        self.stack.push(top.clone());
        self.stack.push(second);
        self.stack.push(top);
        Ok(())
    }

    // 条件语句实现
    fn op_if(&mut self) -> Result<()> {
        let condition = self.stack.pop()?;
        let should_execute = !condition.is_empty() && condition[0] != 0;
        self.condition_stack.push(should_execute);
        Ok(())
    }

    fn op_else(&mut self) -> Result<()> {
        if let Some(condition) = self.condition_stack.pop() {
            self.condition_stack.push(!condition);
        }
        Ok(())
    }

    fn op_endif(&mut self) -> Result<()> {
        self.condition_stack.pop();
        Ok(())
    }

    // 逻辑操作实现
    fn op_equal(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let result = if a == b { 1 } else { 0 };
        self.stack.push(vec![result]);
        Ok(())
    }

    fn op_equalverify(&mut self) -> Result<()> {
        self.op_equal()?;
        self.op_verify()?;
        Ok(())
    }

    fn op_verify(&mut self) -> Result<()> {
        let item = self.stack.pop()?;
        if item.is_empty() || item[0] == 0 {
            return Err(ExecError::ScriptError("OP_VERIFY失败".to_string()));
        }
        Ok(())
    }

    // 哈希操作实现
    fn op_ripemd160(&mut self) -> Result<()> {
        let data = self.stack.pop()?;
        let hash = ripemd160(&data);
        self.stack.push(hash);
        Ok(())
    }

    fn op_sha1(&mut self) -> Result<()> {
        let data = self.stack.pop()?;
        // 注意：这里应该使用专门的SHA1实现
        let hash = sha256(&data); // 暂时使用SHA256作为占位符
        self.stack.push(hash);
        Ok(())
    }

    fn op_sha256(&mut self) -> Result<()> {
        let data = self.stack.pop()?;
        let hash = sha256(&data);
        self.stack.push(hash);
        Ok(())
    }

    fn op_hash160(&mut self) -> Result<()> {
        let data = self.stack.pop()?;
        let hash = hash160(&data);
        self.stack.push(hash);
        Ok(())
    }

    fn op_hash256(&mut self) -> Result<()> {
        let data = self.stack.pop()?;
        let hash = sha256d(&data);
        self.stack.push(hash);
        Ok(())
    }

    // 签名操作实现
    fn op_checksig(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let _pubkey_data = self.stack.pop()?;
        let _signature_data = self.stack.pop()?;

        // 这里应该实现实际的签名验证
        // 暂时返回成功
        self.stack.push(vec![1]);
        Ok(())
    }

    fn op_checksigverify(&mut self) -> Result<()> {
        self.op_checksig()?;
        self.op_verify()?;
        Ok(())
    }

    fn op_checkmultisig(&mut self) -> Result<()> {
        // 实现多重签名验证
        // 暂时返回成功
        self.stack.push(vec![1]);
        Ok(())
    }

    fn op_checkmultisigverify(&mut self) -> Result<()> {
        self.op_checkmultisig()?;
        self.op_verify()?;
        Ok(())
    }

    // 时间锁定实现
    fn op_checklocktimeverify(&mut self) -> Result<()> {
        if !self.options.verify_cltv {
            return Ok(());
        }
        // 这里应该实现实际的CLTV验证
        // 暂时返回成功
        Ok(())
    }

    fn op_checksequenceverify(&mut self) -> Result<()> {
        if !self.options.verify_csv {
            return Ok(());
        }
        // 这里应该实现实际的CSV验证
        // 暂时返回成功
        Ok(())
    }

    // 其他操作码实现
    fn op_return(&mut self) -> Result<()> {
        return Err(ExecError::ScriptError("OP_RETURN执行".to_string()));
    }

    fn op_depth(&mut self) -> Result<()> {
        let depth = self.stack.len() as i64;
        self.stack.push(scriptint_to_vec(depth));
        Ok(())
    }

    fn op_size(&mut self) -> Result<()> {
        let item = self.stack.top().ok_or(ExecError::StackUnderflow)?;
        let size = item.len() as i64;
        self.stack.push(scriptint_to_vec(size));
        Ok(())
    }

    // 添加缺失的操作码实现
    fn op_2drop(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        self.stack.pop()?;
        self.stack.pop()?;
        Ok(())
    }

    fn op_2dup(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let second = self.stack.get(self.stack.len() - 2).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        let first = self.stack.get(self.stack.len() - 1).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        self.stack.push(second);
        self.stack.push(first);
        Ok(())
    }

    fn op_3dup(&mut self) -> Result<()> {
        if self.stack.len() < 3 {
            return Err(ExecError::StackUnderflow);
        }
        let third = self.stack.get(self.stack.len() - 3).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        let second = self.stack.get(self.stack.len() - 2).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        let first = self.stack.get(self.stack.len() - 1).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        self.stack.push(third);
        self.stack.push(second);
        self.stack.push(first);
        Ok(())
    }

    fn op_2over(&mut self) -> Result<()> {
        if self.stack.len() < 4 {
            return Err(ExecError::StackUnderflow);
        }
        let fourth = self.stack.get(self.stack.len() - 4).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        let third = self.stack.get(self.stack.len() - 3).ok_or(ExecError::StackIndexOutOfBounds)?.to_vec();
        self.stack.push(fourth);
        self.stack.push(third);
        Ok(())
    }

    fn op_2rot(&mut self) -> Result<()> {
        if self.stack.len() < 6 {
            return Err(ExecError::StackUnderflow);
        }
        let sixth = self.stack.pop()?;
        let fifth = self.stack.pop()?;
        let fourth = self.stack.pop()?;
        let third = self.stack.pop()?;
        let second = self.stack.pop()?;
        let first = self.stack.pop()?;
        self.stack.push(fourth);
        self.stack.push(third);
        self.stack.push(second);
        self.stack.push(first);
        self.stack.push(sixth);
        self.stack.push(fifth);
        Ok(())
    }

    fn op_2swap(&mut self) -> Result<()> {
        if self.stack.len() < 4 {
            return Err(ExecError::StackUnderflow);
        }
        let fourth = self.stack.pop()?;
        let third = self.stack.pop()?;
        let second = self.stack.pop()?;
        let first = self.stack.pop()?;
        self.stack.push(third);
        self.stack.push(fourth);
        self.stack.push(first);
        self.stack.push(second);
        Ok(())
    }

    // 占位符实现
    fn op_booland(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let result = if !a.is_empty() && !b.is_empty() { 1 } else { 0 };
        self.stack.push(vec![result]);
        Ok(())
    }

    fn op_boolor(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let result = if !a.is_empty() || !b.is_empty() { 1 } else { 0 };
        self.stack.push(vec![result]);
        Ok(())
    }

    fn op_numequal(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num == b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_numequalverify(&mut self) -> Result<()> {
        self.op_numequal()?;
        self.op_verify()?;
        Ok(())
    }

    fn op_numnotequal(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num != b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_lessthan(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num < b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_greaterthan(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num > b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_lessthanorequal(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num <= b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_greaterthanorequal(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num >= b_num { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_min(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num < b_num { a_num } else { b_num };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_max(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = if a_num > b_num { a_num } else { b_num };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    // 算术操作占位符
    fn op_add(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num + b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_sub(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num - b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_mul(&mut self) -> Result<()> {
        if !self.options.experimental.op_mul {
            return Err(ExecError::OpcodeError("OP_MUL未启用".to_string()));
        }
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num * b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_div(&mut self) -> Result<()> {
        if !self.options.experimental.op_div {
            return Err(ExecError::OpcodeError("OP_DIV未启用".to_string()));
        }
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        if b_num == 0 {
            return Err(ExecError::ScriptError("除零错误".to_string()));
        }
        let result = a_num / b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_mod(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        if b_num == 0 {
            return Err(ExecError::ScriptError("模零错误".to_string()));
        }
        let result = a_num % b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_lshift(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        if b_num < 0 || b_num > 31 {
            return Err(ExecError::ScriptError("移位值超出范围".to_string()));
        }
        let result = a_num << b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_rshift(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        if b_num < 0 || b_num > 31 {
            return Err(ExecError::ScriptError("移位值超出范围".to_string()));
        }
        let result = a_num >> b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_codeseparator(&mut self) -> Result<()> {
        // 代码分隔符，暂时不实现
        Ok(())
    }

    // 其他操作码占位符
    fn op_invert(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = !a_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_and(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num & b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_or(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num | b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_xor(&mut self) -> Result<()> {
        if self.stack.len() < 2 {
            return Err(ExecError::StackUnderflow);
        }
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let b_num = read_scriptint(&b, 4, self.options.require_minimal)?;
        let result = a_num ^ b_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_1add(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = a_num + 1;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_1sub(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = a_num - 1;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_2mul(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = a_num * 2;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_2div(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = a_num / 2;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_negate(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = -a_num;
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_abs(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = a_num.abs();
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_not(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = if a_num == 0 { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    fn op_0notequal(&mut self) -> Result<()> {
        if self.stack.len() < 1 {
            return Err(ExecError::StackUnderflow);
        }
        let a = self.stack.pop()?;
        let a_num = read_scriptint(&a, 4, self.options.require_minimal)?;
        let result = if a_num != 0 { 1 } else { 0 };
        self.stack.push(scriptint_to_vec(result));
        Ok(())
    }

    // 获取栈的引用
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// 获取备用栈的引用
    pub fn altstack(&self) -> &Stack {
        &self.altstack
    }

    /// 获取栈的可变引用
    pub fn stack_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    /// 获取备用栈的可变引用
    pub fn altstack_mut(&mut self) -> &mut Stack {
        &mut self.altstack
    }

    /// 获取操作码计数
    pub fn op_count(&self) -> usize {
        self.op_count
    }

    /// 检查是否应该执行当前操作码
    fn should_execute(&self) -> bool {
        self.condition_stack.top().unwrap_or(true)
    }



    /// 执行单个操作码（内部方法）
    fn execute_opcode_internal(&mut self, opcode: u8) -> Result<()> {
        match opcode {
            // 常量操作码
            0x00 => self.op_0()?,
            0x51..=0x60 => self.op_push_number(opcode - 0x50)?,
            0x4f => self.op_1negate()?,

            // 栈操作
            0x76 => self.op_dup()?,
            0x77 => self.op_nip()?,
            0x78 => self.op_over()?,
            0x79 => self.op_pick()?,
            0x7a => self.op_roll()?,
            0x7b => self.op_rot()?,
            0x7c => self.op_swap()?,
            0x7d => self.op_tuck()?,
            0x6d => self.op_2drop()?,
            0x6e => self.op_2dup()?,
            0x6f => self.op_3dup()?,
            0x70 => self.op_2over()?,
            0x71 => self.op_2rot()?,
            0x72 => self.op_2swap()?,

            // 条件语句
            0x63 => self.op_if()?,
            0x67 => self.op_else()?,
            0x68 => self.op_endif()?,

            // 逻辑操作
            0x87 => self.op_equal()?,
            0x88 => self.op_equalverify()?,
            0x69 => self.op_verify()?,
            0x9a => self.op_booland()?,
            0x9b => self.op_boolor()?,
            0x9c => self.op_numequal()?,
            0x9d => self.op_numequalverify()?,
            0x9e => self.op_numnotequal()?,
            0x9f => self.op_lessthan()?,
            0xa0 => self.op_greaterthan()?,
            0xa1 => self.op_lessthanorequal()?,
            0xa2 => self.op_greaterthanorequal()?,
            0xa3 => self.op_min()?,
            0xa4 => self.op_max()?,

            // 算术操作
            0x93 => self.op_add()?,
            0x94 => self.op_sub()?,
            0x95 => self.op_mul()?,
            0x96 => self.op_div()?,
            0x97 => self.op_mod()?,
            0x98 => self.op_lshift()?,
            0x99 => self.op_rshift()?,

            // 哈希操作
            0xa6 => self.op_ripemd160()?,
            0xa7 => self.op_sha1()?,
            0xa8 => self.op_sha256()?,
            0xa9 => self.op_hash160()?,
            0xaa => self.op_hash256()?,
            0xab => self.op_codeseparator()?,

            // 签名操作
            0xac => self.op_checksig()?,
            0xad => self.op_checksigverify()?,
            0xae => self.op_checkmultisig()?,
            0xaf => self.op_checkmultisigverify()?,

            // 时间锁定
            0xb1 => self.op_checklocktimeverify()?,
            0xb2 => self.op_checksequenceverify()?,

            // 其他
            0x6a => self.op_return()?,
            0x75 => self.op_depth()?,
            0x7e => self.op_size()?,
            0x7f => self.op_invert()?,
            0x80 => self.op_and()?,
            0x81 => self.op_or()?,
            0x82 => self.op_xor()?,
            0x83 => self.op_equal()?,
            0x84 => self.op_equalverify()?,
            0x85 => self.op_1add()?,
            0x86 => self.op_1sub()?,
            0x8b => self.op_2mul()?,
            0x8c => self.op_2div()?,
            0x8d => self.op_negate()?,
            0x8e => self.op_abs()?,
            0x8f => self.op_not()?,
            0x90 => self.op_0notequal()?,

            _ => return Err(ExecError::OpcodeError(format!("不支持的操作码: 0x{:02x}", opcode))),
        }

        Ok(())
    }
}

/// 创建新的脚本执行器
pub fn create_executor(ctx: ExecCtx, options: Options) -> TondiScriptExecutor {
    TondiScriptExecutor::new(ctx, options)
}

/// 执行脚本的便捷函数
pub fn execute_script(script: &TondiScript, ctx: ExecCtx, options: Options) -> Result<()> {
    let mut executor = create_executor(ctx, options);
    executor.execute(script)
}

/// 执行脚本并返回结果
pub fn execute_script_with_result(script: &TondiScript, ctx: ExecCtx, options: Options) -> Result<Stack> {
    let mut executor = create_executor(ctx, options);
    executor.execute(script)?;
    Ok(executor.stack().clone())
}


