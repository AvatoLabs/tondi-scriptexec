use crate::{data_structures::TondiScript, error::ExecError, utils};
use secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey};

/// 签名类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureType {
    /// ECDSA签名
    Ecdsa,
    /// Schnorr签名
    Schnorr,
}

/// 签名数据
#[derive(Debug, Clone)]
pub struct Signature {
    /// 签名类型
    pub sig_type: SignatureType,
    /// 签名数据
    pub data: Vec<u8>,
    /// 哈希类型
    pub hash_type: u8,
}

impl Signature {
    /// 创建新的ECDSA签名
    pub fn new_ecdsa(data: Vec<u8>, hash_type: u8) -> Self {
        Signature {
            sig_type: SignatureType::Ecdsa,
            data,
            hash_type,
        }
    }

    /// 创建新的Schnorr签名
    pub fn new_schnorr(data: Vec<u8>, hash_type: u8) -> Self {
        Signature {
            sig_type: SignatureType::Schnorr,
            data,
            hash_type,
        }
    }

    /// 从字节数据创建签名
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ExecError> {
        if data.len() < 2 {
            return Err(ExecError::InvalidSignature);
        }

        let hash_type = data[data.len() - 1];
        let sig_data = data[..data.len() - 1].to_vec();

        // 尝试解析为ECDSA签名
        if let Ok(_) = secp256k1::ecdsa::Signature::from_der(&sig_data) {
            return Ok(Signature::new_ecdsa(sig_data, hash_type));
        }

        // 尝试解析为Schnorr签名
        if sig_data.len() == 64 {
            return Ok(Signature::new_schnorr(sig_data, hash_type));
        }

        Err(ExecError::InvalidSignature)
    }

    /// 获取签名的字节表示
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.data.clone();
        result.push(self.hash_type);
        result
    }

    /// 检查签名是否有效
    pub fn is_valid(&self) -> bool {
        match self.sig_type {
            SignatureType::Ecdsa => {
                if self.data.len() < 2 {
                    return false;
                }
                // 检查DER编码
                secp256k1::ecdsa::Signature::from_der(&self.data).is_ok()
            }
            SignatureType::Schnorr => {
                self.data.len() == 64
            }
        }
    }
}

/// 公钥数据
#[derive(Debug, Clone)]
pub struct PublicKeyData {
    /// 公钥类型
    pub key_type: SignatureType,
    /// 公钥数据
    pub data: Vec<u8>,
}

impl PublicKeyData {
    /// 创建新的ECDSA公钥
    pub fn new_ecdsa(data: Vec<u8>) -> Result<Self, ExecError> {
        if !utils::is_valid_public_key(&data) {
            return Err(ExecError::InvalidPublicKey);
        }
        Ok(PublicKeyData {
            key_type: SignatureType::Ecdsa,
            data,
        })
    }

    /// 创建新的Schnorr公钥
    pub fn new_schnorr(data: Vec<u8>) -> Result<Self, ExecError> {
        if data.len() != 32 {
            return Err(ExecError::InvalidPublicKey);
        }
        Ok(PublicKeyData {
            key_type: SignatureType::Schnorr,
            data,
        })
    }

    /// 从字节数据创建公钥
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ExecError> {
        if data.len() == 32 {
            // 可能是Schnorr公钥
            Self::new_schnorr(data)
        } else if data.len() == 33 || data.len() == 65 {
            // 可能是ECDSA公钥
            Self::new_ecdsa(data)
        } else {
            Err(ExecError::InvalidPublicKey)
        }
    }

    /// 获取公钥的字节表示
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// 检查公钥是否有效
    pub fn is_valid(&self) -> bool {
        match self.key_type {
            SignatureType::Ecdsa => utils::is_valid_public_key(&self.data),
            SignatureType::Schnorr => self.data.len() == 32,
        }
    }
}

/// 签名验证器
pub struct SignatureVerifier {
    secp: Secp256k1<secp256k1::All>,
}

impl SignatureVerifier {
    /// 创建新的签名验证器
    pub fn new() -> Self {
        SignatureVerifier {
            secp: Secp256k1::new(),
        }
    }

    /// 验证ECDSA签名
    pub fn verify_ecdsa(
        &self,
        signature: &Signature,
        pubkey: &PublicKeyData,
        message: &[u8],
    ) -> Result<bool, ExecError> {
        if signature.sig_type != SignatureType::Ecdsa {
            return Err(ExecError::InvalidSignature);
        }

        if pubkey.key_type != SignatureType::Ecdsa {
            return Err(ExecError::InvalidPublicKey);
        }

        let sig = secp256k1::ecdsa::Signature::from_der(&signature.data)
            .map_err(|_| ExecError::InvalidSignature)?;

        let pubkey_secp = PublicKey::from_slice(&pubkey.data)
            .map_err(|_| ExecError::InvalidPublicKey)?;

        let msg = Message::from_digest_slice(message)
            .map_err(|_| ExecError::InvalidSignature)?;

        let result = self.secp.verify_ecdsa(msg, &sig, &pubkey_secp);
        Ok(result.is_ok())
    }

    /// 验证Schnorr签名
    pub fn verify_schnorr(
        &self,
        signature: &Signature,
        pubkey: &PublicKeyData,
        message: &[u8],
    ) -> Result<bool, ExecError> {
        if signature.sig_type != SignatureType::Schnorr {
            return Err(ExecError::InvalidSignature);
        }

        if pubkey.key_type != SignatureType::Schnorr {
            return Err(ExecError::InvalidPublicKey);
        }

        let sig = secp256k1::schnorr::Signature::from_slice(&signature.data)
            .map_err(|_| ExecError::InvalidSignature)?;

        let pubkey_xonly = XOnlyPublicKey::from_slice(&pubkey.data)
            .map_err(|_| ExecError::InvalidPublicKey)?;

        let msg = Message::from_digest_slice(message)
            .map_err(|_| ExecError::InvalidSignature)?;

        let result = self.secp.verify_schnorr(&sig, &msg, &pubkey_xonly);
        Ok(result.is_ok())
    }

    /// 验证签名（自动检测类型）
    pub fn verify(
        &self,
        signature: &Signature,
        pubkey: &PublicKeyData,
        message: &[u8],
    ) -> Result<bool, ExecError> {
        match signature.sig_type {
            SignatureType::Ecdsa => self.verify_ecdsa(signature, pubkey, message),
            SignatureType::Schnorr => self.verify_schnorr(signature, pubkey, message),
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// 脚本签名验证器
pub struct ScriptSignatureVerifier {
    verifier: SignatureVerifier,
}

impl ScriptSignatureVerifier {
    /// 创建新的脚本签名验证器
    pub fn new() -> Self {
        ScriptSignatureVerifier {
            verifier: SignatureVerifier::new(),
        }
    }

    /// 验证脚本签名
    pub fn verify_script_signature(
        &self,
        script_sig: &TondiScript,
        script_pubkey: &TondiScript,
        tx_data: &[u8],
    ) -> Result<bool, ExecError> {
        // 这里需要实现具体的脚本签名验证逻辑
        // 暂时返回true作为占位符
        Ok(true)
    }

    /// 验证多重签名
    pub fn verify_multisig(
        &self,
        signatures: &[Signature],
        pubkeys: &[PublicKeyData],
        message: &[u8],
        required: usize,
    ) -> Result<bool, ExecError> {
        if signatures.len() < required {
            return Ok(false);
        }

        if pubkeys.len() < required {
            return Ok(false);
        }

        let mut valid_sigs = 0;
        let mut used_pubkeys = std::collections::HashSet::new();

        for sig in signatures {
            for (i, pubkey) in pubkeys.iter().enumerate() {
                if used_pubkeys.contains(&i) {
                    continue;
                }

                if self.verifier.verify(sig, pubkey, message)? {
                    used_pubkeys.insert(i);
                    valid_sigs += 1;
                    break;
                }
            }
        }

        Ok(valid_sigs >= required)
    }
}

impl Default for ScriptSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// 哈希类型常量
pub mod hash_types {
    pub const SIGHASH_ALL: u8 = 0x01;
    pub const SIGHASH_NONE: u8 = 0x02;
    pub const SIGHASH_SINGLE: u8 = 0x03;
    pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
}

/// 签名哈希计算器
pub struct SignatureHashCalculator;

impl SignatureHashCalculator {
    /// 计算签名哈希
    pub fn calculate_hash(
        tx_data: &[u8],
        script_code: &[u8],
        hash_type: u8,
    ) -> Result<Vec<u8>, ExecError> {
        // 这里需要实现具体的签名哈希计算逻辑
        // 暂时返回简单的哈希作为占位符
        Ok(utils::sha256d(tx_data))
    }

    /// 计算交易输入的签名哈希
    pub fn calculate_input_hash(
        tx_data: &[u8],
        input_index: usize,
        script_code: &[u8],
        hash_type: u8,
    ) -> Result<Vec<u8>, ExecError> {
        // 这里需要实现具体的输入签名哈希计算逻辑
        // 暂时返回简单的哈希作为占位符
        let mut data = Vec::new();
        data.extend_from_slice(&input_index.to_le_bytes());
        data.extend_from_slice(script_code);
        data.push(hash_type);
        Ok(utils::sha256d(&data))
    }
}
