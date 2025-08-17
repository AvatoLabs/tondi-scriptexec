/// 定义操作码的宏
#[macro_export]
macro_rules! define_opcode {
    ($name:ident, $code:expr, $description:expr) => {
        pub const $name: u8 = $code;
    };
}

/// 定义操作码组的宏
#[macro_export]
macro_rules! define_opcode_group {
    ($group_name:ident, { $($opcode:ident = $value:expr,)* }) => {
        pub mod $group_name {
            $(
                pub const $opcode: u8 = $value;
            )*
        }
    };
}

/// 定义脚本执行结果的宏
#[macro_export]
macro_rules! script_result {
    ($expr:expr) => {
        match $expr {
            Ok(result) => result,
            Err(e) => return Err(crate::ExecError::ScriptError(format!("{:?}", e))),
        }
    };
}

/// 定义栈操作的宏
#[macro_export]
macro_rules! stack_require {
    ($stack:expr, $count:expr) => {
        if $stack.len() < $count {
            return Err(crate::ExecError::StackUnderflow);
        }
    };
}

/// 定义条件执行的宏
#[macro_export]
macro_rules! conditional_execute {
    ($condition:expr, $block:block) => {
        if $condition {
            $block
        }
    };
}

/// 定义调试日志的宏
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!("[DEBUG] {}", format!($($arg)*));
    };
}

/// 定义性能计时的宏
#[macro_export]
macro_rules! time_operation {
    ($name:expr, $block:block) => {
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        debug_log!("{} took {:?}", $name, duration);
        result
    };
}
