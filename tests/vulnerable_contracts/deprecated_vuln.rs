// VULNERABLE: Multiple deprecated patterns present
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

pub fn process(accounts: &[AccountInfo]) -> ProgramResult {
    // DEPRECATED: direct spl_token instruction call
    spl_token::instruction::transfer(/* ... */);

    // BAD: unwrap() in on-chain code panics on failure
    let value: u64 = some_option().unwrap();

    // BAD: panic! causes abrupt failure with no error code
    if value == 0 {
        panic!("Value must not be zero");
    }

    // BAD: todo!() will always panic
    todo!("Implement this function");
}

fn some_option() -> Option<u64> {
    Some(42)
}
