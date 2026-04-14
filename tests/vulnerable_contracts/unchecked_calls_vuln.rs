// VULNERABLE: Return values of external calls are discarded
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
    system_instruction,
};

pub fn process(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let from = next_account_info(accounts_iter)?;
    let to   = next_account_info(accounts_iter)?;

    // VULNERABLE: return value discarded — if this fails, execution continues
    invoke(
        &system_instruction::transfer(from.key, to.key, amount),
        &[from.clone(), to.clone()],
    );

    // VULNERABLE: another unchecked call
    invoke(
        &system_instruction::transfer(from.key, to.key, 1000),
        &[from.clone(), to.clone()],
    );

    Ok(())
}
