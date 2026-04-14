// SAFE: All external call return values are propagated with ?
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

    // SAFE: ? propagates any error immediately
    invoke(
        &system_instruction::transfer(from.key, to.key, amount),
        &[from.clone(), to.clone()],
    )?;

    // SAFE: second call also checked
    invoke(
        &system_instruction::transfer(from.key, to.key, 1000),
        &[from.clone(), to.clone()],
    )?;

    Ok(())
}
