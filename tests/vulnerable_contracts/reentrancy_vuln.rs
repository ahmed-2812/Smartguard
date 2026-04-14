// VULNERABLE: External call (invoke) before state update — reentrancy risk
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
    system_instruction,
};

pub fn withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;

    // VULNERABLE: Transfer happens BEFORE the balance is zeroed
    invoke(
        &system_instruction::transfer(vault.key, destination.key, amount),
        &[vault.clone(), destination.clone()],
    )?;

    // State update happens AFTER the external call — reentrancy window
    let mut vault_data = vault.try_borrow_mut_data()?;
    vault_data[0] = 0; // balance = 0

    Ok(())
}
