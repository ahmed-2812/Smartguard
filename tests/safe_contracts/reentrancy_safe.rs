// SAFE: State is updated BEFORE the external call — no reentrancy window
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

    // SAFE: Zero the balance FIRST (Checks-Effects-Interactions)
    let mut vault_data = vault.try_borrow_mut_data()?;
    vault_data[0] = 0; // balance = 0
    drop(vault_data);   // release borrow before CPI

    // External call happens AFTER state has been committed
    invoke(
        &system_instruction::transfer(vault.key, destination.key, amount),
        &[vault.clone(), destination.clone()],
    )?;

    Ok(())
}
