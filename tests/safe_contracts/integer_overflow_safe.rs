// SAFE: All arithmetic uses checked math
use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
}

#[program]
pub mod token_vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // SAFE: checked_add returns None on overflow
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        // SAFE: checked multiply for fee calculation
        let fee = amount
            .checked_mul(3)
            .ok_or(ErrorCode::Overflow)?
            .checked_div(100)
            .ok_or(ErrorCode::Overflow)?;

        // SAFE: checked_sub returns None on underflow
        vault.available = vault.total_deposited
            .checked_sub(fee)
            .ok_or(ErrorCode::Underflow)?;

        Ok(())
    }

    pub fn calculate_reward(base: u64, multiplier: u64) -> Option<u64> {
        // SAFE: returns None instead of wrapping
        base.checked_mul(multiplier)
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub total_deposited: u64,
    pub available: u64,
}
