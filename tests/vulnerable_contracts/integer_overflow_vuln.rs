// VULNERABLE: Raw arithmetic without checked math — wraps on overflow
use anchor_lang::prelude::*;

#[program]
pub mod token_vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // VULNERABLE: raw addition — overflows silently in release builds
        vault.total_deposited = vault.total_deposited + amount;

        // VULNERABLE: raw multiplication
        let fee = amount * 3 / 100;

        // VULNERABLE: raw subtraction — can underflow
        vault.available = vault.total_deposited - fee;

        Ok(())
    }

    pub fn calculate_reward(base: u64, multiplier: u64) -> u64 {
        // VULNERABLE: no overflow check on multiplication
        base * multiplier
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
