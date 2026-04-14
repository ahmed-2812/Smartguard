// VULNERABLE: withdraw() and close() have no authorisation checks
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    // VULNERABLE: No signer check — any account can call this
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;
        // transfer funds ...
        Ok(())
    }

    // VULNERABLE: No authority check — anyone can close the vault
    pub fn close(ctx: Context<Close>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.is_closed = true;
        Ok(())
    }

    // VULNERABLE: Anyone can drain the treasury
    pub fn drain(ctx: Context<Drain>) -> Result<()> {
        // sends all lamports to caller
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct Drain<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub is_closed: bool,
}
