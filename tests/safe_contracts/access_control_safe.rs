// SAFE: withdraw() and close() enforce authority checks
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // SAFE: has_one constraint ensures authority matches vault.authority
        let vault = &mut ctx.accounts.vault;
        require!(
            ctx.accounts.authority.is_signer,
            ErrorCode::Unauthorized
        );
        vault.balance -= amount;
        Ok(())
    }

    pub fn close(ctx: Context<Close>) -> Result<()> {
        require!(
            ctx.accounts.authority.is_signer,
            ErrorCode::Unauthorized
        );
        let vault = &mut ctx.accounts.vault;
        vault.is_closed = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub is_closed: bool,
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("You are not authorized to perform this action.")]
    Unauthorized,
}
