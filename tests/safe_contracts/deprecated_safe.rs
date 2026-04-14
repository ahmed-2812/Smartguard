// SAFE: No deprecated patterns — modern APIs and proper error handling
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[program]
pub mod safe_transfer {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        // SAFE: Uses anchor_spl CPI helper, not deprecated spl_token directly
        let cpi_accounts = Transfer {
            from: ctx.accounts.from.to_account_info(),
            to:   ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        Ok(())
    }

    pub fn safe_division(numerator: u64, denominator: u64) -> Result<u64> {
        // SAFE: Returns a typed error instead of panicking
        if denominator == 0 {
            return Err(ErrorCode::DivisionByZero.into());
        }
        // SAFE: ok_or returns an error rather than unwrap-panicking
        numerator.checked_div(denominator).ok_or(ErrorCode::Overflow.into())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Division by zero")]
    DivisionByZero,
    #[msg("Arithmetic overflow")]
    Overflow,
}
