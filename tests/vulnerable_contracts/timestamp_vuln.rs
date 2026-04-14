// VULNERABLE: unix_timestamp used as sole gate for a fund transfer
use anchor_lang::prelude::*;

#[program]
pub mod vesting {
    use super::*;

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let vesting = &ctx.accounts.vesting;

        // VULNERABLE: validator can skew unix_timestamp by seconds/minutes
        let clock = Clock::get()?;
        if clock.unix_timestamp >= vesting.unlock_time {
            // Transfer vested tokens directly based on manipulable timestamp
            transfer(ctx.accounts.into())?;
        }

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let clock = Clock::get()?;

        // VULNERABLE: timestamp comparison guards a withdrawal
        require!(
            clock.unix_timestamp > ctx.accounts.escrow.expiry,
            ErrorCode::NotYetExpired
        );

        invoke(
            &system_instruction::transfer(/* ... */),
            &[],
        )?;

        Ok(())
    }
}

#[error_code]
pub enum ErrorCode {
    NotYetExpired,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    pub vesting: Account<'info, VestingAccount>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub escrow: Account<'info, Escrow>,
}

#[account]
pub struct VestingAccount {
    pub unlock_time: i64,
    pub amount: u64,
}

#[account]
pub struct Escrow {
    pub expiry: i64,
    pub amount: u64,
}
