// SAFE: Slot-based logic used; timestamp only as an informational hint
use anchor_lang::prelude::*;

// A tolerance buffer of 60 seconds to account for validator skew
const BUFFER_SECS: i64 = 60;

#[program]
pub mod vesting {
    use super::*;

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let vesting = &ctx.accounts.vesting;

        // SAFE: Adds a buffer and uses slot as secondary confirmation
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= vesting.unlock_time + BUFFER_SECS
                && clock.slot >= vesting.unlock_slot,
            ErrorCode::TooEarly
        );

        // Transfer only after both conditions satisfied
        // transfer(ctx.accounts.into())?;

        Ok(())
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Vesting period has not yet elapsed.")]
    TooEarly,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    pub vesting: Account<'info, VestingAccount>,
}

#[account]
pub struct VestingAccount {
    pub unlock_time: i64,
    pub unlock_slot: u64,
    pub amount: u64,
}
