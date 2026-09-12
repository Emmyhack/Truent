// EXPECT: sol_sysvar_account_validation
use anchor_lang::prelude::*;

#[program]
pub mod p {
    use super::*;
    pub fn tick(ctx: Context<Tick>) -> Result<()> {
        let clock = Clock::from_account_info(&ctx.accounts.clock)?;
        ctx.accounts.state.last = clock.unix_timestamp;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Tick<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub clock: AccountInfo<'info>,
}

#[account]
pub struct State {
    pub last: i64,
}
