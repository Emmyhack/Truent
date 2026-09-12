// EXPECT: sol_treasury_single_authority
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[program]
pub mod treasury {
    use super::*;
    pub fn payout(ctx: Context<Payout>, amount: u64) -> Result<()> {
        let rent = Rent::get()?;
        let _ = rent.minimum_balance(0);
        let cpi = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.treasury.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(cpi, amount)
    }
}

#[derive(Accounts)]
pub struct Payout<'info> {
    #[account(mut)]
    pub treasury: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
