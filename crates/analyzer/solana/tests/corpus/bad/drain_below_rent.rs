// EXPECT: sol_rent_exemption_check
use anchor_lang::prelude::*;

#[program]
pub mod p {
    use super::*;
    pub fn drain(ctx: Context<Drain>, amount: u64) -> Result<()> {
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.to.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Drain<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    /// CHECK: destination chosen by the authority
    pub to: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
}
