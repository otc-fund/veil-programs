//! P0-06: Fee Distribution Module
//! 
//! Security Features:
//! - State-first updates (before CPI calls)
//! - Pull-over-push pattern (users claim rewards)
//! - Rate limiting (1 claim per 24 hours)
//! - CPI depth limits

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

declare_id!("VeilFeeDistribut111111111111111111111111111");

/// Immutable constants for security
pub const CLAIM_COOLDOWN_SECONDS: i64 = 24 * 60 * 60; // 24 hours
pub const MAX_CPI_DEPTH: u8 = 4;
pub const BASIS_POINTS: u64 = 10000;

#[program]
pub mod fee_distribution {
    use super::*;

    /// Initialize the fee distribution system
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey, fee_bps: u64) -> Result<()> {
        require!(fee_bps <= BASIS_POINTS, FeeDistributionError::InvalidFee);
        
        let config = &mut ctx.accounts.config;
        config.admin = admin;
        config.fee_bps = fee_bps;
        config.bump = ctx.bumps.config;
        config.created_at = Clock::get()?.unix_timestamp;
        config.total_fees_collected = 0;
        config.total_fees_distributed = 0;
        config.is_paused = false;
        config.cpi_depth = 0;
        
        emit!(FeeDistributionInitialized { 
            admin, 
            fee_bps, 
            timestamp: config.created_at 
        });
        Ok(())
    }

    /// Collect fees from a transaction (STATE-FIRST: update before any CPI)
    pub fn collect_fees<'info>(
        ctx: Context<'_, '_, 'info, 'info, CollectFees<'info>>,
        amount: u64
    ) -> Result<()> {
        require!(!ctx.accounts.config.is_paused, FeeDistributionError::DistributionPaused);
        
        // STATE-FIRST: Update state BEFORE any CPI calls
        let config = &mut ctx.accounts.config;
        let fee_amount = amount
            .checked_mul(config.fee_bps)
            .ok_or(FeeDistributionError::Overflow)?
            .checked_div(BASIS_POINTS)
            .ok_or(FeeDistributionError::Overflow)?;
        
        config.total_fees_collected = config
            .total_fees_collected
            .checked_add(fee_amount)
            .ok_or(FeeDistributionError::Overflow)?;
        
        // Check CPI depth limit
        require!(config.cpi_depth < MAX_CPI_DEPTH, FeeDistributionError::CpiDepthExceeded);
        config.cpi_depth += 1;
        
        // Transfer fees to vault (CPI happens AFTER state update)
        if fee_amount > 0 {
            anchor_spl::token_interface::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    anchor_spl::token_interface::Transfer {
                        from: ctx.accounts.source_token_account.to_account_info(),
                        to: ctx.accounts.fee_vault.to_account_info(),
                        authority: ctx.accounts.fee_payer.to_account_info(),
                    }
                ),
                fee_amount
            )?;
        }
        
        // Decrement CPI depth after completion
        config.cpi_depth -= 1;
        
        emit!(FeesCollected { 
            amount: fee_amount, 
            total_collected: config.total_fees_collected,
            fee_payer: ctx.accounts.fee_payer.key()
        });
        Ok(())
    }

    /// Record user rewards (STATE-FIRST: update before any external calls)
    pub fn record_rewards(ctx: Context<RecordRewards>, amount: u64) -> Result<()> {
        require!(!ctx.accounts.config.is_paused, FeeDistributionError::DistributionPaused);
        
        // STATE-FIRST: Update state BEFORE any CPI
        let config = &mut ctx.accounts.config;
        config.total_fees_distributed = config
            .total_fees_distributed
            .checked_add(amount)
            .ok_or(FeeDistributionError::Overflow)?;
        
        let user_reward = &mut ctx.accounts.user_reward;
        user_reward.pending_rewards = user_reward
            .pending_rewards
            .checked_add(amount)
            .ok_or(FeeDistributionError::Overflow)?;
        user_reward.last_updated = Clock::get()?.unix_timestamp;
        
        emit!(RewardsRecorded { 
            user: ctx.accounts.user.key(), 
            amount, 
            pending: user_reward.pending_rewards 
        });
        Ok(())
    }

    /// Claim rewards (PULL pattern: user initiates claim)
    pub fn claim_rewards<'info>(
        ctx: Context<'_, '_, 'info, 'info, ClaimRewards<'info>>
    ) -> Result<()> {
        require!(!ctx.accounts.config.is_paused, FeeDistributionError::DistributionPaused);
        
        let user_reward = &mut ctx.accounts.user_reward;
        let claim_amount = user_reward.pending_rewards;
        
        require!(claim_amount > 0, FeeDistributionError::NoRewardsToClaim);
        
        // RATE LIMITING: Check 24-hour cooldown
        let clock = Clock::get()?;
        let time_since_last_claim = clock.unix_timestamp - user_reward.last_claim_at;
        require!(
            time_since_last_claim >= CLAIM_COOLDOWN_SECONDS || user_reward.last_claim_at == 0,
            FeeDistributionError::ClaimCooldownActive
        );
        
        // STATE-FIRST: Zero out rewards BEFORE transfer (prevents reentrancy)
        user_reward.pending_rewards = 0;
        user_reward.last_claim_at = clock.unix_timestamp;
        user_reward.total_claimed = user_reward
            .total_claimed
            .checked_add(claim_amount)
            .ok_or(FeeDistributionError::Overflow)?;
        
        // PULL pattern: Transfer to user's token account
        anchor_spl::token_interface::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::Transfer {
                    from: ctx.accounts.fee_vault.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: ctx.accounts.fee_vault_authority.to_account_info(),
                }
            ),
            claim_amount
        )?;
        
        emit!(RewardsClaimed { 
            user: ctx.accounts.user.key(), 
            amount: claim_amount,
            total_claimed: user_reward.total_claimed
        });
        Ok(())
    }

    /// Pause distribution (admin only, with signer constraint)
    pub fn pause_distribution(ctx: Context<PauseDistribution>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(ctx.accounts.admin.key() == config.admin, FeeDistributionError::Unauthorized);
        
        config.is_paused = true;
        
        emit!(DistributionPaused { timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    /// Unpause distribution (admin only, with signer constraint)
    pub fn unpause_distribution(ctx: Context<UnpauseDistribution>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(ctx.accounts.admin.key() == config.admin, FeeDistributionError::Unauthorized);
        
        config.is_paused = false;
        
        emit!(DistributionUnpaused { timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    /// Update fee basis points (admin only, with signer constraint)
    pub fn update_fee(ctx: Context<UpdateFee>, new_fee_bps: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(ctx.accounts.admin.key() == config.admin, FeeDistributionError::Unauthorized);
        require!(new_fee_bps <= BASIS_POINTS, FeeDistributionError::InvalidFee);
        
        let old_fee = config.fee_bps;
        config.fee_bps = new_fee_bps;
        
        emit!(FeeUpdated { 
            old_fee_bps: old_fee, 
            new_fee_bps, 
            timestamp: Clock::get()?.unix_timestamp 
        });
        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        init,
        payer = admin,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"fee_config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CollectFees<'info> {
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    
    #[account(
        seeds = [b"fee_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"fee_vault"],
        bump = fee_vault.bump
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,
    
    #[account(mut)]
    pub source_token_account: InterfaceAccount<'info, TokenAccount>,
    
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct RecordRewards<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        seeds = [b"fee_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    /// CHECK: User receiving rewards
    pub user: AccountInfo<'info>,
    
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + UserReward::INIT_SPACE,
        seeds = [b"user_reward", user.key().as_ref()],
        bump
    )]
    pub user_reward: Account<'info, UserReward>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        seeds = [b"fee_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"fee_vault"],
        bump = fee_vault.bump
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault_authority"],
        bump = fee_vault_authority.bump
    )]
    /// CHECK: PDA authority for fee vault
    pub fee_vault_authority: AccountInfo<'info>,
    
    #[account(
        mut,
        seeds = [b"user_reward", user.key().as_ref()],
        bump = user_reward.bump
    )]
    pub user_reward: Account<'info, UserReward>,
    
    #[account(mut)]
    pub user_token_account: InterfaceAccount<'info, TokenAccount>,
    
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct PauseDistribution<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"fee_config"],
        bump = config.bump,
        has_one = admin @ FeeDistributionError::Unauthorized
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct UnpauseDistribution<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"fee_config"],
        bump = config.bump,
        has_one = admin @ FeeDistributionError::Unauthorized
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"fee_config"],
        bump = config.bump,
        has_one = admin @ FeeDistributionError::Unauthorized
    )]
    pub config: Account<'info, Config>,
}

// ============================================================================
// Account Data Structures
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u64,
    pub bump: u8,
    pub created_at: i64,
    pub total_fees_collected: u64,
    pub total_fees_distributed: u64,
    pub is_paused: bool,
    pub cpi_depth: u8,
    #[reserved(22)]
    _reserved: [u8; 22],
}

#[account]
#[derive(InitSpace)]
pub struct UserReward {
    pub user: Pubkey,
    pub bump: u8,
    pub pending_rewards: u64,
    pub total_claimed: u64,
    pub last_claim_at: i64,
    pub last_updated: i64,
    #[reserved(16)]
    _reserved: [u8; 16],
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct FeeDistributionInitialized {
    pub admin: Pubkey,
    pub fee_bps: u64,
    pub timestamp: i64,
}

#[event]
pub struct FeesCollected {
    pub amount: u64,
    pub total_collected: u64,
    pub fee_payer: Pubkey,
}

#[event]
pub struct RewardsRecorded {
    pub user: Pubkey,
    pub amount: u64,
    pub pending: u64,
}

#[event]
pub struct RewardsClaimed {
    pub user: Pubkey,
    pub amount: u64,
    pub total_claimed: u64,
}

#[event]
pub struct DistributionPaused {
    pub timestamp: i64,
}

#[event]
pub struct DistributionUnpaused {
    pub timestamp: i64,
}

#[event]
pub struct FeeUpdated {
    pub old_fee_bps: u64,
    pub new_fee_bps: u64,
    pub timestamp: i64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum FeeDistributionError {
    #[msg("Unauthorized: signer is not admin")]
    Unauthorized,
    #[msg("Invalid fee basis points")]
    InvalidFee,
    #[msg("Distribution is paused")]
    DistributionPaused,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("CPI depth limit exceeded")]
    CpiDepthExceeded,
    #[msg("No rewards available to claim")]
    NoRewardsToClaim,
    #[msg("Claim cooldown active (24 hours)")]
    ClaimCooldownActive,
    #[msg("Invalid token account")]
    InvalidTokenAccount,
    #[msg("Insufficient vault balance")]
    InsufficientVaultBalance,
}
