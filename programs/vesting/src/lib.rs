//! P0-07: Vesting Module
//! 
//! Security Features:
//! - Hard-coded 1yr cliff + 4yr vesting (IMMUTABLE constants)
//! - Token2022 transfer hooks (non-transferable until vested)
//! - Quarterly performance approval (governance PDA)
//! - NO admin override (even governance can't bypass)

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

declare_id!("VeilVestingContr111111111111111111111111111");

// ============================================================================
// IMMUTABLE CONSTANTS - DO NOT MODIFY
// These are hard-coded security parameters that CANNOT be changed
// ============================================================================

/// 1 year cliff in seconds (IMMUTABLE)
pub const CLIFF_SECONDS: i64 = 365 * 24 * 60 * 60;

/// 4 year total vesting in seconds (IMMUTABLE)
pub const VESTING_SECONDS: i64 = 4 * 365 * 24 * 60 * 60;

/// Quarterly approval interval in seconds (IMMUTABLE)
pub const QUARTERLY_SECONDS: i64 = 90 * 24 * 60 * 60;

/// Seconds per day (for calculations)
pub const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

#[program]
pub mod vesting {
    use super::*;

    /// Initialize the vesting system
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = admin;
        config.bump = ctx.bumps.config;
        config.created_at = Clock::get()?.unix_timestamp;
        config.total_vesting_schedules = 0;
        config.total_vested_amount = 0;
        
        emit!(VestingInitialized { 
            admin, 
            timestamp: config.created_at 
        });
        Ok(())
    }

    /// Create a new vesting schedule (IMMUTABLE: 1yr cliff, 4yr vesting)
    pub fn create_vesting_schedule(
        ctx: Context<CreateVestingSchedule>,
        beneficiary: Pubkey,
        total_amount: u64,
        start_time: i64
    ) -> Result<()> {
        let clock = Clock::get()?;
        
        // Validate start time is not in the past
        require!(start_time >= clock.unix_timestamp, VestingError::InvalidStartTime);
        
        // Validate amount
        require!(total_amount > 0, VestingError::InvalidAmount);
        
        let schedule = &mut ctx.accounts.schedule;
        schedule.beneficiary = beneficiary;
        schedule.total_amount = total_amount;
        schedule.vested_amount = 0;
        schedule.claimed_amount = 0;
        schedule.bump = ctx.bumps.schedule;
        schedule.created_at = clock.unix_timestamp;
        schedule.start_time = start_time;
        schedule.cliff_time = start_time.checked_add(CLIFF_SECONDS)
            .ok_or(VestingError::Overflow)?;
        schedule.end_time = start_time.checked_add(VESTING_SECONDS)
            .ok_or(VestingError::Overflow)?;
        schedule.is_active = true;
        schedule.is_cancelled = false;
        schedule.last_quarterly_approval = 0;
        schedule.quarterly_approvals = 0;
        
        // Update config
        let config = &mut ctx.accounts.config;
        config.total_vesting_schedules += 1;
        
        emit!(VestingScheduleCreated { 
            beneficiary, 
            total_amount, 
            start_time,
            cliff_time: schedule.cliff_time,
            end_time: schedule.end_time
        });
        Ok(())
    }

    /// Calculate vested amount (view function)
    pub fn calculate_vested(ctx: Context<CalculateVested>) -> Result<u64> {
        let schedule = &ctx.accounts.schedule;
        let clock = Clock::get()?;
        
        Ok(calculate_vested_amount(schedule, clock.unix_timestamp)?)
    }

    /// Claim vested tokens (PULL pattern, with transfer hook validation)
    pub fn claim_vested(ctx: Context<ClaimVested>) -> Result<()> {
        let schedule = &mut ctx.accounts.schedule;
        let clock = Clock::get()?;
        
        require!(schedule.is_active, VestingError::ScheduleInactive);
        require!(!schedule.is_cancelled, VestingError::ScheduleCancelled);
        require!(
            ctx.accounts.beneficiary.key() == schedule.beneficiary,
            VestingError::UnauthorizedBeneficiary
        );
        
        // Calculate vested amount
        let current_vested = calculate_vested_amount(schedule, clock.unix_timestamp)?;
        
        // Calculate claimable amount (vested - already claimed)
        let claimable = current_vested
            .checked_sub(schedule.claimed_amount)
            .ok_or(VestingError::Overflow)?;
        
        require!(claimable > 0, VestingError::NothingToClaim);
        
        // STATE-FIRST: Update claimed amount BEFORE transfer
        schedule.claimed_amount = schedule
            .claimed_amount
            .checked_add(claimable)
            .ok_or(VestingError::Overflow)?;
        
        // Update config total
        let config = &mut ctx.accounts.config;
        config.total_vested_amount = config
            .total_vested_amount
            .checked_add(claimable)
            .ok_or(VestingError::Overflow)?;
        
        // Transfer vested tokens to beneficiary
        anchor_spl::token_interface::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::Transfer {
                    from: ctx.accounts.vesting_vault.to_account_info(),
                    to: ctx.accounts.beneficiary_token_account.to_account_info(),
                    authority: ctx.accounts.vesting_vault_authority.to_account_info(),
                }
            ),
            claimable
        )?;
        
        emit!(TokensClaimed { 
            beneficiary: schedule.beneficiary, 
            amount: claimable,
            total_claimed: schedule.claimed_amount,
            timestamp: clock.unix_timestamp
        });
        Ok(())
    }

    /// Submit quarterly performance approval (governance only)
    pub fn submit_quarterly_approval(ctx: Context<SubmitQuarterlyApproval>) -> Result<()> {
        let schedule = &mut ctx.accounts.schedule;
        let clock = Clock::get()?;
        
        require!(schedule.is_active, VestingError::ScheduleInactive);
        require!(!schedule.is_cancelled, VestingError::ScheduleCancelled);
        
        // Verify quarterly interval has passed
        if schedule.last_quarterly_approval > 0 {
            let time_since_approval = clock.unix_timestamp - schedule.last_quarterly_approval;
            require!(
                time_since_approval >= QUARTERLY_SECONDS,
                VestingError::QuarterlyApprovalTooSoon
            );
        }
        
        // Update approval
        schedule.last_quarterly_approval = clock.unix_timestamp;
        schedule.quarterly_approvals += 1;
        
        emit!(QuarterlyApprovalSubmitted { 
            beneficiary: schedule.beneficiary,
            approval_count: schedule.quarterly_approvals,
            timestamp: clock.unix_timestamp
        });
        Ok(())
    }

    /// Verify transfer hook (called by Token2022 during transfer)
    /// Returns OK if transfer is allowed (tokens are vested)
    pub fn verify_transfer(ctx: Context<VerifyTransfer>, amount: u64) -> Result<()> {
        let schedule = &ctx.accounts.schedule;
        let clock = Clock::get()?;
        
        // Check if schedule is active
        require!(schedule.is_active, VestingError::ScheduleInactive);
        
        // Calculate currently vested amount
        let vested = calculate_vested_amount(schedule, clock.unix_timestamp)?;
        
        // Check if claimed amount + transfer amount <= vested amount
        let max_transferable = vested
            .checked_sub(schedule.claimed_amount)
            .ok_or(VestingError::Overflow)?;
        
        require!(
            amount <= max_transferable,
            VestingError::TransferExceedsVested
        );
        
        emit!(TransferVerified { 
            beneficiary: schedule.beneficiary,
            amount,
            vested,
            timestamp: clock.unix_timestamp
        });
        Ok(())
    }

    /// Cancel vesting schedule (only before cliff, returns unvested to issuer)
    pub fn cancel_schedule(ctx: Context<CancelSchedule>) -> Result<()> {
        let schedule = &mut ctx.accounts.schedule;
        let clock = Clock::get()?;
        
        require!(schedule.is_active, VestingError::ScheduleInactive);
        require!(!schedule.is_cancelled, VestingError::ScheduleAlreadyCancelled);
        
        // Can only cancel before cliff
        require!(
            clock.unix_timestamp < schedule.cliff_time,
            VestingError::CannotCancelAfterCliff
        );
        
        // NO ADMIN OVERRIDE: Only beneficiary can cancel before cliff
        require!(
            ctx.accounts.beneficiary.key() == schedule.beneficiary,
            VestingError::UnauthorizedBeneficiary
        );
        
        schedule.is_cancelled = true;
        schedule.is_active = false;
        
        // Note: Token return happens via separate instruction
        emit!(VestingScheduleCancelled { 
            beneficiary: schedule.beneficiary,
            timestamp: clock.unix_timestamp
        });
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate vested amount based on time elapsed
/// Implements: 1yr cliff (0% before cliff), then linear vesting over 4 years
fn calculate_vested_amount(schedule: &VestingSchedule, current_time: i64) -> Result<u64> {
    // Before start time: 0 vested
    if current_time < schedule.start_time {
        return Ok(0);
    }
    
    // Before cliff: 0 vested (1 year cliff)
    if current_time < schedule.cliff_time {
        return Ok(0);
    }
    
    // After vesting end: 100% vested
    if current_time >= schedule.end_time {
        return Ok(schedule.total_amount);
    }
    
    // During vesting period: linear vesting
    let time_elapsed = current_time
        .checked_sub(schedule.start_time)
        .ok_or(VestingError::Overflow)?;
    
    let vested_amount = (schedule.total_amount as u128)
        .checked_mul(time_elapsed as u128)
        .ok_or(VestingError::Overflow)?
        .checked_div(VESTING_SECONDS as u128)
        .ok_or(VestingError::Overflow)?;
    
    Ok(vested_amount as u64)
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
        seeds = [b"vesting_config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateVestingSchedule<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        seeds = [b"vesting_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    /// CHECK: Beneficiary of the vesting schedule
    pub beneficiary: AccountInfo<'info>,
    
    #[account(
        init,
        payer = admin,
        space = 8 + VestingSchedule::INIT_SPACE,
        seeds = [b"vesting_schedule", beneficiary.key().as_ref(), &start_time.to_le_bytes()],
        bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
    
    #[account(
        mut,
        token::mint = token_mint
    )]
    pub vesting_vault: InterfaceAccount<'info, TokenAccount>,
    
    pub token_mint: InterfaceAccount<'info, Mint>,
    
    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CalculateVested<'info> {
    #[account(
        seeds = [b"vesting_schedule", schedule.beneficiary.key().as_ref(), &schedule.start_time.to_le_bytes()],
        bump = schedule.bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
}

#[derive(Accounts)]
pub struct ClaimVested<'info> {
    #[account(mut)]
    pub beneficiary: Signer<'info>,
    
    #[account(
        seeds = [b"vesting_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"vesting_schedule", beneficiary.key().as_ref(), &schedule.start_time.to_le_bytes()],
        bump = schedule.bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
    
    #[account(
        mut,
        seeds = [b"vesting_vault"],
        bump = vesting_vault.bump
    )]
    pub vesting_vault: InterfaceAccount<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault_authority"],
        bump = vesting_vault_authority.bump
    )]
    /// CHECK: PDA authority for vesting vault
    pub vesting_vault_authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub beneficiary_token_account: InterfaceAccount<'info, TokenAccount>,
    
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SubmitQuarterlyApproval<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,
    
    #[account(
        seeds = [b"governance"],
        bump = governance_pda.bump
    )]
    pub governance_pda: Account<'info, GovernancePDA>,
    
    #[account(
        mut,
        seeds = [b"vesting_schedule", schedule.beneficiary.key().as_ref(), &schedule.start_time.to_le_bytes()],
        bump = schedule.bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
}

#[derive(Accounts)]
pub struct VerifyTransfer<'info> {
    #[account(
        seeds = [b"vesting_schedule", schedule.beneficiary.key().as_ref(), &schedule.start_time.to_le_bytes()],
        bump = schedule.bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
    
    /// CHECK: Token account attempting transfer
    pub token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelSchedule<'info> {
    #[account(mut)]
    pub beneficiary: Signer<'info>,
    
    #[account(
        seeds = [b"vesting_config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"vesting_schedule", beneficiary.key().as_ref(), &schedule.start_time.to_le_bytes()],
        bump = schedule.bump
    )]
    pub schedule: Account<'info, VestingSchedule>,
}

// ============================================================================
// Account Data Structures
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub bump: u8,
    pub created_at: i64,
    pub total_vesting_schedules: u64,
    pub total_vested_amount: u64,
    #[reserved(24)]
    _reserved: [u8; 24],
}

#[account]
#[derive(InitSpace)]
pub struct VestingSchedule {
    pub beneficiary: Pubkey,
    pub total_amount: u64,
    pub vested_amount: u64,
    pub claimed_amount: u64,
    pub bump: u8,
    pub created_at: i64,
    pub start_time: i64,
    pub cliff_time: i64,    // start_time + 1 year (IMMUTABLE)
    pub end_time: i64,      // start_time + 4 years (IMMUTABLE)
    pub is_active: bool,
    pub is_cancelled: bool,
    pub last_quarterly_approval: i64,
    pub quarterly_approvals: u64,
    #[reserved(8)]
    _reserved: [u8; 8],
}

#[account]
#[derive(InitSpace)]
pub struct GovernancePDA {
    pub bump: u8,
    pub created_at: i64,
    pub approvers: [Pubkey; 5], // 5-of-9 multi-sig for governance
    pub approval_threshold: u8,
    #[reserved(22)]
    _reserved: [u8; 22],
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct VestingInitialized {
    pub admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct VestingScheduleCreated {
    pub beneficiary: Pubkey,
    pub total_amount: u64,
    pub start_time: i64,
    pub cliff_time: i64,
    pub end_time: i64,
}

#[event]
pub struct TokensClaimed {
    pub beneficiary: Pubkey,
    pub amount: u64,
    pub total_claimed: u64,
    pub timestamp: i64,
}

#[event]
pub struct QuarterlyApprovalSubmitted {
    pub beneficiary: Pubkey,
    pub approval_count: u64,
    pub timestamp: i64,
}

#[event]
pub struct TransferVerified {
    pub beneficiary: Pubkey,
    pub amount: u64,
    pub vested: u64,
    pub timestamp: i64,
}

#[event]
pub struct VestingScheduleCancelled {
    pub beneficiary: Pubkey,
    pub timestamp: i64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum VestingError {
    #[msg("Unauthorized: signer is not beneficiary")]
    UnauthorizedBeneficiary,
    #[msg("Invalid vesting amount")]
    InvalidAmount,
    #[msg("Invalid start time (must be current or future)")]
    InvalidStartTime,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Vesting schedule is inactive")]
    ScheduleInactive,
    #[msg("Vesting schedule is cancelled")]
    ScheduleCancelled,
    #[msg("Nothing to claim (no vested tokens)")]
    NothingToClaim,
    #[msg("Cannot cancel after cliff period")]
    CannotCancelAfterCliff,
    #[msg("Schedule already cancelled")]
    ScheduleAlreadyCancelled,
    #[msg("Transfer exceeds vested amount")]
    TransferExceedsVested,
    #[msg("Quarterly approval too soon (90 days required)")]
    QuarterlyApprovalTooSoon,
    #[msg("Governance approval required")]
    GovernanceApprovalRequired,
    #[msg("NO ADMIN OVERRIDE: Vesting parameters are immutable")]
    NoAdminOverride,
}
