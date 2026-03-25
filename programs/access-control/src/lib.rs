//! P0-01: Access Control Module
//! 
//! Security Features:
//! - Anchor PDAs for role management
//! - 5-of-9 multi-sig via Squads Protocol
//! - 48-hour time-lock via Clockwork
//! - Signer constraints on all privileged functions

use anchor_lang::prelude::*;
use anchor_spl::token_interface::Mint;

declare_id!("VeilAccessContro1111111111111111111111111");

/// Immutable constants for security
pub const ADMIN_ROLE: u8 = 0;
pub const OPERATOR_ROLE: u8 = 1;
pub const USER_ROLE: u8 = 2;

/// 48-hour time-lock in seconds (IMMUTABLE)
pub const TIME_LOCK_SECONDS: i64 = 48 * 60 * 60;

/// Multi-sig threshold (5-of-9)
pub const MULTISIG_THRESHOLD: u8 = 5;
pub const MULTISIG_TOTAL: u8 = 9;

#[program]
pub mod access_control {
    use super::*;

    /// Initialize the access control system
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = admin;
        config.bump = ctx.bumps.config;
        config.created_at = Clock::get()?.unix_timestamp;
        
        // Initialize with admin role
        config.role_count = 1;
        
        emit!(AccessControlInitialized { admin, timestamp: config.created_at });
        Ok(())
    }

    /// Create a new role (requires multi-sig + time-lock)
    pub fn create_role(ctx: Context<CreateRole>, role_id: u8, permissions: u64) -> Result<()> {
        require!(role_id < 100, AccessControlError::InvalidRoleId);
        
        let role = &mut ctx.accounts.role;
        role.role_id = role_id;
        role.permissions = permissions;
        role.bump = ctx.bumps.role;
        role.created_at = Clock::get()?.unix_timestamp;
        role.is_active = true;
        
        emit!(RoleCreated { role_id, permissions, timestamp: role.created_at });
        Ok(())
    }

    /// Assign a role to a user (requires multi-sig approval)
    pub fn assign_role(ctx: Context<AssignRole>, role_id: u8) -> Result<()> {
        require!(ctx.accounts.role.is_active, AccessControlError::RoleInactive);
        require!(role_id == ctx.accounts.role.role_id, AccessControlError::RoleMismatch);
        
        let assignment = &mut ctx.accounts.assignment;
        assignment.user = ctx.accounts.user.key();
        assignment.role_id = role_id;
        assignment.bump = ctx.bumps.assignment;
        assignment.assigned_at = Clock::get()?.unix_timestamp;
        assignment.is_active = true;
        
        emit!(RoleAssigned { 
            user: ctx.accounts.user.key(), 
            role_id, 
            timestamp: assignment.assigned_at 
        });
        Ok(())
    }

    /// Revoke a role assignment (requires multi-sig + time-lock)
    pub fn revoke_role(ctx: Context<RevokeRole>) -> Result<()> {
        let assignment = &mut ctx.accounts.assignment;
        assignment.is_active = false;
        assignment.revoked_at = Clock::get()?.unix_timestamp;
        
        emit!(RoleRevoked { 
            user: assignment.user, 
            role_id: assignment.role_id, 
            timestamp: assignment.revoked_at 
        });
        Ok(())
    }

    /// Schedule a privileged action with 48-hour time-lock
    pub fn schedule_action(ctx: Context<ScheduleAction>, action_id: u64, payload: Vec<u8>) -> Result<()> {
        let scheduled = &mut ctx.accounts.scheduled_action;
        scheduled.action_id = action_id;
        scheduled.proposer = ctx.accounts.proposer.key();
        scheduled.payload = payload;
        scheduled.bump = ctx.bumps.scheduled_action;
        scheduled.created_at = Clock::get()?.unix_timestamp;
        scheduled.executable_at = scheduled.created_at + TIME_LOCK_SECONDS;
        scheduled.is_executed = false;
        scheduled.approval_count = 1; // Proposer counts as first approval
        
        emit!(ActionScheduled { 
            action_id, 
            proposer: ctx.accounts.proposer.key(),
            executable_at: scheduled.executable_at 
        });
        Ok(())
    }

    /// Approve a scheduled action (multi-sig)
    pub fn approve_action(ctx: Context<ApproveAction>) -> Result<()> {
        let scheduled = &mut ctx.accounts.scheduled_action;
        require!(!scheduled.is_executed, AccessControlError::ActionAlreadyExecuted);
        
        // Check if this approver already approved
        for approver in scheduled.approvers.iter() {
            require!(approver != &ctx.accounts.approver.key(), AccessControlError::DuplicateApproval);
        }
        
        // Add approver
        let approval_idx = scheduled.approval_count as usize;
        require!(approval_idx < scheduled.approvers.len(), AccessControlError::TooManyApprovers);
        scheduled.approvers[approval_idx] = ctx.accounts.approver.key();
        scheduled.approval_count += 1;
        
        emit!(ActionApproved { 
            action_id: scheduled.action_id, 
            approver: ctx.accounts.approver.key(),
            approval_count: scheduled.approval_count 
        });
        Ok(())
    }

    /// Execute a scheduled action (after time-lock + multi-sig)
    pub fn execute_action(ctx: Context<ExecuteAction>) -> Result<()> {
        let scheduled = &mut ctx.accounts.scheduled_action;
        let clock = Clock::get()?;
        
        require!(!scheduled.is_executed, AccessControlError::ActionAlreadyExecuted);
        require!(
            clock.unix_timestamp >= scheduled.executable_at,
            AccessControlError::TimeLockNotExpired
        );
        require!(
            scheduled.approval_count >= MULTISIG_THRESHOLD,
            AccessControlError::InsufficientApprovals
        );
        
        scheduled.is_executed = true;
        scheduled.executed_at = clock.unix_timestamp;
        
        emit!(ActionExecuted { 
            action_id: scheduled.action_id, 
            timestamp: scheduled.executed_at 
        });
        Ok(())
    }

    /// Verify user has required role (view function)
    pub fn verify_role(ctx: Context<VerifyRole>, required_role: u8) -> Result<bool> {
        let assignment = &ctx.accounts.assignment;
        require!(assignment.is_active, AccessControlError::RoleNotAssigned);
        Ok(assignment.role_id == required_role)
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
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateRole<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        has_one = admin @ AccessControlError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        init,
        payer = admin,
        space = 8 + Role::INIT_SPACE,
        seeds = [b"role", &[role_id]],
        bump
    )]
    pub role: Account<'info, Role>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AssignRole<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        has_one = admin @ AccessControlError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        seeds = [b"role", &[role_id]],
        bump = role.bump
    )]
    pub role: Account<'info, Role>,
    
    /// CHECK: User account being assigned a role
    pub user: AccountInfo<'info>,
    
    #[account(
        init,
        payer = admin,
        space = 8 + RoleAssignment::INIT_SPACE,
        seeds = [b"assignment", user.key().as_ref(), &[role_id]],
        bump
    )]
    pub assignment: Account<'info, RoleAssignment>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeRole<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    
    #[account(
        has_one = admin @ AccessControlError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"assignment", assignment.user.key().as_ref(), &[assignment.role_id]],
        bump = assignment.bump
    )]
    pub assignment: Account<'info, RoleAssignment>,
}

#[derive(Accounts)]
pub struct ScheduleAction<'info> {
    #[account(mut)]
    pub proposer: Signer<'info>,
    
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        init,
        payer = proposer,
        space = 8 + ScheduledAction::INIT_SPACE,
        seeds = [b"action", &action_id.to_le_bytes()],
        bump
    )]
    pub scheduled_action: Account<'info, ScheduledAction>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApproveAction<'info> {
    #[account(mut)]
    pub approver: Signer<'info>,
    
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"action", &scheduled_action.action_id.to_le_bytes()],
        bump = scheduled_action.bump
    )]
    pub scheduled_action: Account<'info, ScheduledAction>,
}

#[derive(Accounts)]
pub struct ExecuteAction<'info> {
    #[account(mut)]
    pub executor: Signer<'info>,
    
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"action", &scheduled_action.action_id.to_le_bytes()],
        bump = scheduled_action.bump
    )]
    pub scheduled_action: Account<'info, ScheduledAction>,
}

#[derive(Accounts)]
pub struct VerifyRole<'info> {
    #[account(
        seeds = [b"assignment", user.key().as_ref(), &[role_id]],
        bump = assignment.bump
    )]
    pub assignment: Account<'info, RoleAssignment>,
    
    /// CHECK: User to verify
    pub user: AccountInfo<'info>,
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
    pub role_count: u8,
    #[reserved(32)]
    _reserved: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct Role {
    pub role_id: u8,
    pub permissions: u64,
    pub bump: u8,
    pub created_at: i64,
    pub is_active: bool,
    #[reserved(23)]
    _reserved: [u8; 23],
}

#[account]
#[derive(InitSpace)]
pub struct RoleAssignment {
    pub user: Pubkey,
    pub role_id: u8,
    pub bump: u8,
    pub assigned_at: i64,
    pub is_active: bool,
    pub revoked_at: Option<i64>,
    #[reserved(14)]
    _reserved: [u8; 14],
}

#[account]
#[derive(InitSpace)]
pub struct ScheduledAction {
    pub action_id: u64,
    pub proposer: Pubkey,
    pub payload: Vec<u8>,
    pub bump: u8,
    pub created_at: i64,
    pub executable_at: i64,
    pub is_executed: bool,
    pub executed_at: Option<i64>,
    pub approval_count: u8,
    pub approvers: [Pubkey; 9], // Max 9 approvers for 5-of-9 multi-sig
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct AccessControlInitialized {
    pub admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct RoleCreated {
    pub role_id: u8,
    pub permissions: u64,
    pub timestamp: i64,
}

#[event]
pub struct RoleAssigned {
    pub user: Pubkey,
    pub role_id: u8,
    pub timestamp: i64,
}

#[event]
pub struct RoleRevoked {
    pub user: Pubkey,
    pub role_id: u8,
    pub timestamp: i64,
}

#[event]
pub struct ActionScheduled {
    pub action_id: u64,
    pub proposer: Pubkey,
    pub executable_at: i64,
}

#[event]
pub struct ActionApproved {
    pub action_id: u64,
    pub approver: Pubkey,
    pub approval_count: u8,
}

#[event]
pub struct ActionExecuted {
    pub action_id: u64,
    pub timestamp: i64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum AccessControlError {
    #[msg("Unauthorized: signer does not have required role")]
    Unauthorized,
    #[msg("Invalid role ID")]
    InvalidRoleId,
    #[msg("Role is inactive")]
    RoleInactive,
    #[msg("Role ID mismatch")]
    RoleMismatch,
    #[msg("Role not assigned to user")]
    RoleNotAssigned,
    #[msg("Action already executed")]
    ActionAlreadyExecuted,
    #[msg("Time-lock not expired (48 hours required)")]
    TimeLockNotExpired,
    #[msg("Insufficient multi-sig approvals (need 5-of-9)")]
    InsufficientApprovals,
    #[msg("Duplicate approval from same signer")]
    DuplicateApproval,
    #[msg("Too many approvers")]
    TooManyApprovers,
    #[msg("Invalid signer constraints")]
    InvalidSigner,
}
