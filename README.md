# VEIL Network - Solana Smart Contracts

**Anchor Programs for VEIL Network Tokenomics**

## 📜 Programs

### 1. Access Control
- **Purpose:** Role-based access control with multi-sig
- **Features:** 5-of-9 Squads multi-sig, 48h time-lock via Clockwork
- **P0 Fix:** P0-01 (Access control missing)

### 2. Fee Distribution
- **Purpose:** Distribute protocol fees to node operators + stakers
- **Features:** Pull-over-push pattern, rate limiting (1 claim/24h)
- **P0 Fix:** P0-06 (Reentrancy vulnerability)

### 3. Vesting
- **Purpose:** Team/contributor token vesting
- **Features:** Hard-coded 1yr cliff + 4yr vesting, IMMUTABLE
- **P0 Fix:** P0-07 (Vesting bypass possible)

## 🛡️ Security

All programs have been audited for P0 security issues:
- ✅ Access control with multi-sig
- ✅ Reentrancy protection (state-first updates)
- ✅ Immutable vesting (no admin override)

## 🚀 Build

`ash
cd veil
anchor build
`

## 🧪 Test

`ash
anchor test
`

## 📋 Deploy

`ash
# Devnet
anchor deploy --provider.cluster devnet

# Mainnet (after audit)
anchor deploy --provider.cluster mainnet
`

## 📚 Documentation

- docs/SECURITY_FIXES.md - Security analysis
- docs/DEPLOYMENT_GUIDE.md - Deployment instructions

## ⚖️ License

Apache 2.0 (Open Source)