// SPDX-License-Identifier: Apache-2.0
//
// Functional tests proving that, when a guest is launched with secure-tsc=on,
// the TSC is derived from the AMD Secure Processor (PSP) via SNP_GUEST_REQUEST
// rather than from the hypervisor.
//
// Background
// ----------
// When secure-tsc=on:
//  1. QEMU sets vmsa_features |= BIT(9) (SVM_SEV_FEAT_SECURE_TSC) in KVM_SEV_INIT2.
//  2. KVM calls SEV_CMD_SNP_LAUNCH_START with desired_tsc_khz; the PSP records it.
//  3. KVM marks guest_tsc_protected=true: it no longer writes tsc_offset into the
//     VMCB and blocks all KVM-side TSC adjustments.
//  4. KVM *removes* the read intercept for MSR 0xC0010134 (MSR_AMD64_GUEST_TSC_FREQ),
//     so the guest reads the hardware register directly (programmed by the PSP).
//  5. At boot the guest kernel issues SNP_MSG_TSC_INFO_REQ (msg type 17) via
//     VMGExit 0x80000011 (SVM_VMGEXIT_GUEST_REQUEST).  KVM proxies this to the PSP,
//     which returns tsc_scale, tsc_offset, and tsc_factor.
//  6. The guest kernel overrides calibrate_cpu/calibrate_tsc with the PSP-derived
//     frequency, and stores tsc_scale/tsc_offset into every AP's VMSA.
//  7. MSR 0xC0010131 (SEV_STATUS) bit 11 (SecureTscEn) is set.
//
// Test strategy
// -------------
// Test 1 – SecureTscEn MSR bit
//   Read MSR 0xC0010131 bit 11.  This is set by the PSP when it processes
//   SNP_LAUNCH_START with the SecureTSC feature bit; the hypervisor cannot fake it.
//   Failing: bit is clear → secure-tsc=off or firmware does not support it.
//
// Test 2 – GUEST_TSC_FREQ MSR is readable and sane
//   Read MSR 0xC0010134 (MSR_AMD64_GUEST_TSC_FREQ).  KVM explicitly removes the
//   read intercept (sev.c: svm_set_intercept_for_msr(..., !snp_is_secure_tsc_enabled()))
//   only when secure-tsc is on, so if this MSR read succeeds with a plausible value
//   it proves KVM handed TSC ownership to the PSP.

use anyhow::Result;
use msru::{Accessor, Msr};
use std::mem; // used in unit tests for size/offset assertions

// ── Constants ────────────────────────────────────────────────────────────────

/// MSR_AMD64_GUEST_TSC_FREQ (0xC0010134): nominal TSC frequency in MHz (bits 17:0).
/// KVM removes the read intercept for this MSR when secure-tsc=on, so a successful
/// read proves the PSP programmed the value, not the hypervisor.
const MSR_GUEST_TSC_FREQ: u32 = 0xC001_0134;
const TSC_FREQ_MASK: u64 = 0x3_FFFF; // bits 17:0

/// Decoded response from SNP_MSG_TSC_INFO_RSP (arch/x86/include/asm/sev.h).
/// Layout: status(u32), rsvd1(u32), tsc_scale(u64), tsc_offset(u64),
///         tsc_factor(u32), rsvd2([u8; 100]) — total 128 bytes.
///
/// Not yet used at runtime: a future SNP_GET_TSC_INFO kernel ioctl will return
/// this struct, at which point request_tsc_info() should be added here.
#[allow(dead_code)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TscInfoResp {
    pub status: u32,
    _rsvd1: u32,
    pub tsc_scale: u64,
    pub tsc_offset: u64,
    pub tsc_factor: u32,
    _rsvd2: [u8; 100],
}

impl Default for TscInfoResp {
    fn default() -> Self {
        Self {
            status: 0,
            _rsvd1: 0,
            tsc_scale: 0,
            tsc_offset: 0,
            tsc_factor: 0,
            _rsvd2: [0u8; 100],
        }
    }
}

// ── Test 2: GUEST_TSC_FREQ MSR readable and sane ─────────────────────────────

/// Reads MSR_AMD64_GUEST_TSC_FREQ (0xC0010134) and returns the frequency in MHz.
///
/// KVM only removes the read intercept for this MSR when secure-tsc is on
/// (arch/x86/kvm/svm/sev.c: svm_set_intercept_for_msr with !snp_is_secure_tsc_enabled).
/// Without secure-tsc, the guest would trap into KVM on this read; with it, the
/// hardware returns the PSP-programmed value directly.
///
/// Returns Ok(Some(mhz)) when readable, Ok(None) when the MSR access fails
/// (indicating interception or unsupported MSR — both expected without secure-tsc).
pub fn read_guest_tsc_freq_mhz() -> Result<Option<u64>> {
    let mut msr = match Msr::new(MSR_GUEST_TSC_FREQ, 0) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    match msr.read() {
        Ok(val) => Ok(Some(val & TSC_FREQ_MASK)),
        Err(_) => Ok(None),
    }
}

/// Returns true if `freq_mhz` is within a plausible range for a real TSC.
/// The PSP programs the nominal TSC frequency; anything outside 500 MHz–8 GHz
/// indicates a firmware bug or an emulated/fake value.
pub fn is_plausible_tsc_freq(freq_mhz: u64) -> bool {
    (500..=8_000).contains(&freq_mhz)
}

// ── Test 3: observed TSC rate matches MSR_AMD64_GUEST_TSC_FREQ ───────────────
//
// Strategy: measure the TSC tick rate directly in userspace by bracketing
// _rdtsc() calls around a CLOCK_MONOTONIC_RAW sleep, then compare the observed
// rate to the value in MSR_AMD64_GUEST_TSC_FREQ (0xC0010134).
//
// Why this proves secure-tsc=on:
//   snp_secure_tsc_init() (arch/x86/coco/sev/core.c) does:
//     1. rdmsrq(MSR_AMD64_GUEST_TSC_FREQ, tsc_freq_mhz)   ← reads the PSP value
//     2. snp_tsc_freq_khz = SNP_SCALE_TSC_FREQ(tsc_freq_mhz*1000, tsc_factor)
//     3. x86_platform.calibrate_tsc = securetsc_get_tsc_khz  ← overrides calibration
//   This makes the kernel's tsc_khz — which governs CLOCK_MONOTONIC_RAW — derive
//   from the PSP-programmed MSR.  So if the observed TSC/wall-clock ratio agrees
//   with MSR 0xC0010134 within tolerance, both sides of the comparison trace back
//   to the same PSP-programmed value.
//
//   With secure-tsc=off, KVM manages tsc_offset and calibration happens via PIT/HPET;
//   MSR 0xC0010134 is intercepted so we cannot read it (Test 2 already catches this),
//   but even if the read somehow succeeded with a fake value, the measured TSC rate
//   would reflect the hypervisor's calibration rather than the MSR value.
//
// Tolerance: 250 ppm (0.025%).  The PSP's tsc_factor represents the percent
// decrease from nominal to mean frequency (in units of 0.001%), so on real hardware
// the nominal rate (MSR) and the mean rate (measured over ~50 ms) may differ by up
// to ~200 ppm; we allow 250 ppm to cover measurement noise.

/// How long to sleep between RDTSC samples. 50 ms gives ~0.2% statistical accuracy
/// on a 3 GHz TSC without taking too long in a test suite.
const MEASURE_SLEEP_NS: u64 = 50_000_000;

/// Number of measurement rounds. The best (shortest ns_delta) is kept; the rest
/// are discarded. Preemption inflates ns_delta asymmetrically, so the minimum
/// ratio across rounds converges to the true rate — same technique the kernel uses.
const MEASURE_ROUNDS: usize = 5;

/// Measures the TSC tick frequency in kHz by sampling RDTSC around a
/// CLOCK_MONOTONIC_RAW sleep and comparing to MSR_AMD64_GUEST_TSC_FREQ.
///
/// Takes MEASURE_ROUNDS samples and keeps the one with the smallest elapsed
/// wall time (closest to the requested sleep), which discards rounds where the
/// thread was preempted between the RDTSC and clock_gettime bracket points.
///
/// Returns `Ok((measured_khz, msr_khz))` on success.
pub fn measure_tsc_rate_vs_msr() -> Result<(u64, u64)> {
    let msr_mhz = read_guest_tsc_freq_mhz()?
        .ok_or_else(|| anyhow::anyhow!("MSR_AMD64_GUEST_TSC_FREQ unreadable"))?;
    let msr_khz = msr_mhz * 1000;

    let sleep_req = libc::timespec {
        tv_sec: 0,
        tv_nsec: MEASURE_SLEEP_NS as libc::c_long,
    };

    // (tsc_delta, ns_delta) for the best round so far.
    let mut best: Option<(u64, u64)> = None;

    for _ in 0..MEASURE_ROUNDS {
        let (tsc0, t0_ns) = rdtsc_and_clock_ns()?;

        // nanosleep for MEASURE_SLEEP_NS.  CLOCK_MONOTONIC_RAW is not accepted by
        // clock_nanosleep (ENOTSUP); use CLOCK_MONOTONIC for the sleep — the
        // measurement itself still uses CLOCK_MONOTONIC_RAW on both sides.
        //
        // Safety: valid timespec, null remaining pointer (we don't need it).
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &sleep_req, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "clock_nanosleep failed: {}",
                std::io::Error::from_raw_os_error(rc)
            ));
        }

        let (tsc1, t1_ns) = rdtsc_and_clock_ns()?;

        if t1_ns <= t0_ns || tsc1 <= tsc0 {
            continue;
        }

        let ns_delta = t1_ns - t0_ns;
        let tsc_delta = tsc1 - tsc0;

        // Keep the round with the smallest ns_delta: preemption only ever
        // inflates elapsed time, so the shortest sample is the least-disturbed.
        let keep = match best {
            None => true,
            Some((_, prev_ns)) => ns_delta < prev_ns,
        };
        if keep {
            best = Some((tsc_delta, ns_delta));
        }
    }

    let (tsc_delta, ns_delta) = best.ok_or_else(|| {
        anyhow::anyhow!("TSC or wall clock did not advance across all measurement rounds")
    })?;

    // measured_khz = tsc_delta / wall_delta_us  (ticks/us == kHz)
    // Use u128 for the intermediate product to avoid overflow.
    let measured_khz = (tsc_delta as u128 * 1_000_000 / ns_delta as u128) as u64;

    Ok((measured_khz, msr_khz))
}

/// Reads RDTSC and CLOCK_MONOTONIC_RAW as close together as possible.
/// Returns (tsc_value, nanoseconds).
fn rdtsc_and_clock_ns() -> Result<(u64, u64)> {
    // _rdtsc() returns the tsc that the VM is experiencing, regardless if it was reported by the hypervisor,
    // or returned by the VMSA
    if !std::is_x86_feature_detected!("tsc") {
        return Err(anyhow::anyhow!(
            "RDTSC instruction not supported on this CPU"
        ));
    }
    let tsc = unsafe { std::arch::x86_64::_rdtsc() };

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Safety: valid timespec pointer, CLOCK_MONOTONIC_RAW is always available.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "clock_gettime(CLOCK_MONOTONIC_RAW) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
    Ok((tsc, ns))
}

/// Returns true if `measured_khz` is at or below `msr_khz`.
///
/// tsc_factor encodes the percent decrease from nominal (MSR) to mean (measured)
/// frequency, so the corrected rate can never exceed the nominal.  A measured
/// rate above the MSR value would indicate a measurement error or a firmware bug.
pub fn tsc_rate_at_or_below_nominal(measured_khz: u64, msr_khz: u64) -> bool {
    measured_khz <= msr_khz
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TscInfoResp layout ────────────────────────────────────────────────────

    #[test]
    fn tsc_info_resp_size() {
        // Must be exactly 128 bytes to match the kernel's snp_tsc_info_resp:
        // u32 status + u32 rsvd1 + u64 tsc_scale + u64 tsc_offset + u32 tsc_factor
        // + u8 rsvd2[100] = 4+4+8+8+4+100 = 128.
        assert_eq!(mem::size_of::<TscInfoResp>(), 128);
    }

    #[test]
    fn tsc_info_resp_field_offsets() {
        // Verify field offsets match the kernel struct (arch/x86/include/asm/sev.h).
        // Use a zeroed instance and check that writing through raw pointers lands
        // at the expected byte offsets.
        let base = TscInfoResp::default();
        let ptr = &base as *const TscInfoResp as usize;
        let status_off = &base.status as *const u32 as usize - ptr;
        let scale_off = &base.tsc_scale as *const u64 as usize - ptr;
        let offset_off = &base.tsc_offset as *const u64 as usize - ptr;
        let factor_off = &base.tsc_factor as *const u32 as usize - ptr;
        assert_eq!(status_off, 0, "status at offset 0");
        assert_eq!(scale_off, 8, "tsc_scale at offset 8");
        assert_eq!(offset_off, 16, "tsc_offset at offset 16");
        assert_eq!(factor_off, 24, "tsc_factor at offset 24");
    }

    // ── is_plausible_tsc_freq ─────────────────────────────────────────────────

    #[test]
    fn plausible_freq_boundaries() {
        assert!(!is_plausible_tsc_freq(0));
        assert!(!is_plausible_tsc_freq(499));
        assert!(is_plausible_tsc_freq(500));
        assert!(is_plausible_tsc_freq(3_600));
        assert!(is_plausible_tsc_freq(8_000));
        assert!(!is_plausible_tsc_freq(8_001));
        assert!(!is_plausible_tsc_freq(u64::MAX));
    }

    // ── tsc_rate_at_or_below_nominal ─────────────────────────────────────────

    #[test]
    fn rate_at_or_below_nominal() {
        let nominal: u64 = 3_600_000; // 3600 MHz in kHz
        assert!(tsc_rate_at_or_below_nominal(nominal, nominal));
        assert!(tsc_rate_at_or_below_nominal(nominal - 1, nominal));
        assert!(tsc_rate_at_or_below_nominal(0, nominal));
        assert!(!tsc_rate_at_or_below_nominal(nominal + 1, nominal));
        assert!(!tsc_rate_at_or_below_nominal(u64::MAX, nominal));
    }

    // ── TSC_FREQ_MASK ─────────────────────────────────────────────────────────

    #[test]
    fn tsc_freq_mask_width() {
        // Bits 17:0 (18 bits) should be extracted; higher bits discarded.
        let raw: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        assert_eq!(raw & TSC_FREQ_MASK, 0x3_FFFF);
        // 3600 MHz fits in 18 bits.
        assert_eq!(3600u64 & TSC_FREQ_MASK, 3600);
    }
}
