//! Fork detection security test.
//!
//! Verifies that after fork(), the child process receives
//! CKR_CRYPTOKI_NOT_INITIALIZED on any PKCS#11 call, preventing
//! accidental reuse of parent's cryptographic state.

#![allow(non_snake_case)]

#[cfg(unix)]
mod fork_tests {
    use craton_hsm::pkcs11_abi::constants::*;
    use craton_hsm::pkcs11_abi::functions::*;
    use craton_hsm::pkcs11_abi::types::*;
    use std::ptr;

    /// After fork(), the child inherits the parent's global HSM but
    /// `INIT_PID` still holds the parent's PID.  Every PKCS#11 function
    /// that routes through `get_hsm()` must detect the mismatch and
    /// return `CKR_CRYPTOKI_NOT_INITIALIZED`.
    #[test]
    fn test_fork_child_gets_not_initialized() {
        // Initialize in parent
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: 0x{:08X}",
            rv
        );

        // Fork
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            // ---- CHILD process ----
            //
            // Verify that multiple PKCS#11 API calls are all rejected.
            // Exit codes 1..N identify which check failed if one does.

            // 1) C_GetSlotList must be rejected
            let mut slot_count: CK_ULONG = 0;
            let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut slot_count);
            if rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                unsafe { libc::_exit(1) };
            }

            // 2) C_GetInfo must be rejected
            let mut info: CK_INFO = unsafe { std::mem::zeroed() };
            let rv = C_GetInfo(&mut info);
            if rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                unsafe { libc::_exit(2) };
            }

            // 3) C_GetSlotInfo must be rejected
            let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
            let rv = C_GetSlotInfo(0, &mut slot_info);
            if rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                unsafe { libc::_exit(3) };
            }

            // 4) C_OpenSession must be rejected
            let mut session: CK_SESSION_HANDLE = 0;
            let rv = C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut session,
            );
            if rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                unsafe { libc::_exit(4) };
            }

            // All checks passed
            unsafe { libc::_exit(0) };
        } else {
            // ---- PARENT process ----
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };

            // Verify child exited cleanly
            assert!(
                libc::WIFEXITED(status),
                "child did not exit normally (status: {})",
                status
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child reported fork detection failure (exit code: {})",
                libc::WEXITSTATUS(status)
            );

            // Clean up parent
            let rv = C_Finalize(ptr::null_mut());
            assert!(
                rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED,
                "C_Finalize failed: 0x{:08X}",
                rv
            );
        }
    }
}
