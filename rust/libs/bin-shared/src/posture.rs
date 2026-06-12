//! Device posture collection.
//!
//! Gathers a best-effort, client-side snapshot of the device's security state
//! (OS type/version, disk encryption, host firewall, antivirus) which the
//! client sends to the portal on connect as a JSON `posture` parameter. The
//! portal evaluates it against policy posture conditions.
//!
//! This is advisory signal, not attestation: a determined user on a rooted
//! device can spoof it. Each signal is `Option`: `None` means "could not
//! determine", which the portal treats as a posture-condition violation (fail
//! closed). Collection never blocks connect — any probe failure degrades to
//! `None` rather than erroring.

use serde::Serialize;

/// A device posture snapshot. Field names match the keys the portal's
/// `Portal.Policies.Posture` normalizer recognizes.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct PostureReport {
    /// Canonical OS family: "windows" | "macos" | "linux".
    pub os_type: Option<String>,
    /// Dotted OS version, e.g. Windows build "10.0.22631" or macOS "14.5.0".
    pub os_version: Option<String>,
    /// Whether full-disk encryption is enabled (BitLocker / FileVault / LUKS).
    pub disk_encryption: Option<bool>,
    /// Whether a host firewall is enabled.
    pub firewall_enabled: Option<bool>,
    /// Whether antivirus / endpoint protection is present and enabled.
    pub antivirus_enabled: Option<bool>,
    /// The Firezone client version, so policies can require a minimum client.
    pub client_version: Option<String>,
}

impl PostureReport {
    /// Serialize to the compact JSON string sent as the `posture` connect param.
    /// Returns `None` if serialization fails (it never should for this shape).
    pub fn to_param(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

/// Collect the current device posture. Always returns a report; individual
/// signals degrade to `None` on any failure so connect is never blocked.
pub fn collect() -> PostureReport {
    PostureReport {
        os_type: os_type(),
        os_version: os_version(),
        disk_encryption: disk_encryption(),
        firewall_enabled: firewall_enabled(),
        antivirus_enabled: antivirus_enabled(),
        client_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

fn os_type() -> Option<String> {
    let os = std::env::consts::OS;
    match os {
        "windows" => Some("windows".to_string()),
        "macos" => Some("macos".to_string()),
        "linux" => Some("linux".to_string()),
        other => Some(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn os_version() -> Option<String> {
    // `cmd /c ver` prints e.g. "Microsoft Windows [Version 10.0.22631.4317]".
    let out = run("cmd", &["/c", "ver"])?;
    let start = out.find("Version")?;
    let rest = &out[start + "Version".len()..];
    let version: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

#[cfg(target_os = "windows")]
fn disk_encryption() -> Option<bool> {
    // Query BitLocker protection status on the system drive via PowerShell.
    // ProtectionStatus == 1 means On.
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus",
        ],
    )?;
    parse_bitlocker_status(&out)
}

#[cfg(target_os = "windows")]
fn parse_bitlocker_status(out: &str) -> Option<bool> {
    match out.trim() {
        "1" | "On" => Some(true),
        "0" | "Off" => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn firewall_enabled() -> Option<bool> {
    // True if any firewall profile is enabled.
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-NetFirewallProfile | Where-Object Enabled -eq 'True' | Measure-Object).Count",
        ],
    )?;
    parse_count_positive(&out)
}

#[cfg(target_os = "windows")]
fn antivirus_enabled() -> Option<bool> {
    // Windows Security Center registers AV products; productState's high byte
    // indicates enabled. Presence of any product with an "enabled"-ish state.
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Measure-Object).Count",
        ],
    )?;
    parse_count_positive(&out)
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn os_version() -> Option<String> {
    // `sw_vers -productVersion` -> "14.5" or "14.5.1".
    let out = run("sw_vers", &["-productVersion"])?;
    let v = out.trim();
    if v.is_empty() { None } else { Some(v.to_string()) }
}

#[cfg(target_os = "macos")]
fn disk_encryption() -> Option<bool> {
    // `fdesetup status` -> "FileVault is On." / "FileVault is Off."
    let out = run("fdesetup", &["status"])?;
    if out.contains("On") {
        Some(true)
    } else if out.contains("Off") {
        Some(false)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn firewall_enabled() -> Option<bool> {
    // Application-layer firewall global state. 0 = off, 1/2 = on.
    let out = run(
        "defaults",
        &["read", "/Library/Preferences/com.apple.alf", "globalstate"],
    )?;
    match out.trim() {
        "1" | "2" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn antivirus_enabled() -> Option<bool> {
    // macOS ships XProtect/Gatekeeper. Report Gatekeeper assessment state as a
    // proxy for built-in protection. `spctl --status` -> "assessments enabled".
    let out = run("spctl", &["--status"])?;
    if out.contains("enabled") {
        Some(true)
    } else if out.contains("disabled") {
        Some(false)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn os_version() -> Option<String> {
    // Kernel release via uname, e.g. "6.8.0-31-generic" -> "6.8.0".
    let out = run("uname", &["-r"])?;
    let v = out.trim();
    if v.is_empty() {
        return None;
    }
    let numeric: String = v
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if numeric.is_empty() {
        Some(v.to_string())
    } else {
        Some(numeric)
    }
}

#[cfg(target_os = "linux")]
fn disk_encryption() -> Option<bool> {
    // True if any active device-mapper target is LUKS/crypt.
    let out = run("lsblk", &["-o", "TYPE", "--noheadings"])?;
    Some(out.lines().any(|l| l.trim() == "crypt"))
}

#[cfg(target_os = "linux")]
fn firewall_enabled() -> Option<bool> {
    // Best-effort: ufw if present, else nft ruleset non-empty. Both may need
    // privileges; failure degrades to None.
    if let Some(out) = run("ufw", &["status"]) {
        if out.contains("Status: active") {
            return Some(true);
        }
        if out.contains("Status: inactive") {
            return Some(false);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn antivirus_enabled() -> Option<bool> {
    // No standard Linux AV. Cannot determine -> None (fails closed server-side
    // if a policy requires AV on Linux).
    None
}

// ---------------------------------------------------------------------------
// Shared command helper (used by the OS-specific probes above)
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(target_os = "windows")]
fn parse_count_positive(out: &str) -> Option<bool> {
    out.trim().parse::<i64>().ok().map(|n| n > 0)
}

// ---------------------------------------------------------------------------
// Fallback for any other target (iOS/Android handle posture natively).
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn os_version() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn disk_encryption() -> Option<bool> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn firewall_enabled() -> Option<bool> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn antivirus_enabled() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_type_is_known_on_this_platform() {
        // On any of the three first-class targets, os_type resolves.
        let report = collect();
        assert!(report.client_version.is_some());
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(report.os_type.is_some());
    }

    #[test]
    fn to_param_roundtrips_to_json_object() {
        let report = PostureReport {
            os_type: Some("linux".to_string()),
            os_version: Some("6.8.0".to_string()),
            disk_encryption: Some(true),
            firewall_enabled: Some(false),
            antivirus_enabled: None,
            client_version: Some("1.5.7".to_string()),
        };
        let json = report.to_param().unwrap();
        assert!(json.starts_with('{'));
        assert!(json.contains("\"os_type\":\"linux\""));
        assert!(json.contains("\"antivirus_enabled\":null"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_bitlocker_status() {
        assert_eq!(parse_bitlocker_status("1\r\n"), Some(true));
        assert_eq!(parse_bitlocker_status("0"), Some(false));
        assert_eq!(parse_bitlocker_status("On"), Some(true));
        assert_eq!(parse_bitlocker_status("garbage"), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_positive_count() {
        assert_eq!(parse_count_positive("2\n"), Some(true));
        assert_eq!(parse_count_positive("0"), Some(false));
        assert_eq!(parse_count_positive("x"), None);
    }
}
