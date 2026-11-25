# Scope

What BlueFire Nexus covers today, what it does not, and the terms you use it under.

BlueFire Nexus 3.0.0-rc2 is a prerelease, not a stable release.

## Current scope

BlueFire brings experiment planning, review, execution, run inspection, and detection work into one local workspace. The optional Assistant supports drafting and revision; manual editing and simulation are available with AI Off. Deterministic and fixture-backed checks do not establish live model inference, and native action support varies by method and platform. Remote runners, broad Active Directory coverage, and production EDR/SIEM collection integrations are not shipped.

Generated fixtures and hosted CI are not customer-host, Active Directory, or AWS validation. S3 audit dispatch remains gated by `DISPATCH_RELEASED = false`. See the [program phases](AI_FIRST_PROGRAM.md), [capability reference](RELEASE_CAPABILITIES.md), [Windows paired readable-baseline guide](WINDOWS_FILE_ACCESS_BASELINE.md), and [roadmap](https://github.com/Moneer-S/BlueFire-Nexus/issues/202).

## License

[MIT](../LICENSE). Third-party components retain their own [licenses and attribution](../THIRD_PARTY_NOTICES.md).

Use BlueFire only on systems you own or are authorized to test. Keep the web service local. For security reports, follow [SECURITY.md](../SECURITY.md).
