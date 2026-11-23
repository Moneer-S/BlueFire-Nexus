use std::path::PathBuf;

use bluefire_runner::contract::INVENTORY_SCHEMA_VERSION;
use bluefire_runner::{
    execute_files, inventory, run_internal_cancellation_descendant, TaskStatus,
    INTERNAL_DESCENDANT_VERB,
};
use serde_json::json;

fn usage() -> &'static str {
    "usage:\n  bluefire-runner inventory [--json]\n  bluefire-runner inspect-native-tool --installation <path> [--json]\n  bluefire-runner inspect-native-tool-candidate --candidate <path> [--json]\n  bluefire-runner execute --manifest <path> --profile <path> [--json]"
}

fn take_flag_value(args: &[String], flag: &str) -> Result<PathBuf, String> {
    let positions = args
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == flag).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!("{flag} must be provided exactly once"));
    }
    let index = positions[0];
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{flag} requires a path"))?;
    if value.starts_with('-') {
        return Err(format!("{flag} requires a path"));
    }
    Ok(PathBuf::from(value))
}

fn execute_command(args: &[String]) -> Result<i32, String> {
    for (index, value) in args.iter().enumerate() {
        let is_value = index > 0 && matches!(args[index - 1].as_str(), "--manifest" | "--profile");
        if !is_value && !matches!(value.as_str(), "--manifest" | "--profile" | "--json") {
            return Err(format!("unknown execute argument: {value}"));
        }
    }
    if args
        .iter()
        .filter(|value| value.as_str() == "--json")
        .count()
        > 1
    {
        return Err("--json must not be repeated".to_string());
    }
    let manifest_path = take_flag_value(args, "--manifest")?;
    let profile_path = take_flag_value(args, "--profile")?;
    if bluefire_runner::service_admission::verify_inherited_files(&manifest_path, &profile_path)?
        .is_some()
    {
        // No reservation may imply possible effects for an unavailable adapter.
        return Err("the fixed owned-service adapter is not registered in this runner".into());
    }
    let result =
        match bluefire_runner::s3_admission::verify_inherited_files(&manifest_path, &profile_path)?
        {
            Some(admission) => bluefire_runner::runner_s3_access::execute_admitted(admission),
            None => {
                execute_files(&manifest_path, &profile_path).map_err(|error| error.to_string())?
            }
        };
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| format!("cannot serialize runner result: {error}"))?
    );
    let code = match result.status {
        TaskStatus::Success => 0,
        TaskStatus::Refused | TaskStatus::ControlBlocked => 3,
        TaskStatus::Partial
        | TaskStatus::Failed
        | TaskStatus::TimedOut
        | TaskStatus::CleanupFailed => 4,
    };
    Ok(code)
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage().to_string());
    };
    match command {
        "macos-file-access-capability" => {
            if args.len() != 1 {
                return Err("the fixed Darwin capability accepts no arguments".into());
            }
            println!("{}", bluefire_runner::macos_file_access::capability());
            Ok(0)
        }
        "macos-file-access-reader" => bluefire_runner::macos_file_access::run_reader(&args[1..]),
        "macos-file-access-owner-control" => {
            bluefire_runner::macos_file_access::run_owner_control(&args[1..])
        }
        "windows-file-correction-worker" => {
            require_no_windows_worker_arguments(&args[1..])?;
            bluefire_runner::windows_file_access_worker::run_fixed_correction()
        }
        "windows-file-correction-worker-capability" => {
            require_no_windows_worker_arguments(&args[1..])?;
            println!(
                "{}",
                bluefire_runner::windows_file_access_worker::correction_protocol_capability()
            );
            Ok(0)
        }
        "windows-file-baseline-worker" => {
            require_no_windows_worker_arguments(&args[1..])?;
            bluefire_runner::windows_file_access_worker::run_fixed_pair()
        }
        "windows-file-baseline-worker-capability" => {
            require_no_windows_worker_arguments(&args[1..])?;
            println!(
                "{}",
                bluefire_runner::windows_file_access_worker::pair_protocol_capability()
            );
            Ok(0)
        }
        "windows-file-worker" => {
            require_no_windows_worker_arguments(&args[1..])?;
            bluefire_runner::windows_file_access_worker::run_fixed()
        }
        "windows-file-worker-capability" => {
            require_no_windows_worker_arguments(&args[1..])?;
            println!(
                "{}",
                bluefire_runner::windows_file_access_worker::protocol_capability()
            );
            Ok(0)
        }
        "ad-smb-worker" => {
            if args.len() != 1 {
                return Err("the fixed AD worker accepts no arguments".into());
            }
            bluefire_runner::ad_smb_worker::run_fixed()
        }
        INTERNAL_DESCENDANT_VERB => {
            if args.len() != 1 {
                return Err("the internal cancellation descendant accepts no arguments".to_string());
            }
            run_internal_cancellation_descendant()
        }
        "inventory" => {
            if args.len() > 2 || (args.len() == 2 && args[1] != "--json") {
                return Err(usage().to_string());
            }
            let response = json!({
                "schema_version": INVENTORY_SCHEMA_VERSION,
                "runner": "bluefire-rust-runner",
                "runner_id": "bluefire-rust-runner.v1",
                "runner_version": env!("CARGO_PKG_VERSION"),
                "action_sdk_version": bluefire_runner::ACTION_SDK_SCHEMA_VERSION,
                "receipt_protocol": bluefire_runner::RECEIPT_PROTOCOL_VERSION,
                "platform": bluefire_runner::Platform::current(),
                "actions": inventory(),
                "provider_runtimes": bluefire_runner::provider_runtimes(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&response)
                    .map_err(|error| format!("cannot serialize action inventory: {error}"))?
            );
            Ok(0)
        }
        "inspect-native-tool" => inspect_command(&args[1..]),
        "inspect-native-tool-candidate" => inspect_candidate_command(&args[1..]),
        "execute" => execute_command(&args[1..]),
        "owned-service-payload" => bluefire_runner::service_payload::run_fixed_wait(&args[1..]),
        _ => Err(usage().to_string()),
    }
}

fn require_no_windows_worker_arguments(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err("the fixed Windows file worker commands accept no arguments".into())
    }
}

fn real_main() -> Result<i32, String> {
    dispatch(&std::env::args().skip(1).collect::<Vec<_>>())
}

fn inspect_candidate_command(args: &[String]) -> Result<i32, String> {
    use std::io::Read;
    for (index, value) in args.iter().enumerate() {
        let is_value = index > 0 && args[index - 1] == "--candidate";
        if !is_value && !matches!(value.as_str(), "--candidate" | "--json") {
            return Err("unknown candidate inspection argument".into());
        }
    }
    if args
        .iter()
        .filter(|value| value.as_str() == "--json")
        .count()
        > 1
    {
        return Err("--json must not be repeated".into());
    }
    let path = take_flag_value(args, "--candidate")?;
    let file = std::fs::File::open(path).map_err(|_| "cannot open candidate record")?;
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read candidate record")?;
    if bytes.len() > 16_384 {
        return Err("candidate record exceeds the size limit".into());
    }
    let candidate = serde_json::from_slice(&bytes).map_err(|_| "invalid candidate record")?;
    let response = bluefire_runner::inspect_candidate(&candidate);
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|_| "cannot serialize candidate inspection")?
    );
    Ok(0)
}

fn inspect_command(args: &[String]) -> Result<i32, String> {
    use std::io::Read;
    for (index, value) in args.iter().enumerate() {
        let is_value = index > 0 && args[index - 1] == "--installation";
        if !is_value && !matches!(value.as_str(), "--installation" | "--json") {
            return Err("unknown tool inspection argument".into());
        }
    }
    if args
        .iter()
        .filter(|value| value.as_str() == "--json")
        .count()
        > 1
    {
        return Err("--json must not be repeated".into());
    }
    let path = take_flag_value(args, "--installation")?;
    let file = std::fs::File::open(path).map_err(|_| "cannot open installation record")?;
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read installation record")?;
    if bytes.len() > 16_384 {
        return Err("installation record exceeds the size limit".into());
    }
    let installation = serde_json::from_slice(&bytes).map_err(|_| "invalid installation record")?;
    let response = bluefire_runner::inspect_installation(&installation);
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|_| "cannot serialize inspection")?
    );
    Ok(0)
}

fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_windows_commands_reject_every_argument_before_dispatch() {
        for command in [
            "windows-file-worker",
            "windows-file-worker-capability",
            "windows-file-baseline-worker",
            "windows-file-baseline-worker-capability",
            "windows-file-correction-worker",
            "windows-file-correction-worker-capability",
        ] {
            for argument in [
                "--json",
                "--manifest",
                "--profile",
                "--password",
                "--path",
                "--command",
                "",
                "synthetic-private-value",
            ] {
                assert_eq!(
                    dispatch(&[command.into(), argument.into()]),
                    Err("the fixed Windows file worker commands accept no arguments".into())
                );
            }
        }
    }

    #[test]
    fn private_windows_capability_is_a_no_input_query() {
        assert_eq!(dispatch(&["windows-file-worker-capability".into()]), Ok(0));
        assert_eq!(
            dispatch(&["windows-file-baseline-worker-capability".into()]),
            Ok(0)
        );
        assert_eq!(
            dispatch(&["windows-file-correction-worker-capability".into()]),
            Ok(0)
        );
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn unsupported_windows_worker_refuses_without_reading_stdin() {
        assert_eq!(
            dispatch(&["windows-file-worker".into()]),
            Err("the fixed Windows file worker requires Windows x86_64".into())
        );
        assert_eq!(
            dispatch(&["windows-file-baseline-worker".into()]),
            Err("the fixed Windows file worker requires Windows x86_64".into())
        );
        assert_eq!(
            dispatch(&["windows-file-correction-worker".into()]),
            Err("the fixed Windows file worker requires Windows x86_64".into())
        );
    }
}
