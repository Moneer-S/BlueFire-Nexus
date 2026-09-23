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
    let result = execute_files(&manifest_path, &profile_path).map_err(|error| error.to_string())?;
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

fn real_main() -> Result<i32, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage().to_string());
    };
    match command {
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
        _ => Err(usage().to_string()),
    }
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
