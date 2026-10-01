//! Fixed, finite workload for the owned user-service experiment.
//!
//! Running this workload does not create, enable, start or observe a service.
//! Those effects require the separate reviewed adapter and its admission path.

use std::time::Duration;

pub const MAX_DURATION_SECONDS: u64 = 120;

fn duration(args: &[String]) -> Result<Duration, String> {
    let [flag, value] = args else {
        return Err("fixed service payload requires one bounded duration".into());
    };
    if flag != "--duration-seconds"
        || value.is_empty()
        || value.len() > 3
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("fixed service payload arguments are invalid".into());
    }
    let seconds: u64 = value
        .parse()
        .map_err(|_| "fixed service payload duration is invalid")?;
    if !(1..=MAX_DURATION_SECONDS).contains(&seconds) || seconds.to_string() != *value {
        return Err("fixed service payload duration is outside its bounds".into());
    }
    Ok(Duration::from_secs(seconds))
}

/// Wait once, without creating files, synthetic events, subprocesses or sockets.
pub fn run_fixed_wait(args: &[String]) -> Result<i32, String> {
    let wait = duration(args)?;
    #[cfg(target_os = "linux")]
    {
        std::thread::sleep(wait);
        Ok(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = wait;
        Err("owned user-service payload requires Linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(value: &str) -> Vec<String> {
        vec!["--duration-seconds".into(), value.into()]
    }

    #[test]
    fn duration_is_finite_and_canonical() {
        for seconds in [1, 60, MAX_DURATION_SECONDS] {
            assert_eq!(
                duration(&arguments(&seconds.to_string())).unwrap(),
                Duration::from_secs(seconds)
            );
        }
        for value in [
            "",
            "0",
            "121",
            "999999999999",
            "01",
            "+1",
            "-1",
            "1.0",
            "1e2",
            " 1",
            "1\n",
        ] {
            assert!(duration(&arguments(value)).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn payload_accepts_no_command_or_extra_argument() {
        assert!(duration(&[]).is_err());
        assert!(duration(&["60".into()]).is_err());
        assert!(duration(&["--command".into(), "60".into()]).is_err());
        let mut extra = arguments("60");
        extra.push("--duration-seconds".into());
        extra.push("120".into());
        assert!(duration(&extra).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unavailable_platform_refuses_without_waiting() {
        assert!(run_fixed_wait(&arguments("120")).is_err());
    }
}
