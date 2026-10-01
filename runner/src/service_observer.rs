//! Bounded parsing for a future independent service observer, never observation authority.
//!
//! Callers can author these bytes. Parsed properties prove neither their source nor
//! filesystem/cgroup ownership, freshness, cleanup or an operation's success. This
//! module performs no I/O and cannot construct a reconciliation token.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::service_operation_binding::ServiceOperationBinding;

pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_CGROUP_BYTES: usize = 128;
const MANAGER_FIELDS: [&str; 6] = [
    "Id",
    "LoadState",
    "ActiveState",
    "InvocationID",
    "MainPID",
    "ControlGroup",
];
const USER_MANAGER_FIELDS: [&str; 2] = ["ControlGroup", "UnitPath"];
const UNIT_FIELDS: [&str; 10] = [
    "Id",
    "Names",
    "LoadState",
    "ActiveState",
    "ControlGroup",
    "FragmentPath",
    "DropInPaths",
    "UnitFileState",
    "Transient",
    "NeedDaemonReload",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertyQuery {
    OwnerManager,
    UserManager,
    OwnedUnit,
}

/// Completion metadata is supplied by the future trusted bounded reader.
/// Marking caller-authored data complete does not authenticate it.
#[derive(Clone, Copy, Debug)]
pub enum ReadOutcome<'a> {
    Unavailable,
    Finished {
        bytes: &'a [u8],
        exit_code: i32,
        truncated: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationIssue {
    Unavailable(&'static str),
    Unknown(&'static str),
    IdentityMismatch(&'static str),
}

// Projection only: ServiceOperationBinding already checked its closed v1 schema.
// Retain the complete binding below, including authorization and target digests.
#[derive(Deserialize)]
struct BindingProjection {
    identity: IdentityProjection,
}

#[derive(Deserialize)]
struct IdentityProjection {
    owner_uid: u32,
    manager_id: String,
    unit_nonce: String,
}

pub struct ObservationTarget {
    binding: ServiceOperationBinding,
    identity: IdentityProjection,
    unit_name: String,
}

/// Reported values use the existing observation vocabulary. They are not an
/// EvidenceRecord, an observer attestation, or a verified-absence assessment.
#[derive(Debug, PartialEq, Eq)]
pub struct ReportedServiceProperties {
    binding: ServiceOperationBinding,
    pub manager_pid: u32,
    pub manager_control_group: String,
    pub unit_search_paths: Vec<String>,
    pub unit_load_state: &'static str,
    pub unit_active_state: &'static str,
    pub unit_control_group: Option<String>,
    pub fragment_path: Option<String>,
    /// systemctl's enablement report, not the observed identity of a unit file.
    pub manager_unit_file_state: String,
    pub cgroup_state: &'static str,
    pub cgroup_frozen: bool,
}

impl ReportedServiceProperties {
    pub fn binding(&self) -> &ServiceOperationBinding {
        &self.binding
    }
}

impl ObservationTarget {
    pub fn from_binding(binding: &ServiceOperationBinding) -> Result<Self, ObservationIssue> {
        let projection: BindingProjection = serde_json::from_str(binding.canonical_json())
            .map_err(|_| ObservationIssue::Unknown("binding_projection"))?;
        Ok(Self {
            binding: binding.clone(),
            unit_name: format!("bluefire-{}.service", projection.identity.unit_nonce),
            identity: projection.identity,
        })
    }

    pub fn binding(&self) -> &ServiceOperationBinding {
        &self.binding
    }

    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    /// Fixed arguments only; the future reader must separately supply a held,
    /// reviewed installation. No executable, verb, unit or endpoint input exists.
    pub fn query_arguments(&self, query: PropertyQuery) -> Vec<String> {
        let (scope, fields, unit) = match query {
            PropertyQuery::OwnerManager => (
                "--system",
                MANAGER_FIELDS.as_slice(),
                Some(format!("user@{}.service", self.identity.owner_uid)),
            ),
            PropertyQuery::UserManager => ("--user", USER_MANAGER_FIELDS.as_slice(), None),
            PropertyQuery::OwnedUnit => (
                "--user",
                UNIT_FIELDS.as_slice(),
                Some(self.unit_name.clone()),
            ),
        };
        let mut arguments = vec![
            scope.into(),
            "--no-pager".into(),
            "--no-ask-password".into(),
            "show".into(),
            "--all".into(),
            format!("--property={}", fields.join(",")),
        ];
        arguments.extend(unit);
        arguments
    }

    /// Description for a future cleared user-query environment, not inherited
    /// variables or permission to connect. Force the exact scope's session bus:
    /// the reviewed systemctl otherwise prefers the manager's private socket.
    pub fn user_bus_environment(&self) -> [(&'static str, String); 3] {
        let runtime = format!("/run/user/{}", self.identity.owner_uid);
        [
            ("SYSTEMCTL_FORCE_BUS", "1".into()),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={runtime}/bus"),
            ),
            ("XDG_RUNTIME_DIR", runtime),
        ]
    }

    pub fn parse_reported_properties(
        &self,
        owner_manager: ReadOutcome<'_>,
        user_manager: ReadOutcome<'_>,
        unit: ReadOutcome<'_>,
        cgroup_events: ReadOutcome<'_>,
    ) -> Result<ReportedServiceProperties, ObservationIssue> {
        let manager = fields(
            owner_manager,
            &MANAGER_FIELDS,
            '=',
            MAX_QUERY_BYTES,
            "manager",
        )?;
        if manager["Id"] != format!("user@{}.service", self.identity.owner_uid) {
            return Err(ObservationIssue::IdentityMismatch("manager_unit"));
        }
        match (manager["LoadState"], manager["ActiveState"]) {
            ("loaded", "active") => {}
            ("not-found", "inactive") | ("loaded", "inactive" | "failed") => {
                return Err(ObservationIssue::Unavailable("manager_inactive"));
            }
            _ => return Err(ObservationIssue::Unknown("manager_state")),
        }
        if !nonce(manager["InvocationID"]) {
            return Err(ObservationIssue::Unknown("manager_invocation"));
        }
        if manager["InvocationID"] != self.identity.manager_id {
            return Err(ObservationIssue::IdentityMismatch("manager_invocation"));
        }
        let manager_pid = manager["MainPID"]
            .parse::<u32>()
            .ok()
            .filter(|pid| {
                *pid > 0 && *pid <= i32::MAX as u32 && pid.to_string() == manager["MainPID"]
            })
            .ok_or(ObservationIssue::Unknown("manager_pid"))?;
        let manager_group = manager["ControlGroup"];
        if !absolute_path(manager_group) {
            return Err(ObservationIssue::Unknown("manager_cgroup"));
        }
        if !manager_group.ends_with(&format!("/user@{}.service", self.identity.owner_uid)) {
            return Err(ObservationIssue::IdentityMismatch("manager_cgroup"));
        }
        let user = fields(
            user_manager,
            &USER_MANAGER_FIELDS,
            '=',
            MAX_QUERY_BYTES,
            "user_manager",
        )?;
        if !absolute_path(user["ControlGroup"]) {
            return Err(ObservationIssue::Unknown("user_manager_cgroup"));
        }
        if user["ControlGroup"] != manager_group {
            return Err(ObservationIssue::IdentityMismatch("user_manager_cgroup"));
        }
        let paths: Vec<_> = user["UnitPath"].split(' ').collect();
        if paths.is_empty()
            || paths.len() > 32
            || paths.iter().any(|path| !absolute_path(path))
            || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
        {
            return Err(ObservationIssue::Unknown("unit_search_paths"));
        }
        let unit = fields(unit, &UNIT_FIELDS, '=', MAX_QUERY_BYTES, "unit")?;
        if unit["Id"] != self.unit_name || unit["Names"] != self.unit_name {
            return Err(ObservationIssue::IdentityMismatch("unit_name_or_alias"));
        }
        if !unit["DropInPaths"].is_empty() || unit["Transient"] == "yes" {
            return Err(ObservationIssue::IdentityMismatch("unit_configuration"));
        }
        if unit["Transient"] != "no" || unit["NeedDaemonReload"] != "no" {
            return Err(ObservationIssue::Unknown("unit_configuration"));
        }
        let active = match unit["ActiveState"] {
            "active" => "active",
            "inactive" => "inactive",
            "failed" => "failed",
            _ => return Err(ObservationIssue::Unknown("unit_active_state")),
        };
        let load = match unit["LoadState"] {
            "not-found"
                if active == "inactive"
                    && unit["ControlGroup"].is_empty()
                    && unit["FragmentPath"].is_empty()
                    && unit["UnitFileState"].is_empty() =>
            {
                "absent"
            }
            "loaded" => "loaded",
            _ => return Err(ObservationIssue::Unknown("unit_load_state")),
        };
        if load == "loaded" {
            if !absolute_path(unit["FragmentPath"]) {
                return Err(ObservationIssue::Unknown("unit_fragment"));
            }
            if !paths
                .iter()
                .any(|path| unit["FragmentPath"] == format!("{path}/{}", self.unit_name))
            {
                return Err(ObservationIssue::IdentityMismatch("unit_fragment"));
            }
            if !matches!(
                unit["UnitFileState"],
                "enabled" | "enabled-runtime" | "disabled"
            ) {
                return Err(ObservationIssue::Unknown("unit_file_state"));
            }
        }
        let group = unit["ControlGroup"];
        if group.is_empty() {
            if active != "inactive" {
                return Err(ObservationIssue::Unknown("unit_cgroup_missing"));
            }
        } else {
            if !absolute_path(group) {
                return Err(ObservationIssue::Unknown("unit_cgroup"));
            }
            if !group.starts_with(&format!("{manager_group}/"))
                || !group.ends_with(&format!("/{}", self.unit_name))
            {
                return Err(ObservationIssue::IdentityMismatch("unit_cgroup"));
            }
        }
        let cgroup = fields(
            cgroup_events,
            &["populated", "frozen"],
            ' ',
            MAX_CGROUP_BYTES,
            "cgroup",
        )?;
        let populated = bit(cgroup["populated"])?;
        let frozen = bit(cgroup["frozen"])?;
        Ok(ReportedServiceProperties {
            binding: self.binding.clone(),
            manager_pid,
            manager_control_group: manager_group.into(),
            unit_search_paths: paths.into_iter().map(str::to_string).collect(),
            unit_load_state: load,
            unit_active_state: active,
            unit_control_group: (!group.is_empty()).then(|| group.to_string()),
            fragment_path: (!unit["FragmentPath"].is_empty())
                .then(|| unit["FragmentPath"].to_string()),
            manager_unit_file_state: unit["UnitFileState"].into(),
            cgroup_state: if populated { "populated" } else { "empty" },
            cgroup_frozen: frozen,
        })
    }
}

fn fields<'a>(
    outcome: ReadOutcome<'a>,
    expected: &[&str],
    separator: char,
    maximum: usize,
    source: &'static str,
) -> Result<BTreeMap<&'a str, &'a str>, ObservationIssue> {
    let bytes = match outcome {
        ReadOutcome::Unavailable => return Err(ObservationIssue::Unavailable(source)),
        ReadOutcome::Finished {
            bytes,
            exit_code: 0,
            truncated: false,
        } => bytes,
        ReadOutcome::Finished { .. } => return Err(ObservationIssue::Unknown(source)),
    };
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes.ends_with(b"\n")
        || bytes
            .iter()
            .any(|byte| !matches!(*byte, b'\n' | b' '..=b'~'))
    {
        return Err(ObservationIssue::Unknown(source));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ObservationIssue::Unknown(source))?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once(separator)
            .ok_or(ObservationIssue::Unknown(source))?;
        if line.len() > 4096 || !expected.contains(&name) || result.insert(name, value).is_some() {
            return Err(ObservationIssue::Unknown(source));
        }
    }
    if result.len() != expected.len() {
        return Err(ObservationIssue::Unknown(source));
    }
    Ok(result)
}

fn absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-@".contains(&byte))
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn nonce(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bit(value: &str) -> Result<bool, ObservationIssue> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(ObservationIssue::Unknown("cgroup_value")),
    }
}

#[cfg(test)]
#[path = "service_observer_tests.rs"]
mod tests;
