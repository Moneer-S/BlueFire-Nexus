//! Independently check the one supported structural policy edit, not effective access.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_scope::{require, role_arn, Checked, Scope};

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum Values {
    One(String),
    Many(Vec<String>),
}

impl Values {
    fn values(&self, maximum: usize) -> Checked<Vec<&str>> {
        let values = match self {
            Self::One(value) => vec![value.as_str()],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        };
        require((1..=maximum).contains(&values.len()))?;
        require(values.iter().copied().collect::<BTreeSet<_>>().len() == values.len())?;
        Ok(values)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Principal {
    #[serde(rename = "AWS")]
    aws: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct Statement {
    sid: String,
    effect: String,
    principal: Principal,
    action: Values,
    resource: Values,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub(super) struct Policy {
    version: String,
    statement: Vec<Statement>,
}

pub(super) fn encoded<T: Serialize>(value: &T) -> Checked<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| "S3 binding cannot be encoded")
}

impl Policy {
    fn validate(&self, scope: &Scope, hardened: bool) -> Checked<()> {
        require(canonical_json(&encoded(self)?).len() <= 20 * 1024)?;
        require(self.version == "2012-10-17" && (1..=32).contains(&self.statement.len()))?;
        let resources = scope.object_arns();
        let mut sids = BTreeSet::new();
        let mut routes = BTreeSet::new();
        let mut probe = 0;
        let mut legitimate = 0;
        for statement in &self.statement {
            require(
                (1..=128).contains(&statement.sid.len())
                    && statement
                        .sid
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric())
                    && sids.insert(&statement.sid),
            )?;
            require(["Allow", "Deny"].contains(&statement.effect.as_str()))?;
            require(statement.action.values(1)? == ["s3:GetObject"])?;
            let role = &statement.principal.aws;
            require(role_arn(role, &scope.account_id) && role != &scope.roles.controller)?;
            let bound = statement.resource.values(2)?;
            for resource in &bound {
                require(
                    resources
                        .iter()
                        .any(|expected| expected.as_str() == *resource),
                )?;
                require(routes.insert((role, *resource)))?;
            }
            if role == &scope.roles.probe {
                require(
                    statement.sid == scope.policy.probe_sid
                        && statement.effect == "Allow"
                        && bound == [resources[0].as_str()],
                )?;
                probe += 1;
            } else if role == &scope.roles.legitimate {
                require(
                    statement.sid == scope.policy.legitimate_sid
                        && statement.effect == "Allow"
                        && bound.len() == 2,
                )?;
                legitimate += 1;
            } else {
                require(
                    statement.sid != scope.policy.probe_sid
                        && statement.sid != scope.policy.legitimate_sid,
                )?;
            }
        }
        require(probe == if hardened { 0 } else { 1 })?;
        require(legitimate == 1)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyChange {
    schema_version: String,
    scope_digest: String,
    before: Policy,
    before_digest: String,
    after: Policy,
    after_digest: String,
    removed_sid: String,
}

impl PolicyChange {
    pub fn validate(&self, scope: &Scope) -> Checked<()> {
        require(self.schema_version == "bluefire.s3-access-policy-change.v1")?;
        require(self.scope_digest == canonical_hash(&encoded(scope)?))?;
        self.before.validate(scope, false)?;
        self.after.validate(scope, true)?;
        require(
            self.before_digest == canonical_hash(&encoded(&self.before)?)
                && self.before_digest == scope.policy.baseline_digest
                && self.after_digest == canonical_hash(&encoded(&self.after)?)
                && self.removed_sid == scope.policy.probe_sid,
        )?;
        let mut derived = self.before.clone();
        derived
            .statement
            .retain(|statement| statement.sid != self.removed_sid);
        // Compare the complete structural document, retaining order and scalar/list shape.
        require(encoded(&derived)? == encoded(&self.after)?)
    }

    pub fn payload_digest(&self, rollback: bool) -> Checked<String> {
        Ok(canonical_hash(&encoded(if rollback {
            &self.before
        } else {
            &self.after
        })?))
    }
}
