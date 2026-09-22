//! Authored contract expectations, independently checked against compiled source.
use serde_json::Value;

#[test]
fn compiled_optional_tool_descriptors_match_reviewed_contracts() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/native_tool_descriptors_v1.json"
    ))
    .unwrap();
    assert_eq!(
        expected["schema_version"],
        "bluefire.native-tool-descriptor-expectations.v1"
    );
    let actual: Vec<Value> = bluefire_runner::inventory()
        .into_iter()
        .filter(|row| {
            matches!(
                row.action_id,
                "sandbox.collection.atomic-gzip.v1" | "sandbox.permission.chmod.v1"
            )
        })
        .map(|row| serde_json::to_value(row).unwrap())
        .collect();
    let mut expected = expected["actions"].as_array().unwrap().clone();
    let mut actual = actual;
    actual.sort_by_key(|row| row["action_id"].as_str().unwrap().to_owned());
    expected.sort_by_key(|row| row["action_id"].as_str().unwrap().to_owned());
    assert_eq!(expected.len(), 2);
    assert_eq!(actual, expected);
}
