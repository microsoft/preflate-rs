use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};
use tempfile::tempdir;

fn request() -> Value {
    serde_json::from_slice(
        &fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("replay.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn run(request: &Value) -> (Output, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_preflate_replay"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(request).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let result = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, result)
}

#[test]
fn replay_reports_later_blocks_with_preceding_dictionary_context() {
    let (output, result) = run(&request());
    assert!(output.status.success(), "{result}");
    assert!(output.stderr.is_empty());
    let result = &result["result"];
    assert_eq!(result["verified"], true);
    assert_eq!(result["total_blocks"], 3);
    assert_eq!(result["total_tokens"], 6);
    assert_eq!(result["plaintext_bytes"], 28);
    assert_eq!(result["reported_tokens"], 1);
    assert_eq!(result["reported_mismatches"], 0);
    assert_eq!(result["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(result["blocks"][0]["index"], 2);
    assert_eq!(result["blocks"][0]["plaintext_offset"], 16);
    assert_eq!(result["blocks"][0]["dictionary_reset"], false);
    assert!(result["reconstruction_bytes"].as_u64().unwrap() > 0);
    assert_eq!(result["effective_parameters"], result["parameters"]);
}

#[test]
fn replay_without_encoding_labels_unverified_results() {
    let mut input = request();
    input["options"]["encode"] = json!(false);
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert!(result["result"]["verified"].is_null());
    assert!(result["result"]["reconstruction_bytes"].is_null());
    assert_eq!(result["result"]["reported_tokens"], 1);
}

#[test]
fn replay_rejects_bad_parameters_ranges_tokens_limits_and_unknown_fields() {
    let mut cases = Vec::new();
    let mut input = request();
    input["parameters"]["window_bits"] = json!(32);
    cases.push(input);
    let mut input = request();
    input["parameters"]["hash_algorithm"]["Zlib"]["hash_shift"] = json!(16);
    cases.push(input);
    let mut input = request();
    input["parameters"]["surprise"] = json!(true);
    cases.push(input);
    let mut input = request();
    input["options"]["block_start"] = json!(3);
    cases.push(input);
    let mut input = request();
    input["options"]["max_tokens"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_blocks"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_plaintext_bytes"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_input_bytes"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["tokens"][4]["length"] = json!(2);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["tokens"][4]["distance"] = json!(5);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["last"] = json!(true);
    cases.push(input);
    for input in cases {
        let (output, result) = run(&input);
        assert!(!output.status.success(), "{input}");
        assert_eq!(result["status"], "error", "{result}");
        assert_eq!(result["error"]["code"], "InvalidParameter", "{result}");
    }
}

#[test]
fn replay_reads_exact_file_ranges_and_never_overwrites_output() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("wrapped.bin");
    // A final stored block containing "abc", surrounded by non-stream bytes.
    fs::write(&source, b"XX\x01\x03\x00\xfc\xffabcYY").unwrap();
    let mut input = request();
    input["source"] = json!({"type": "file", "path": source, "offset": 2, "length": 8});
    input["options"] = json!({});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["compressed_bytes"], 8);
    assert_eq!(result["result"]["plaintext_bytes"], 3);
    assert_eq!(result["result"]["verified"], true);
    let request_path = directory.path().join("request.json");
    fs::write(&request_path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output_path = directory.path().join("result.json");
    fs::write(&output_path, b"do not replace").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_preflate_replay"))
        .arg(request_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), b"do not replace");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot write replay result")
    );
}

#[test]
fn replay_preserves_parameters_and_bounds_mismatch_examples() {
    let mut input = request();
    input["source"] = json!({
        "type": "blocks",
        "blocks": [{
            "type": "huffman", "last": true,
            "tokens": (0..100).map(|_| json!({"type":"literal", "value":97})).collect::<Vec<_>>()
        }]
    });
    input["options"] = json!({"max_mismatches": 2});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    let result = &result["result"];
    assert_eq!(result["verified"], true);
    assert_eq!(result["parameters"], input["parameters"]);
    assert_eq!(result["effective_parameters"], input["parameters"]);
    assert!(result["total_mismatches"].as_u64().unwrap() > 2);
    assert_eq!(result["mismatches"].as_array().unwrap().len(), 2);
    assert_eq!(result["mismatches_truncated"], true);
    for mismatch in result["mismatches"].as_array().unwrap() {
        assert!(mismatch["actual"].get("value").is_none());
    }
}

#[test]
fn replay_enforces_raw_stream_limits_during_parsing() {
    let mut input = request();
    let blocks = serde_json::from_value(input["source"]["blocks"].clone()).unwrap();
    let bytes = preflate_rs::diagnostics::encode_replay_blocks(
        blocks,
        &preflate_rs::diagnostics::ReplayOptions::default(),
    )
    .unwrap();
    input["source"] = json!({"type":"deflate","bytes":bytes});
    input["options"] = json!({"max_tokens":6,"max_blocks":3});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    for (tokens, blocks) in [(5, 3), (6, 2)] {
        input["options"] = json!({"max_tokens":tokens,"max_blocks":blocks});
        let (output, result) = run(&input);
        assert!(!output.status.success());
        assert_eq!(result["error"]["code"], "InvalidParameter");
    }

    // Stop at the block budget rather than inspecting a malformed later block.
    input["source"] = json!({"type":"deflate","bytes":[0,0,0,255,255,7]});
    input["options"] = json!({"max_blocks":1});
    let (output, result) = run(&input);
    assert!(!output.status.success());
    assert_eq!(result["error"]["code"], "InvalidParameter");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_blocks")
    );
}

#[test]
fn typed_parameter_json_roundtrips_all_supplied_variants() {
    let matching = [
        json!("Greedy"),
        json!({"Lazy":{"max_lazy":16,"filtered_matching":false,"behavior":{"Zlib":{"good_length":8}}}}),
        json!({"Lazy":{"max_lazy":16,"filtered_matching":true,"behavior":"RecomputeAfterLiteral"}}),
        json!({"MiniZ":{"max_probes":128,"greedy":false}}),
        json!({"LibdeflateLazy":{"two_positions":true}}),
        json!("LibdeflateGreedy"),
        json!({"WindowsLazy":{"max_lazy":32}}),
    ];
    for variant in matching {
        let mut parameters = request()["parameters"].clone();
        parameters["matching_type"] = variant;
        let typed: preflate_rs::TokenPredictorParameters =
            serde_json::from_value(parameters.clone()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), parameters);
    }
}

#[test]
fn replay_reports_correction_failures_as_json_without_hiding_them() {
    let mut input = request();
    input["source"] = json!({
        "type":"blocks",
        "blocks":[{
            "type":"huffman", "last":true,
            "tokens":[
                {"type":"literal","value":64},
                {"type":"literal","value":97},
                {"type":"literal","value":98},
                {"type":"literal","value":99},
                {"type":"literal","value":88},
                {"type":"literal","value":155},
                {"type":"literal","value":17},
                {"type":"literal","value":0},
                {"type":"reference","length":3,"distance":7},
                {"type":"literal","value":90}
            ]
        }]
    });
    input["parameters"]["hash_algorithm"] = json!("Libdeflate4");
    input["options"] = json!({});
    let (output, result) = run(&input);
    assert!(!output.status.success());
    assert_eq!(result["status"], "error");
    assert!(matches!(
        result["error"]["code"].as_str(),
        Some("MatchNotFound" | "PredictionFailure")
    ));
    assert!(result.get("result").is_none());
}

#[test]
fn replay_only_normalizes_parameters_when_explicitly_requested() {
    let mut input = request();
    input["options"]["normalize_parameters"] = json!(true);
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["verified"], true);
    assert_eq!(result["result"]["parameters"], input["parameters"]);
    assert_ne!(
        result["result"]["effective_parameters"],
        input["parameters"]
    );
}
