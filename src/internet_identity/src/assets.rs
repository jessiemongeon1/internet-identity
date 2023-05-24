// All assets
//
// This file describes which assets are used and how (content, content type and content encoding).

use crate::hash::{hash_of_map, Value};
use crate::http::security_headers;
use crate::{http, state, LABEL_EXPR};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ic_cdk::api;
use ic_certified_map::{AsHashTree, Hash};
use include_dir::{include_dir, Dir, File};
use lazy_static::lazy_static;
use serde::Serialize;
use sha2::Digest;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContentEncoding {
    Identity,
    GZip,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum ContentType {
    HTML,
    JS,
    JSON,
    ICO,
    WEBP,
    CSS,
    OCTETSTREAM,
    PNG,
    SVG,
    WOFF2,
}

// The <script> tag that loads the 'index.js'
const JS_SETUP_SCRIPT: &str = "let s = document.createElement('script');s.type = 'module';s.src = 'index.js';document.head.appendChild(s);";
const IC_CERTIFICATE_EXPRESSION: &str =
    "default_certification(ValidationArgs{certification:Certification{no_request_certification: Empty{},\
    response_certification:ResponseCertification{response_header_exclusions:ResponseHeaderList{headers:[]}}}})";

// Fix up HTML pages, by injecting canister ID, script tag and CSP
fn fixup_html(html: &str) -> String {
    let canister_id = api::id();
    let setup_js: String = JS_SETUP_SCRIPT.to_string();
    let html = html.replace(
        r#"<script id="setupJs"></script>"#,
        &format!(r#"<script data-canister-id="{canister_id}" id="setupJs">{setup_js}</script>"#),
    );
    html.replace(
        "<meta replaceme-with-csp/>",
        &format!(
            r#"<meta http-equiv="Content-Security-Policy" content="{}" />"#,
            &http::content_security_policy_meta()
        ),
    )
}

lazy_static! {
    // The SRI sha256 hash of the script tag, used by the CSP policy.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
    pub static ref JS_SETUP_SCRIPT_SRI_HASH: String = {
        let hash = &sha2::Sha256::digest(JS_SETUP_SCRIPT.as_bytes());
        let hash = BASE64.encode(hash);
        format!("sha256-{hash}")
    };
}

// used both in init and post_upgrade
pub fn init_assets() {
    let expr_hash: Hash = sha2::Sha256::digest(IC_CERTIFICATE_EXPRESSION).into();
    state::assets_and_hashes_mut(|assets, asset_hashes_v1, asset_hashes_v2| {
        for (path, content, content_encoding, content_type) in get_static_assets() {
            let body_hash = sha2::Sha256::digest(&content).into();
            asset_hashes_v1.insert(path.clone(), body_hash);
            let mut headers = match content_encoding {
                ContentEncoding::Identity => vec![],
                ContentEncoding::GZip => {
                    vec![("Content-Encoding".to_string(), "gzip".to_string())]
                }
            };
            headers.push((
                "Content-Type".to_string(),
                content_type.to_mime_type_string(),
            ));
            headers.push((
                "IC-CertificateExpression".to_ascii_lowercase(),
                IC_CERTIFICATE_EXPRESSION.to_string(),
            ));
            let security_headers = security_headers();
            let mut response_metadata = HashMap::from_iter(
                headers
                    .iter()
                    .chain(security_headers.iter())
                    .map(|(header, value)| (header.to_ascii_lowercase(), Value::String(&value)))
                    .collect::<Vec<_>>(),
            );
            response_metadata.insert(
                "IC-CertificateExpression".to_ascii_lowercase(),
                Value::String(IC_CERTIFICATE_EXPRESSION),
            );
            response_metadata.insert(":ic-cert-status".to_string(), Value::U64(200));
            ic_cdk::println!("response_metadata: {:?}", &response_metadata);
            let mut response_metadata_hash: Vec<u8> = hash_of_map(response_metadata).into();
            ic_cdk::println!(
                "response_metadata_hash: {:?}",
                hex::encode(&response_metadata_hash)
            );
            ic_cdk::println!("body_hash: {:?}", hex::encode(&body_hash));
            response_metadata_hash.extend_from_slice(&body_hash);
            let response_hash: Hash = sha2::Sha256::digest(&response_metadata_hash).into();

            let mut segments: Vec<Vec<u8>> =
                path.split('/').map(str::as_bytes).map(Vec::from).collect();
            // The first segment is always empty, because the path starts with a slash -> drop it
            segments.remove(0);
            segments.push("<$>".as_bytes().to_vec());
            segments.push(Vec::from(expr_hash));
            segments.push(vec![]);
            segments.push(Vec::from(response_hash));
            asset_hashes_v2.insert(&segments, vec![]);
            assets.insert(path, (headers, content));
        }
        ic_cdk::println!("Assets initialized");

        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        asset_hashes_v2
            .as_hash_tree()
            .serialize(&mut serializer)
            .unwrap();
        ic_cdk::println!("assets v2: {:?}", hex::encode(serializer.into_inner()));
    });
}

static ASSET_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../dist");

// Gets the static assets. All static assets are prepared only once (like injecting the canister ID).
fn get_static_assets() -> Vec<(String, Vec<u8>, ContentEncoding, ContentType)> {
    let mut assets = collect_assets_recursive(&ASSET_DIR);

    // Required to make II available on the identity.internetcomputer.org domain.
    // See https://internetcomputer.org/docs/current/developer-docs/production/custom-domain/#custom-domains-on-the-boundary-nodes
    assets.push((
        "/.well-known/ic-domains".to_string(),
        b"identity.internetcomputer.org".to_vec(),
        ContentEncoding::Identity,
        ContentType::OCTETSTREAM,
    ));

    assets
}

fn collect_assets_recursive(dir: &Dir) -> Vec<(String, Vec<u8>, ContentEncoding, ContentType)> {
    let mut assets = collect_assets_from_dir(dir);
    for subdir in dir.dirs() {
        assets.extend(collect_assets_recursive(subdir).into_iter());
    }
    assets
}

fn collect_assets_from_dir(dir: &Dir) -> Vec<(String, Vec<u8>, ContentEncoding, ContentType)> {
    let mut assets: Vec<(String, Vec<u8>, ContentEncoding, ContentType)> = vec![];
    for asset in dir.files() {
        let file_bytes = asset.contents().to_vec();
        let (content, encoding, content_type) = match file_extension(asset) {
            "css" => (file_bytes, ContentEncoding::Identity, ContentType::CSS),
            "html" => (
                fixup_html(String::from_utf8_lossy(&file_bytes).as_ref())
                    .as_bytes()
                    .to_vec(),
                ContentEncoding::Identity,
                ContentType::HTML,
            ),
            "ico" => (file_bytes, ContentEncoding::Identity, ContentType::ICO),
            "json" => (file_bytes, ContentEncoding::Identity, ContentType::JSON),
            "js.gz" => (file_bytes, ContentEncoding::GZip, ContentType::JS),
            "png" => (file_bytes, ContentEncoding::Identity, ContentType::PNG),
            "svg" => (file_bytes, ContentEncoding::Identity, ContentType::SVG),
            "webp" => (file_bytes, ContentEncoding::Identity, ContentType::WEBP),
            "woff2.gz" => (file_bytes, ContentEncoding::GZip, ContentType::WOFF2),
            _ => panic!("Unknown asset type: {}", asset.path().display()),
        };

        assets.push((file_to_asset_path(asset), content, encoding, content_type));
    }
    assets
}

/// Returns the portion of the filename after the first dot.
/// This corresponds to the file extension for the assets handled by this canister.
///
/// The builtin `extension` method on `Path` does not work for file extensions with multiple dots
/// such as `.js.gz`.
fn file_extension<'a>(asset: &'a File) -> &'a str {
    asset
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .split_once('.')
        .unwrap()
        .1
}

/// Returns the asset path for a given file:
/// * make relative path absolute
/// * map **/index.html to **/
/// * map **/<foo>.html to **/foo
/// * map **/<foo>.js.gz to **/<foo>.js
fn file_to_asset_path(asset: &File) -> String {
    // make path absolute
    let mut file_path = "/".to_string() + asset.path().to_str().unwrap();

    if file_path.ends_with("index.html") {
        // drop index.html filename (i.e. maps **/index.html to **/)
        file_path = file_path
            .chars()
            .take(file_path.len() - "index.html".len())
            .collect()
    } else if file_path.ends_with(".html") {
        // drop .html file endings (i.e. maps **/<foo>.html to **/foo)
        file_path = file_path
            .chars()
            .take(file_path.len() - ".html".len())
            .collect()
    } else if file_path.ends_with(".gz") {
        // drop .gz for .foo.gz files (i.e. maps **/<foo>.js.gz to **/<foo>.js)
        file_path = file_path
            .chars()
            .take(file_path.len() - ".gz".len())
            .collect()
    }
    file_path
}
