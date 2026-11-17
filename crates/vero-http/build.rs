use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let dist = manifest.join("../../web/dist");
    let assets = ["index.html", "app.js", "app.css"];
    let available = assets.iter().all(|asset| dist.join(asset).is_file());
    for asset in assets {
        let source = dist.join(asset);
        println!("cargo:rerun-if-changed={}", source.display());
        let contents = if available {
            fs::read(&source).unwrap_or_else(|error| {
                panic!(
                    "could not read generated UI asset {}: {error}",
                    source.display()
                )
            })
        } else if asset == "index.html" {
            b"<!doctype html><meta charset=\"utf-8\"><title>Vero UI unavailable</title><main><h1>Vero UI assets are not built</h1><p>The CLI and MCP are available. To enable the local UI, run <code>npm ci && npm run build</code> in the web directory, then rebuild Vero.</p></main>".to_vec()
        } else {
            Vec::new()
        };
        fs::write(output.join(asset), contents).expect("write embedded UI asset");
    }
}
