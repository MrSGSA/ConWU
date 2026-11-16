fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon = root
        .join("../../../src/ConWU.App/Assets/conwu.ico")
        .canonicalize()
        .expect("ConWU icon");
    println!("cargo:rerun-if-changed={}", icon.display());
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let source = out.join("conwu.rc");
    let resource = out.join("conwu.res");
    std::fs::write(
        &source,
        format!(
            "#pragma code_page(65001)\n101 ICON \"{}\"\n",
            icon.to_string_lossy()
                .trim_start_matches(r"\\?\")
                .replace('\\', "/")
        ),
    )
    .unwrap();
    let compiler = std::env::var_os("CONWU_RC")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe".into()
        });
    let result = std::process::Command::new(compiler)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(source)
        .status()
        .expect("Windows SDK resource compiler (CONWU_RC)");
    assert!(result.success(), "ConWU icon compilation failed");
    println!("cargo:rustc-link-arg-bin=conwu={}", resource.display());
}
