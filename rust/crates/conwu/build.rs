use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-env-changed=CONWU_LINK_NO_MMAP");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && env::var_os("CONWU_LINK_NO_MMAP").is_some()
    {
        // lld's mmap writeback over WSL DrvFs turns a debug link into tens of
        // thousands of synchronous 4KiB 9P writes. The local wrappers opt in to
        // ordinary output writes; generic developer toolchains stay unchanged.
        let flag = if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
            "--no-mmap-output-file"
        } else {
            "-Wl,--no-mmap-output-file"
        };
        println!("cargo:rustc-link-arg={flag}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../../..");
    let icon = root
        .join("src/ConWU.App/Assets/conwu.ico")
        .canonicalize()
        .unwrap();
    println!("cargo:rerun-if-changed={}", icon.display());
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numbers = version
        .split('-')
        .next()
        .unwrap()
        .split('.')
        .collect::<Vec<_>>()
        .join(",");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let source = out.join("conwu.rc");
    let resource = out.join("conwu.res");
    let text = format!(
        r#"#include <winver.h>
101 ICON "{}"
1 VERSIONINFO
FILEVERSION {},0
PRODUCTVERSION {},0
FILEFLAGSMASK 0x3fL
FILEFLAGS {}
FILEOS 0x40004L
FILETYPE 0x1L
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "CompanyName", "ConWU\0"
   VALUE "FileDescription", "ConWU Native Network\0"
   VALUE "FileVersion", "{}\0"
   VALUE "ProductName", "ConWU\0"
   VALUE "ProductVersion", "{}\0"
   VALUE "LegalCopyright", "ConWU contributors\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x0409, 1200
 END
END
"#,
        icon.to_string_lossy()
            .trim_start_matches(r"\\?\")
            .replace('\\', "\\\\"),
        numbers,
        numbers,
        if version.contains('-') { 2 } else { 0 },
        version,
        version
    );
    fs::write(&source, text).unwrap();
    let compiler = env::var_os("CONWU_RC")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe")
        });
    let sdk = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0");
    let output = Command::new(compiler)
        .arg("/nologo")
        .arg("/I")
        .arg(sdk.join("shared"))
        .arg("/I")
        .arg(sdk.join("um"))
        .arg("/fo")
        .arg(&resource)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Windows resource compilation failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("cargo:rustc-link-arg-bin=conwu={}", resource.display());
}
