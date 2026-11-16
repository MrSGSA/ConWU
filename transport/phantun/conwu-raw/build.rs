fn main() {
    println!("cargo:rerun-if-changed=native/xdp_io.cpp");
    println!("cargo:rerun-if-changed=native/xdp_io.h");
    println!("cargo:rerun-if-changed=native/xdp-sdk/include");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .static_crt(true)
        .define("_WIN32_WINNT", "0x0A00")
        .include("native/xdp-sdk/include")
        .file("native/xdp_io.cpp")
        .compile("conwu_xdp");
    for library in ["ntdll", "ws2_32", "iphlpapi", "delayimp"] {
        println!("cargo:rustc-link-lib={library}");
    }
    // TCPRAW's legacy adapter is the only WinDivert caller. A Mimic process
    // does not load that DLL, even though the executable contains both modes.
    println!("cargo:rustc-link-arg=/DELAYLOAD:WinDivert.dll");
}
