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
    // The default Mimic/TCPRAW adapters use WinDivert. Delay loading still
    // allows standalone XDP diagnostics before loading the capture DLL.
    println!("cargo:rustc-link-arg=/DELAYLOAD:WinDivert.dll");
}
