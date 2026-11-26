fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["projection_surface"]));
    tauri_build::try_build(attributes).expect("build ConWU desktop");
}
