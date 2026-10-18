use qrcode::QrCode;

/// Renders a server-side SVG QR code for the given content string (e.g. ZIP 321 URI).
/// Returns an SVG element string suitable for direct inlining in HTML.
pub fn render_qr_svg(content: &str) -> Result<String, String> {
    let code = QrCode::new(content.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build();
    Ok(svg)
}
