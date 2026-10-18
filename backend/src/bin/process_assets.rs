use std::fs;
use std::path::Path;
use image::{imageops::{self, FilterType}, Rgba, RgbaImage};

fn smoothstep(edge0: f32, edge1: f32, x: f32) -> f32 {
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn process_dark_logo(src: &RgbaImage) -> RgbaImage {
    let (w, h) = src.dimensions();
    let bg_r = 4.0f32;
    let bg_g = 7.0f32;
    let bg_b = 14.0f32;

    let mut out = RgbaImage::new(w, h);

    for y in 0..h {
        for x in 0..w {
            let p = src.get_pixel(x, y);
            let pr = p[0] as f32;
            let pg = p[1] as f32;
            let pb = p[2] as f32;

            let dist = ((pr - bg_r).powi(2) + (pg - bg_g).powi(2) + (pb - bg_b).powi(2)).sqrt();

            let alpha = smoothstep(12.0, 36.0, dist);

            if alpha <= 0.001 {
                out.put_pixel(x, y, Rgba([0, 0, 0, 0]));
            } else {
                // Unpremultiply against dark background
                let ur = ((pr - (1.0 - alpha) * bg_r) / alpha).clamp(0.0, 255.0) as u8;
                let ug = ((pg - (1.0 - alpha) * bg_g) / alpha).clamp(0.0, 255.0) as u8;
                let ub = ((pb - (1.0 - alpha) * bg_b) / alpha).clamp(0.0, 255.0) as u8;
                let ua = (alpha * 255.0).round().clamp(0.0, 255.0) as u8;
                out.put_pixel(x, y, Rgba([ur, ug, ub, ua]));
            }
        }
    }
    out
}

fn process_light_logo(src: &RgbaImage) -> RgbaImage {
    let (w, h) = src.dimensions();
    let bg_r = 254.0f32;
    let bg_g = 254.0f32;
    let bg_b = 254.0f32;

    let mut out = RgbaImage::new(w, h);

    for y in 0..h {
        for x in 0..w {
            let p = src.get_pixel(x, y);
            let pr = p[0] as f32;
            let pg = p[1] as f32;
            let pb = p[2] as f32;

            let dist = ((pr - bg_r).powi(2) + (pg - bg_g).powi(2) + (pb - bg_b).powi(2)).sqrt();

            let alpha = smoothstep(10.0, 32.0, dist);

            if alpha <= 0.001 {
                out.put_pixel(x, y, Rgba([0, 0, 0, 0]));
            } else {
                // Unpremultiply against white background
                let ur = ((pr - (1.0 - alpha) * 255.0) / alpha).clamp(0.0, 255.0) as u8;
                let ug = ((pg - (1.0 - alpha) * 255.0) / alpha).clamp(0.0, 255.0) as u8;
                let ub = ((pb - (1.0 - alpha) * 255.0) / alpha).clamp(0.0, 255.0) as u8;
                let ua = (alpha * 255.0).round().clamp(0.0, 255.0) as u8;
                out.put_pixel(x, y, Rgba([ur, ug, ub, ua]));
            }
        }
    }
    out
}

fn find_content_bbox(img: &RgbaImage) -> Option<(u32, u32, u32, u32)> {
    let (w, h) = img.dimensions();
    let mut min_x = w;
    let mut min_y = h;
    let mut max_x = 0;
    let mut max_y = 0;
    let mut found = false;

    for y in 0..h {
        for x in 0..w {
            if img.get_pixel(x, y)[3] > 15 {
                found = true;
                if x < min_x { min_x = x; }
                if x > max_x { max_x = x; }
                if y < min_y { min_y = y; }
                if y > max_y { max_y = y; }
            }
        }
    }

    if found {
        Some((min_x, min_y, max_x + 1, max_y + 1))
    } else {
        None
    }
}

fn crop_with_padding(img: &RgbaImage, bbox: (u32, u32, u32, u32), pad: u32) -> RgbaImage {
    let (min_x, min_y, max_x, max_y) = bbox;
    let (w, h) = img.dimensions();

    let x0 = min_x.saturating_sub(pad);
    let y0 = min_y.saturating_sub(pad);
    let x1 = (max_x + pad).min(w);
    let y1 = (max_y + pad).min(h);

    let crop_w = x1 - x0;
    let crop_h = y1 - y0;

    imageops::crop_imm(img, x0, y0, crop_w, crop_h).to_image()
}

fn main() -> anyhow::Result<()> {
    let dark_path = Path::new("../docs/design/logo-dark-source.png");
    let light_path = Path::new("../docs/design/logo-light-source.png");

    let out_dir = Path::new("src/web/static");
    fs::create_dir_all(out_dir)?;

    println!("Loading source images...");
    let dark_raw = image::open(dark_path)?.to_rgba8();
    let light_raw = image::open(light_path)?.to_rgba8();

    println!("Removing solid backgrounds...");
    let dark_trans = process_dark_logo(&dark_raw);
    let light_trans = process_light_logo(&light_raw);

    let dark_bbox = find_content_bbox(&dark_trans).expect("dark content bbox");
    let light_bbox = find_content_bbox(&light_trans).expect("light content bbox");

    println!("Dark bbox: {:?}", dark_bbox);
    println!("Light bbox: {:?}", light_bbox);

    let dark_cropped = crop_with_padding(&dark_trans, dark_bbox, 12);
    let light_cropped = crop_with_padding(&light_trans, light_bbox, 12);

    println!("Cropped dark: {}x{}", dark_cropped.width(), dark_cropped.height());
    println!("Cropped light: {}x{}", light_cropped.width(), light_cropped.height());

    // Scale logos to about 2x display size (approx 480px width)
    let target_logo_w = 480u32;
    let dark_scaled_h = (dark_cropped.height() as f32 * (target_logo_w as f32 / dark_cropped.width() as f32)).round() as u32;
    let light_scaled_h = (light_cropped.height() as f32 * (target_logo_w as f32 / light_cropped.width() as f32)).round() as u32;

    let dark_logo = imageops::resize(&dark_cropped, target_logo_w, dark_scaled_h, FilterType::Lanczos3);
    let light_logo = imageops::resize(&light_cropped, target_logo_w, light_scaled_h, FilterType::Lanczos3);

    dark_logo.save(out_dir.join("logo-dark.png"))?;
    light_logo.save(out_dir.join("logo-light.png"))?;
    println!("Saved logo-dark.png ({}x{}) and logo-light.png ({}x{})", target_logo_w, dark_scaled_h, target_logo_w, light_scaled_h);

    // Find the blank column between shield and the text
    // The shield starts at dark_bbox.0 (around 340) and ends around 640.
    // Let's scan from x = dark_bbox.0 + 100 onwards to find the first column where there are NO content pixels.
    let mut shield_end_x = dark_bbox.0 + 100;
    let mut gap_found = false;
    for x in (dark_bbox.0 + 200)..dark_bbox.2 {
        let has_pixel = (dark_bbox.1..dark_bbox.3).any(|y| dark_trans.get_pixel(x, y)[3] > 15);
        if !has_pixel && !gap_found {
            // First empty column after shield!
            shield_end_x = x;
            gap_found = true;
            break;
        }
    }
    if !gap_found {
        shield_end_x = dark_bbox.0 + (dark_cropped.width() as f32 * 0.28) as u32;
    }
    println!("Detected shield end x: {}", shield_end_x);

    let shield_sub = imageops::crop_imm(&dark_trans, dark_bbox.0, dark_bbox.1, shield_end_x - dark_bbox.0, dark_bbox.3 - dark_bbox.1).to_image();
    let shield_bbox = find_content_bbox(&shield_sub).expect("shield bbox");
    let shield_cropped = crop_with_padding(&shield_sub, shield_bbox, 4);

    println!("Shield cropped: {}x{}", shield_cropped.width(), shield_cropped.height());

    // Fit shield into a square canvas of 512x512 with transparent padding
    let target_size = 512u32;
    let max_dim = shield_cropped.width().max(shield_cropped.height()) as f32;
    let scale = (target_size as f32 * 0.9) / max_dim;
    let sw = (shield_cropped.width() as f32 * scale).round() as u32;
    let sh = (shield_cropped.height() as f32 * scale).round() as u32;
    let resized_shield = imageops::resize(&shield_cropped, sw, sh, FilterType::Lanczos3);

    let mut mark_512 = RgbaImage::new(target_size, target_size);
    let offset_x = (target_size - sw) / 2;
    let offset_y = (target_size - sh) / 2;
    imageops::overlay(&mut mark_512, &resized_shield, offset_x as i64, offset_y as i64);

    mark_512.save(out_dir.join("shield-mark.png"))?;
    println!("Saved shield-mark.png (512x512)");

    // Generate apple-touch-icon.png (180x180)
    let apple_touch = imageops::resize(&mark_512, 180, 180, FilterType::Lanczos3);
    apple_touch.save(out_dir.join("apple-touch-icon.png"))?;
    println!("Saved apple-touch-icon.png (180x180)");

    // Generate favicon.png (32x32)
    let favicon = imageops::resize(&mark_512, 32, 32, FilterType::Lanczos3);
    favicon.save(out_dir.join("favicon.png"))?;
    println!("Saved favicon.png (32x32)");

    Ok(())
}

