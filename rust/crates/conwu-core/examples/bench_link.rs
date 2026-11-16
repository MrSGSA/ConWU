use conwu_core::{crypto as c, link::Link};
fn main() -> anyhow::Result<()> {
    let count = std::env::args()
        .nth(1)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(500_000u64);
    let secret = c::random();
    let mut a = Link::new(1, 2, secret)?;
    let mut b = Link::new(2, 1, secret)?;
    let hello = a.hello()?;
    let ack = b.receive(&hello, false).reply.unwrap();
    let finish = a.receive(&ack, false).reply.unwrap();
    b.receive(&finish, false);
    let packet = vec![1; 1280];
    for _ in 0..2000 {
        b.receive(&a.data(&packet, 0)?.unwrap(), false);
    }
    let clock = std::time::Instant::now();
    let mut bytes = 0;
    for _ in 0..count {
        bytes += std::hint::black_box(
            b.receive(&a.data(std::hint::black_box(&packet), 0)?.unwrap(), false)
                .packet
                .unwrap()
                .len(),
        );
    }
    let seconds = clock.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({"packets":count,"bytes":bytes,"seconds":seconds,"mbps":bytes as f64*8.0/seconds/1_000_000.0,"scope":"CPU only: authenticated packet encode and decode; no network or adapter"})
    );
    Ok(())
}
