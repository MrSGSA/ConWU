use std::io;

/// IP packets between the Phantun stack and an owned native capture endpoint.
/// The platform adapter supplies packets without creating a virtual interface.
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;
    fn try_send(&self, buf: &[u8]) -> io::Result<()>;
    fn name(&self) -> String;
}
