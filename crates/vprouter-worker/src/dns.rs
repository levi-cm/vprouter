//! Native bounded UDP DNS; no libc resolver, host resolver sockets or env proxy.
use crate::{Error, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::UdpSocket;
pub(crate) const PROVIDER: &str = "am.i.mullvad.net";
pub(crate) async fn resolve(server: SocketAddrV4) -> Result<Ipv4Addr> {
    let mut id = [0; 2];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut id)
        .map_err(|_| Error::Transport)?;
    let id = u16::from_ne_bytes(id);
    let name = Name::from_ascii(format!("{PROVIDER}.")).map_err(|_| Error::InvalidConfiguration)?;
    let query = Query::query(name.clone(), RecordType::A);
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(query.clone());
    let bytes = request.to_vec().map_err(|_| Error::Malformed)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|_| Error::Transport)?;
    socket.connect(server).await.map_err(|_| Error::Transport)?;
    socket.send(&bytes).await.map_err(|_| Error::Transport)?;
    let mut buf = [0u8; 4097];
    let n = socket.recv(&mut buf).await.map_err(|_| Error::Transport)?;
    if n > 4096 {
        return Err(Error::Oversized);
    }
    parse(&buf[..n], id, &query)
}
fn parse(bytes: &[u8], id: u16, query: &Query) -> Result<Ipv4Addr> {
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| Error::Malformed)?;
    if decoder.index() != bytes.len() {
        return Err(Error::Malformed);
    }
    if message.metadata.id != id
        || message.metadata.message_type != MessageType::Response
        || message.metadata.op_code != OpCode::Query
        || message.metadata.truncation
        || message.metadata.response_code != ResponseCode::NoError
        || message.queries != [query.clone()]
    {
        return Err(Error::Malformed);
    }
    let mut name = query.name().clone();
    for _ in 0..8 {
        if let Some(ip) = message.answers.iter().find_map(|r| match &r.data {
            RData::A(ip) if r.name == name => Some(ip.0),
            _ => None,
        }) {
            return if vprouter_core::profile::public_ipv4(ip) {
                Ok(ip)
            } else {
                Err(Error::Malformed)
            };
        }
        name = message
            .answers
            .iter()
            .find_map(|r| match &r.data {
                RData::CNAME(n) if r.name == name => Some(n.0.clone()),
                _ => None,
            })
            .ok_or(Error::Malformed)?;
    }
    Err(Error::Malformed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Record, rdata::A};
    #[test]
    fn dns_exact_question_public_ipv4_and_bounds() {
        let q = Query::query(
            Name::from_ascii(format!("{PROVIDER}.")).unwrap(),
            RecordType::A,
        );
        let mut m = Message::response(17, OpCode::Query);
        m.add_query(q.clone()).add_answer(Record::from_rdata(
            q.name().clone(),
            5,
            RData::A(A("1.2.3.4".parse().unwrap())),
        ));
        assert_eq!(
            parse(&m.to_vec().unwrap(), 17, &q),
            Ok("1.2.3.4".parse().unwrap())
        );
        assert_eq!(parse(&m.to_vec().unwrap(), 18, &q), Err(Error::Malformed));
        m.metadata.truncation = true;
        assert_eq!(parse(&m.to_vec().unwrap(), 17, &q), Err(Error::Malformed));
    }
}
#[cfg(test)]
mod udp_test {
    use super::*;
    #[tokio::test]
    async fn native_udp_uses_only_supplied_socket_and_fixed_query() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let std::net::SocketAddr::V4(address) = server.local_addr().unwrap() else {
            panic!("IPv4")
        };
        let task = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            assert_eq!(request.queries.len(), 1);
            assert_eq!(request.queries[0].name().to_utf8(), "am.i.mullvad.net.");
            assert_eq!(request.queries[0].query_type(), RecordType::A);
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.add_query(request.queries[0].clone());
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A("1.2.3.4".parse().unwrap())),
            ));
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        assert_eq!(resolve(address).await, Ok("1.2.3.4".parse().unwrap()));
        task.await.unwrap();
    }
}
