mod compliance;
use compliance::{get_monitor_event, setup_monitor};
use zeromq::CurveKeyPair;

use std::convert::TryInto;
use zeromq::__async_rt as async_rt;
use zeromq::prelude::*;
use zeromq::ZmqMessage;
use zeromq::{AuthMethod, SocketOptions};

const REP_CURVE_KEY_PUBLIC: [u8; 32] = [
    119, 208, 66, 20, 197, 244, 159, 186, 189, 159, 226, 119, 217, 146, 155, 139, 193, 223, 191,
    65, 23, 190, 199, 224, 104, 39, 175, 146, 123, 120, 104, 97,
];
const REP_CURVE_KEY_SECRET: [u8; 32] = [
    113, 236, 137, 202, 253, 184, 124, 55, 162, 81, 163, 223, 191, 22, 188, 238, 142, 22, 145, 148,
    73, 6, 88, 118, 83, 49, 162, 37, 87, 127, 11, 0,
];

const REQ_CURVE_KEY: CurveKeyPair = CurveKeyPair {
    public_key: [
        178, 77, 122, 88, 204, 209, 185, 72, 213, 217, 191, 20, 14, 160, 60, 89, 114, 30, 14, 33,
        113, 22, 207, 183, 6, 149, 78, 164, 210, 17, 201, 16,
    ],
    secret_key: [
        160, 54, 76, 84, 227, 184, 159, 194, 181, 10, 13, 27, 144, 26, 3, 78, 51, 55, 154, 11, 217,
        42, 242, 88, 154, 198, 56, 122, 238, 58, 47, 75,
    ],
};

/// Returns (socket, bound_endpoint, monitor)
fn setup_their_rep(bind_endpoint: &str) -> (zmq::Socket, String, zmq::Socket) {
    let ctx = zmq::Context::new();

    let auth = ctx.socket(zmq::REP).expect("Couldn't make ZAP socket");
    auth.bind("inproc://zeromq.zap.01")
        .expect("Failed to bind ZAP");

    std::thread::spawn(move || loop {
        let rq = auth.recv_multipart(0).expect("Failed to recv");
        let (version, sequence, mechanism, pub_key) = (&*rq[0], &*rq[1], &*rq[5], &*rq[6]);

        assert_eq!(version, b"1.0");
        assert_eq!(mechanism, b"CURVE");
        println!("Got auth request: pubkey {:?}", pub_key);
        auth.send_multipart(&[version, sequence, b"200", b"OK", b"anonymous", b""], 0)
            .expect("Error sending auth response");
    });

    let their_rep = ctx.socket(zmq::REP).expect("Couldn't make rep socket");
    their_rep
        .set_curve_server(true)
        .expect("Failed to set curve server flag");
    their_rep
        .set_curve_secretkey(&REP_CURVE_KEY_SECRET[..])
        .expect("Failed to set curve secret key");
    their_rep.bind(bind_endpoint).expect("Failed to bind");

    let resolved_bind = their_rep.get_last_endpoint().unwrap().unwrap();

    let their_monitor = setup_monitor(&ctx, &their_rep, "inproc://their-monitor");

    (their_rep, resolved_bind, their_monitor)
}

async fn setup_our_req(bind_endpoint: &str) -> zeromq::ReqSocket {
    let mut sock_opts = SocketOptions::default();
    sock_opts.auth_method(
        AuthMethod::curve_client(REP_CURVE_KEY_PUBLIC, REQ_CURVE_KEY)
            .expect("Failed to initialize curve auth options"),
    );
    let mut our_req = zeromq::ReqSocket::with_options(sock_opts);
    our_req
        .connect(bind_endpoint)
        .await
        .expect("Failed to connect");
    our_req
}

fn run_their_rep(their_rep: zmq::Socket, num_req: u32) -> std::thread::JoinHandle<zmq::Socket> {
    assert_eq!(their_rep.get_socket_type().unwrap(), zmq::REP);
    std::thread::spawn(move || {
        for i in 0..num_req {
            let request = their_rep.recv_msg(0).expect("Failed to recv");
            assert_eq!(request.as_str().unwrap(), format!("Request: {}", i));
            their_rep
                .send(&format!("Reply: {}", i), 0)
                .expect("Failed to send");
        }
        println!("Finished pub task");
        their_rep
    })
}

async fn run_our_req(our_req: &mut zeromq::ReqSocket, num_req: u32) {
    for i in 0..num_req {
        let ms: String = format!("Request: {}", i);
        let message = ZmqMessage::from(ms);
        our_req.send(message).await.expect("Failed to send");
        let reply = our_req.recv().await.expect("Failed to recv");

        let reply_payload: String = reply.try_into().unwrap();
        println!("Received reply: {}", &reply_payload);
        assert_eq!(reply_payload, format!("Reply: {}", i));
    }
}

#[async_rt::test]
async fn test_auth_curve_client() {
    let (their_rep, bind_endpoint, their_monitor) = setup_their_rep("tcp://127.0.0.1:0");
    println!("Their rep was bound to {}", bind_endpoint);

    let mut our_req = setup_our_req(&bind_endpoint).await;
    assert_eq!(
        zmq::SocketEvent::ACCEPTED,
        get_monitor_event(&their_monitor).0
    );
    assert_eq!(
        zmq::SocketEvent::HANDSHAKE_SUCCEEDED,
        get_monitor_event(&their_monitor).0
    );
    println!("Setup done");

    const NUM_MSGS: u32 = 64;

    let their_join_handle = run_their_rep(their_rep, NUM_MSGS);
    run_our_req(&mut our_req, NUM_MSGS).await;
    let _their_rep = their_join_handle
        .join()
        .expect("Their pub terminated with an error!");
    assert_eq!(our_req.close().await.len(), 0);
    // TODO: check that socket disconnected via monitor when we implement that
    // functionality
}
