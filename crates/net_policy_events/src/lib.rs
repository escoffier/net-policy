pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

use proto::{PolicyEvent, PolicyMatchEvent, WafAttackEvent};
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {
    extern "Rust" {
        fn publish_policy_match(
            protocol: u8,
            action: i32,
            direction: i32,
            src_port: u16,
            dst_port: u16,
            src_ip: &str,
            dst_ip: &str,
            policy_name: &str,
        );

        fn publish_waf_attack(
            service_id: u64,
            res_name: &str,
            app_name: &str,
            res_kind: &str,
            k8s_namespace: &str,
            cluster_key: &str,
            action: &str,
            attack_ip: &str,
            attacked_app: &str,
            attack_load: &str,
            attack_time: i64,
            rule_id: i64,
            rule_name: &str,
            req_pkg: &str,
            rsp_pkg: &str,
            attack_type: &str,
            attacked_url: &str,
            rsp_content_type: &str,
        );

        unsafe fn start_event_server(port: u16) -> u16;
    }
}

const EVENT_QUEUE_CAPACITY: usize = 256;

struct EventQueue {
    inner: Mutex<VecDeque<PolicyEvent>>,
    condvar: Condvar,
}

impl EventQueue {
    fn new() -> Self {
        EventQueue { inner: Mutex::new(VecDeque::new()), condvar: Condvar::new() }
    }

    fn push(&self, event: PolicyEvent) {
        let mut guard = self.inner.lock().unwrap();
        if guard.len() >= EVENT_QUEUE_CAPACITY {
            guard.pop_front(); // drop oldest, matching grpc/event_bridge.cc's existing policy
        }
        guard.push_back(event);
        self.condvar.notify_one();
    }

    fn wait_and_pop(&self, timeout: Duration) -> Option<PolicyEvent> {
        let guard = self.inner.lock().unwrap();
        let (mut guard, result) = self
            .condvar
            .wait_timeout_while(guard, timeout, |q| q.is_empty())
            .unwrap();
        if result.timed_out() {
            return None;
        }
        guard.pop_front()
    }
}

static QUEUE: OnceLock<EventQueue> = OnceLock::new();

fn queue() -> &'static EventQueue {
    QUEUE.get_or_init(EventQueue::new)
}

// mirrors ProtoToL4Protocol, grpc/event_bridge.cc (deleted in Task 8) --
// IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1 (see <netinet/in.h>);
// proto values from net_policy_common.proto: UNSPECIFIED=0, TCP=1, UDP=2, ICMP=3
fn protocol_to_l4protocol(protocol: u8) -> i32 {
    match protocol {
        6 => 1,  // L4_PROTOCOL_TCP
        17 => 2, // L4_PROTOCOL_UDP
        1 => 3,  // L4_PROTOCOL_ICMP
        _ => 0,  // L4_PROTOCOL_UNSPECIFIED
    }
}

// mirrors NetPolicyRuleToProto -- NetPolicyRule (net-policy.h): kDeny=0,
// kAllow=1, kMark=2 (kAllowRsp=3/kAllowReq=4/kDefault=5 have no proto
// mapping and fall through to UNSPECIFIED, matching the C++ original's
// default case); PolicyAction (net_policy_common.proto): UNSPECIFIED=0, DENY=1, ALLOW=2, ALERT=3
fn net_policy_rule_to_proto(action: i32) -> i32 {
    match action {
        1 => 2, // POLICY_ACTION_ALLOW
        2 => 3, // POLICY_ACTION_ALERT
        0 => 1, // POLICY_ACTION_DENY
        _ => 0, // POLICY_ACTION_UNSPECIFIED
    }
}

// mirrors FlowDirToProto -- FlowDir (net-policy.h): kIngress=0, kEgress=1;
// FlowDirection (net_policy_common.proto): INGRESS=1, EGRESS=2 (no
// UNSPECIFIED=0 case needed here, matching the C++ original's plain ternary)
fn flow_dir_to_proto(direction: i32) -> i32 {
    if direction == 0 { 1 } else { 2 }
}

pub fn publish_policy_match(
    protocol: u8,
    action: i32,
    direction: i32,
    src_port: u16,
    dst_port: u16,
    src_ip: &str,
    dst_ip: &str,
    policy_name: &str,
) {
    let event = PolicyEvent {
        event: Some(proto::policy_event::Event::PolicyMatch(PolicyMatchEvent {
            protocol: protocol_to_l4protocol(protocol),
            action: net_policy_rule_to_proto(action),
            direction: flow_dir_to_proto(direction),
            src_port: src_port as u32,
            dst_port: dst_port as u32,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            policy_name: policy_name.to_string(),
        })),
    };
    queue().push(event);
}

pub fn publish_waf_attack(
    service_id: u64,
    res_name: &str,
    app_name: &str,
    res_kind: &str,
    k8s_namespace: &str,
    cluster_key: &str,
    action: &str,
    attack_ip: &str,
    attacked_app: &str,
    attack_load: &str,
    attack_time: i64,
    rule_id: i64,
    rule_name: &str,
    req_pkg: &str,
    rsp_pkg: &str,
    attack_type: &str,
    attacked_url: &str,
    rsp_content_type: &str,
) {
    let event = PolicyEvent {
        event: Some(proto::policy_event::Event::WafAttack(WafAttackEvent {
            service_id,
            res_name: res_name.to_string(),
            app_name: app_name.to_string(),
            res_kind: res_kind.to_string(),
            k8s_namespace: k8s_namespace.to_string(),
            cluster_key: cluster_key.to_string(),
            action: action.to_string(),
            attack_ip: attack_ip.to_string(),
            attacked_app: attacked_app.to_string(),
            attack_load: attack_load.to_string(),
            attack_time,
            rule_id,
            rule_name: rule_name.to_string(),
            req_pkg: req_pkg.to_string(),
            rsp_pkg: rsp_pkg.to_string(),
            attack_type: attack_type.to_string(),
            attacked_url: attacked_url.to_string(),
            rsp_content_type: rsp_content_type.to_string(),
        })),
    };
    queue().push(event);
}

use proto::net_policy_events_server::{NetPolicyEvents, NetPolicyEventsServer};
use proto::SubscribeEventsRequest;
use std::pin::Pin;
use tokio_stream::{Stream, StreamExt};
use tonic::{transport::Server, Request, Response, Status};

struct EventServiceImpl;

#[tonic::async_trait]
impl NetPolicyEvents for EventServiceImpl {
    type SubscribeEventsStream =
        Pin<Box<dyn Stream<Item = Result<PolicyEvent, Status>> + Send + 'static>>;

    async fn subscribe_events(
        &self,
        _request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel::<PolicyEvent>(16);
        tokio::task::spawn_blocking(move || {
            // Mirrors EventServiceImpl::SubscribeEvents's existing
            // while(!context->IsCancelled()) + 500ms-timeout loop
            // (grpc/event_service.cc, deleted in Task 8). There's no
            // direct cancellation-token equivalent to context->IsCancelled()
            // here; instead, blocking_send's failure (the Receiver was
            // dropped because the client disconnected and tonic tore down
            // the response stream) is the signal to stop, exactly mirroring
            // the C++ version's `if (!writer->Write(event)) break;`.
            //
            // That check alone isn't sufficient on its own: it only fires
            // once this loop actually wins the race to pop an event and
            // attempts to deliver it, so an idle disconnected subscriber
            // (no events flowing) would never notice a client had gone
            // away and would keep competing for the next event published
            // against the shared global queue, indefinitely. Checking
            // tx.is_closed() up front closes that gap: once the client
            // disconnects and tonic drops the paired Receiver, this loop
            // retires on its own within one wait_and_pop timeout (<=500ms)
            // even if no event ever arrives to reveal the broken channel.
            loop {
                if tx.is_closed() {
                    break;
                }
                if let Some(event) = queue().wait_and_pop(Duration::from_millis(500)) {
                    if tx.blocking_send(event).is_err() {
                        break;
                    }
                }
            }
        });
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok);
        Ok(Response::new(Box::pin(stream) as Self::SubscribeEventsStream))
    }
}

unsafe fn start_event_server(port: u16) -> u16 {
    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        rt.block_on(async move {
            let addr: std::net::SocketAddr =
                format!("0.0.0.0:{port}").parse().expect("invalid bind address");
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(_) => {
                    let _ = port_tx.send(0);
                    return;
                }
            };
            let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            let _ = port_tx.send(bound_port);
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let _ = Server::builder()
                .add_service(NetPolicyEventsServer::new(EventServiceImpl))
                .serve_with_incoming(incoming)
                .await;
        });
    });
    port_rx.recv().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_to_l4protocol_maps_known_values() {
        assert_eq!(protocol_to_l4protocol(6), 1);
        assert_eq!(protocol_to_l4protocol(17), 2);
        assert_eq!(protocol_to_l4protocol(1), 3);
        assert_eq!(protocol_to_l4protocol(99), 0);
    }

    #[test]
    fn net_policy_rule_to_proto_maps_known_values() {
        assert_eq!(net_policy_rule_to_proto(1), 2);
        assert_eq!(net_policy_rule_to_proto(2), 3);
        assert_eq!(net_policy_rule_to_proto(0), 1);
        assert_eq!(net_policy_rule_to_proto(99), 0);
    }

    #[test]
    fn flow_dir_to_proto_maps_known_values() {
        assert_eq!(flow_dir_to_proto(0), 1);
        assert_eq!(flow_dir_to_proto(1), 2);
    }

    #[test]
    fn event_queue_push_then_wait_and_pop_returns_event() {
        let q = EventQueue::new();
        q.push(PolicyEvent { event: None });
        assert!(q.wait_and_pop(Duration::from_millis(100)).is_some());
    }

    #[test]
    fn event_queue_wait_and_pop_times_out_when_empty() {
        let q = EventQueue::new();
        assert!(q.wait_and_pop(Duration::from_millis(50)).is_none());
    }

    #[test]
    fn event_queue_drops_oldest_when_full() {
        let q = EventQueue::new();
        for i in 0..(EVENT_QUEUE_CAPACITY + 1) {
            q.push(PolicyEvent {
                event: Some(proto::policy_event::Event::PolicyMatch(PolicyMatchEvent {
                    src_port: i as u32,
                    ..Default::default()
                })),
            });
        }
        let mut popped_ports = Vec::new();
        while let Some(ev) = q.wait_and_pop(Duration::from_millis(1)) {
            if let Some(proto::policy_event::Event::PolicyMatch(m)) = ev.event {
                popped_ports.push(m.src_port);
            }
        }
        assert_eq!(popped_ports.len(), EVENT_QUEUE_CAPACITY);
        // the oldest push (src_port == 0) must have been dropped, so the
        // first surviving entry is src_port == 1
        assert_eq!(popped_ports[0], 1);
    }
}
