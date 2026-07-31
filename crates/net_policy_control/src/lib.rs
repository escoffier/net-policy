pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

use proto::net_policy_control_server::{NetPolicyControl, NetPolicyControlServer};
use proto::update_node_config_request::Action;
use proto::{
    AddPolicyRuleRequest, AddWafRuleRequest, ContainerInfo as ProtoContainerInfo,
    DeletePolicyRuleRequest, DeleteWafRuleRequest, DumpConfigRequest, DumpConfigResponse,
    DumpConnectionsRequest, DumpConnectionsResponse, DumpHeapProfileRequest, PodDownRequest,
    PodUpRequest, PolicyRuleConfigEntry as ProtoConfigEntry, ResetConfigRequest,
    SetLogLevelRequest, StatusResponse, UpdateNodeConfigRequest,
};
use std::sync::OnceLock;
use tonic::{transport::Server, Request, Response, Status};

#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {
    struct DumpConnectionsResult {
        total: i64,
        items: Vec<String>,
    }

    struct PolicyRuleConfigEntry {
        policy_name: String,
        priority: i32,
        direction: String,
        action: String,
        protocol: String,
        protocol_int: i32,
        from_address: String,
        to_address: String,
    }
    struct ContainerInfo {
        pid: i32,
        pod_id: u64,
    }
    struct DumpConfigResult {
        inbound_rules: Vec<PolicyRuleConfigEntry>,
        outbound_rules: Vec<PolicyRuleConfigEntry>,
        containers: Vec<ContainerInfo>,
        tcp_connections: i64,
    }

    unsafe extern "C++" {
        include!("grpc/control_dispatch.h");

        // DaemonContext is forward-declared at global (root) scope in
        // net-policy.h/control_dispatch.h, not inside namespace grpc_bridge
        // -- override the bridge module's default namespace for this one
        // type so the generated C++ refers to ::DaemonContext, matching the
        // real forward declaration.
        #[namespace = ""]
        type DaemonContext;
        type GrpcDispatchQueue;

        unsafe fn GrpcDispatchResetConfig(daemon: *mut DaemonContext, queue: *mut GrpcDispatchQueue) -> i32;

        unsafe fn GrpcDispatchPodUp(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            pid: i32,
            pod_id: u64,
        ) -> i32;

        unsafe fn GrpcDispatchPodDown(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            pod_id: u64,
        ) -> i32;

        unsafe fn GrpcDispatchDeletePolicyRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            policy_name: &str,
        ) -> i32;

        unsafe fn GrpcDispatchDeleteWafRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            pod_ips: Vec<String>,
        ) -> bool;

        unsafe fn GrpcDispatchDumpHeapProfile(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            enable: bool,
        ) -> i32;

        unsafe fn GrpcDispatchDumpConnections(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            limit: i32,
        ) -> DumpConnectionsResult;

        unsafe fn GrpcDispatchUpdateNodeConfig(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            is_delete: bool,
            node_ips: Vec<String>,
        ) -> i32;

        unsafe fn GrpcDispatchSetLogLevel(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            level: i32,
        ) -> i32;

        unsafe fn GrpcDispatchDumpConfig(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            policy_name: &str,
        ) -> DumpConfigResult;
    }

    extern "Rust" {
        unsafe fn start_control_server(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            dev_port: u16,
        ) -> u16;
    }
}

/*Raw pointers into C++-owned, process-lifetime state (DaemonContext and the
 *dispatch queue), set once when the server starts. Safe to share across the
 *tokio worker threads that call into ffi::GrpcDispatchXxx: the pointers
 *themselves never change after start_control_server returns, and everything
 *they point at is either read-only from Rust's perspective or mutated only
 *on the C++ epoll thread inside the dispatch closures -- Rust never touches
 *DaemonContext's fields directly.*/
struct ServerState {
    daemon: usize, // DaemonContext* as usize; see with_daemon()/with_queue() below
    queue: usize,
    epoll_fd: i32,
}
unsafe impl Send for ServerState {}
unsafe impl Sync for ServerState {}

static STATE: OnceLock<ServerState> = OnceLock::new();

fn daemon_ptr() -> *mut ffi::DaemonContext {
    STATE.get().expect("server state not initialized").daemon as *mut ffi::DaemonContext
}
fn queue_ptr() -> *mut ffi::GrpcDispatchQueue {
    STATE.get().expect("server state not initialized").queue as *mut ffi::GrpcDispatchQueue
}

struct ControlServiceImpl;

// Every other RPC on this service is added in a later Phase 2 task,
// following the exact ResetConfig pattern established here (a
// GrpcDispatchXxx C++ function + an ffi bridge declaration + a method body
// that spawn_blocking's into it). Stubbed as unimplemented until then so the
// service can compile and serve ResetConfig today.
#[tonic::async_trait]
impl NetPolicyControl for ControlServiceImpl {
    async fn pod_up(
        &self,
        request: Request<PodUpRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let epoll_fd = STATE.get().expect("server state not initialized").epoll_fd;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchPodUp(daemon_ptr(), queue_ptr(), epoll_fd, req.pid, req.pod_id)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn pod_down(
        &self,
        request: Request<PodDownRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let epoll_fd = STATE.get().expect("server state not initialized").epoll_fd;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchPodDown(daemon_ptr(), queue_ptr(), epoll_fd, req.pod_id)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn add_policy_rule(
        &self,
        _request: Request<AddPolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("AddPolicyRule not yet implemented"))
    }

    async fn delete_policy_rule(
        &self,
        request: Request<DeletePolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDeletePolicyRule(daemon_ptr(), queue_ptr(), &req.policy_name)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn add_waf_rule(
        &self,
        _request: Request<AddWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("AddWafRule not yet implemented"))
    }

    async fn delete_waf_rule(
        &self,
        request: Request<DeleteWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let found = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDeleteWafRule(daemon_ptr(), queue_ptr(), req.pod_ips)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status: if found { 0 } else { 1 }, uuid: String::new() }))
    }

    async fn dump_heap_profile(
        &self,
        request: Request<DumpHeapProfileRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpHeapProfile(daemon_ptr(), queue_ptr(), req.enable)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn dump_config(
        &self,
        request: Request<DumpConfigRequest>,
    ) -> Result<Response<DumpConfigResponse>, Status> {
        let req = request.into_inner();
        let result = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpConfig(daemon_ptr(), queue_ptr(), &req.policy_name)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;

        let convert = |e: ffi::PolicyRuleConfigEntry| ProtoConfigEntry {
            policy_name: e.policy_name,
            priority: e.priority,
            direction: e.direction,
            action: e.action,
            protocol: e.protocol,
            protocol_int: e.protocol_int,
            from_address: e.from_address,
            to_address: e.to_address,
        };
        Ok(Response::new(DumpConfigResponse {
            inbound_rules: result.inbound_rules.into_iter().map(convert).collect(),
            outbound_rules: result.outbound_rules.into_iter().map(convert).collect(),
            containers: result
                .containers
                .into_iter()
                .map(|c| ProtoContainerInfo { pid: c.pid, pod_id: c.pod_id })
                .collect(),
            tcp_connections: result.tcp_connections,
        }))
    }

    async fn dump_connections(
        &self,
        request: Request<DumpConnectionsRequest>,
    ) -> Result<Response<DumpConnectionsResponse>, Status> {
        let req = request.into_inner();
        let result = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpConnections(daemon_ptr(), queue_ptr(), req.limit)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(DumpConnectionsResponse { total: result.total, items: result.items }))
    }

    async fn reset_config(
        &self,
        _request: Request<ResetConfigRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let status = tokio::task::spawn_blocking(|| unsafe {
            ffi::GrpcDispatchResetConfig(daemon_ptr(), queue_ptr())
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn update_node_config(
        &self,
        request: Request<UpdateNodeConfigRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let is_delete = req.action == Action::Delete as i32;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchUpdateNodeConfig(daemon_ptr(), queue_ptr(), is_delete, req.node_ips)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }

    async fn set_log_level(
        &self,
        request: Request<SetLogLevelRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchSetLogLevel(daemon_ptr(), queue_ptr(), req.level)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
}

unsafe fn start_control_server(
    daemon: *mut ffi::DaemonContext,
    queue: *mut ffi::GrpcDispatchQueue,
    epoll_fd: i32,
    dev_port: u16,
) -> u16 {
    STATE
        .set(ServerState { daemon: daemon as usize, queue: queue as usize, epoll_fd })
        .unwrap_or_else(|_| panic!("start_control_server called more than once"));

    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        rt.block_on(async move {
            let addr: std::net::SocketAddr =
                format!("0.0.0.0:{dev_port}").parse().expect("invalid bind address");
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
                .add_service(NetPolicyControlServer::new(ControlServiceImpl))
                .serve_with_incoming(incoming)
                .await;
        });
    });
    port_rx.recv().unwrap_or(0)
}
