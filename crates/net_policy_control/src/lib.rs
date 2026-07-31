pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

use proto::net_policy_control_server::{NetPolicyControl, NetPolicyControlServer};
use proto::{
    AddPolicyRuleRequest, AddWafRuleRequest, DeletePolicyRuleRequest, DeleteWafRuleRequest,
    DumpConfigRequest, DumpConfigResponse, DumpConnectionsRequest, DumpConnectionsResponse,
    DumpHeapProfileRequest, PodDownRequest, PodUpRequest, ResetConfigRequest, SetLogLevelRequest,
    StatusResponse, UpdateNodeConfigRequest,
};
use std::sync::OnceLock;
use tonic::{transport::Server, Request, Response, Status};

#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {
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
    #[allow(dead_code)]
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
        _request: Request<PodUpRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("PodUp not yet implemented"))
    }

    async fn pod_down(
        &self,
        _request: Request<PodDownRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("PodDown not yet implemented"))
    }

    async fn add_policy_rule(
        &self,
        _request: Request<AddPolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("AddPolicyRule not yet implemented"))
    }

    async fn delete_policy_rule(
        &self,
        _request: Request<DeletePolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("DeletePolicyRule not yet implemented"))
    }

    async fn add_waf_rule(
        &self,
        _request: Request<AddWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("AddWafRule not yet implemented"))
    }

    async fn delete_waf_rule(
        &self,
        _request: Request<DeleteWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("DeleteWafRule not yet implemented"))
    }

    async fn dump_heap_profile(
        &self,
        _request: Request<DumpHeapProfileRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("DumpHeapProfile not yet implemented"))
    }

    async fn dump_config(
        &self,
        _request: Request<DumpConfigRequest>,
    ) -> Result<Response<DumpConfigResponse>, Status> {
        Err(Status::unimplemented("DumpConfig not yet implemented"))
    }

    async fn dump_connections(
        &self,
        _request: Request<DumpConnectionsRequest>,
    ) -> Result<Response<DumpConnectionsResponse>, Status> {
        Err(Status::unimplemented("DumpConnections not yet implemented"))
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
        _request: Request<UpdateNodeConfigRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("UpdateNodeConfig not yet implemented"))
    }

    async fn set_log_level(
        &self,
        _request: Request<SetLogLevelRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("SetLogLevel not yet implemented"))
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
