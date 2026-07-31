pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

// Placeholder bridge module so `corrosion_add_cxxbridge` has something to
// generate a header from (the `cxxbridge` codegen tool errors out if a file
// has no `#[cxx::bridge]` module at all, rather than emitting an empty
// header). Namespace matches what Task 4 of the Phase 2 migration plan will
// use when it fills this in with real extern "C++"/extern "Rust" items; this
// stub is expected to be replaced wholesale at that point.
#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {}
