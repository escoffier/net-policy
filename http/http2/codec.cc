#include "codec.hh"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <glog/logging.h>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <string_view>
#include <utility>

#include "http/codec.h"
#include "http/filter.h"
#include "http/packet.hh"
#include "http/utility.h"

namespace http {
namespace http2 {

constexpr std::string_view HEADER_METHOD{":method"};
constexpr std::string_view HEADER_PATH{":path"};
constexpr std::string_view HEADER_AUTHORITY{":authority"};

std::string strframetype(uint8_t type) {
  switch (type) {
  case NGHTTP2_DATA:
    return "DATA";
  case NGHTTP2_HEADERS:
    return "HEADERS";
  case NGHTTP2_PRIORITY:
    return "PRIORITY";
  case NGHTTP2_RST_STREAM:
    return "RST_STREAM";
  case NGHTTP2_SETTINGS:
    return "SETTINGS";
  case NGHTTP2_PUSH_PROMISE:
    return "PUSH_PROMISE";
  case NGHTTP2_PING:
    return "PING";
  case NGHTTP2_GOAWAY:
    return "GOAWAY";
  case NGHTTP2_WINDOW_UPDATE:
    return "WINDOW_UPDATE";
  case NGHTTP2_ALTSVC:
    return "ALTSVC";
  case NGHTTP2_ORIGIN:
    return "ORIGIN";
    // case NGHTTP2_PRIORITY_UPDATE:
    //   return "PRIORITY_UPDATE";
  }

  std::string s = "extension(0x";
  // s += util::format_hex(&type, 1);
  // s += ')';

  return s;
};

void deleteSession(nghttp2_session* session) {
  if (session) {
    LOG(INFO) << "deleting nghttp2 session";
    nghttp2_session_del(session);
  }
}

session_unque_ptr makeSessionUniquePtr(nghttp2_session_callbacks* callbacks, void* user_data) {
  LOG(INFO) << "session callbacks: " << callbacks << std::endl;
  nghttp2_session* session;
  nghttp2_session_server_new(&session, callbacks, user_data);
  LOG(INFO) << "make session: " << session << std::endl;
  nghttp2_session_callbacks_del(callbacks);
  return session_unque_ptr(session, deleteSession);
}

nghttp2_session_callbacks* callbacks() {
  nghttp2_session_callbacks* callbacks;
  nghttp2_session_callbacks_new(&callbacks);

  // nghttp2_session_callbacks_set_recv_callback(
  //     callbacks,
  //     [](nghttp2_session *session, uint8_t *buf, size_t length, int flags,
  //        void *user_data) -> ssize_t {
  //       auto codec = reinterpret_cast<ConnectionImpl *>(user_data);
  //       if (codec->isHeaderComplete()) {
  //         LOG(INFO) << "header is completed";
  //         return NGHTTP2_ERR_WOULDBLOCK;
  //       }
  //       auto data = codec->getBufferData(length);
  //       if (data.empty()) {
  //         LOG(INFO) << "buf data is empty";
  //         return NGHTTP2_ERR_EOF;
  //       }

  //       LOG(INFO) << "recv_callback read " << data.size() << " bytes";
  //       std::memcpy(buf, data.data(), data.size());
  //       codec->trimBufFront(data.size());
  //       return data.size();
  //     });

  nghttp2_session_callbacks_set_on_header_callback(
      callbacks,
      [](nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* raw_name,
         size_t name_length, const uint8_t* raw_value, size_t value_length, uint8_t,
         void* user_data) -> int {
        if (frame->hd.type == NGHTTP2_HEADERS) {
          if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            return 0;
          }
          std::string_view name{reinterpret_cast<const char*>(raw_name), name_length};

          LOG(INFO) << "stream id: " << frame->hd.stream_id << ", on headers: (" << raw_name
                    << " : " << raw_value << ")" << std::endl;
          Header* header = reinterpret_cast<Header*>(
              nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
          auto codec = reinterpret_cast<ConnectionImpl*>(user_data);
          if (name.compare(HEADER_METHOD) == 0) {
            auto value = reinterpret_cast<const char*>(raw_value);
            codec->setMethod(std::string_view{value, value_length});
            header->method_ = std::string_view{value, value_length};
          } else if (name.compare(HEADER_PATH) == 0) {
            auto value = reinterpret_cast<const char*>(raw_value);
            codec->setPath(std::string_view{value, value_length});
            header->path_ = std::string_view{value, value_length};
          } else if (name.compare(HEADER_AUTHORITY) == 0) {
            auto value = reinterpret_cast<const char*>(raw_value);
            codec->setHost(std::string_view{value, value_length});
            header->host_ = std::string_view{value, value_length};
          }
          if (codec->isHeaderComplete()) {
            header->parseState_ = ParseState::Done;
            codec->onHeadersComplete();
          }
        }
        return 0;
      });

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, [](nghttp2_session* session, const nghttp2_frame* frame, void* user_data) -> int {
        LOG(INFO) << "stream id: " << frame->hd.stream_id << ": on_begin_headers" << std::endl;
        if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
          return 0;
        }
        auto header = new Header;
        nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, header);
        return 0;
      });

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks,
      [](nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data,
         size_t len, void* user_data) -> int { return 0; });

  nghttp2_session_callbacks_set_on_frame_recv_callback(
      callbacks, [](nghttp2_session* session, const nghttp2_frame* frame, void* user_data) -> int {
        // LOG(INFO) << frame->hd.stream_id << ": on_frame_recv" << std::endl;
        LOG(INFO) << "receive " << strframetype(frame->hd.type) << " frame "
                  << "<length=" << frame->hd.length << ", flags=" << int(frame->hd.flags)
                  << ", stream_id=" << frame->hd.stream_id << ">";
        switch (frame->hd.type) {
        case NGHTTP2_DATA:
        case NGHTTP2_HEADERS:
          /* Check that the client request has finished */
          if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            //   stream_data = nghttp2_session_get_stream_user_data(
            //       session, frame->hd.stream_id);
            //   /* For DATA and HEADERS frame, this callback may be called
            //   after
            //      on_stream_close_callback. Check that stream still alive. */
            //   if (!stream_data) {
            //     return 0;
            //   }
            //   return on_request_recv(session, session_data, stream_data);
            return 0;
          }
          break;
        default:
          break;
        }
        return 0;
      });

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks,
      [](nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data) -> int {
        LOG(INFO) << stream_id << "on_stream_close";
        Header* header = (Header*)nghttp2_session_get_stream_user_data(session, stream_id);
        delete header;
        return 0;
      });

  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
      callbacks,
      [](nghttp2_session* session, const nghttp2_frame* frame, int lib_error_code,
         void* user_data) -> int {
        LOG(INFO) << "invalid " << strframetype(frame->hd.type) << " frame "
                  << "<length=" << frame->hd.length << ", flags=" << int(frame->hd.flags)
                  << ", stream_id=" << frame->hd.stream_id << "> "
                  << "err: " << nghttp2_strerror(lib_error_code);
        return 0;
      });
  LOG(INFO) << "create callbacks: " << callbacks << std::endl;
  return callbacks;
}
// nghttp2_session_callbacks *ConnectionImpl::callbacks_ = callbacks();

// Connection::Connection() : session_(makeSessionUniquePtr(callbacks_)) {}

// int64_t Connection::processData(std::string_view data) {
//   std::cout << "processData session: " << session_.get()
//             << " data length: " << data.size() << std::endl;
//   return nghttp2_session_mem_recv(
//       session_.get(), reinterpret_cast<const uint8_t *>(data.data()),
//       data.size());
// }

ConnectionImpl::ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager)
    : session_(nullptr, nullptr), header_{"", "", "", ParseState::Continue}, packet_(),
      filters_manager_(filterManager) {
  session_ = makeSessionUniquePtr(callbacks(), this);
  // filters_manager_ = std::make_unique<HttpFilterManager>(serverSide);
}

const Header& ConnectionImpl::dispatch(std::string_view data) {
  VLOG(8) << "dispatching " << data.size() << " bytes data";
  if (isHeaderComplete()) {
    return header_;
  }
  auto ret = nghttp2_session_mem_recv(session_.get(), reinterpret_cast<const uint8_t*>(data.data()),
                                      data.size());
  if (ret < 0) {
    LOG(ERROR) << "http2 parser err: " << nghttp2_strerror(ret);
    header_.parseState_ = ParseState::Error;
    return header_;
  }
  VLOG(8) << "processed " << ret << " bytes";

  // packet_.append(
  //     seastar::net::packet::from_static_data(data.data(), data.size()));

  // auto ret = nghttp2_session_recv(session_.get());
  // if (ret < 0) {
  //   LOG(ERROR) << "Error " << nghttp2_strerror(ret) << ": " << ret
  //              << nghttp2_strerror(ret);
  //   header_.parseState_ = ParseState::Error;
  //   return header_;
  // }
  return header_;
}

const FilterStatus ConnectionImpl::dispatch(seastar::net::packet pkt) {
  auto data = pkt.get_header(0, pkt.len());
  VLOG(8) << "dispatching " << pkt.len() << " bytes data";
  if (isHeaderComplete()) {
    return status_;
  }
  auto ret =
      nghttp2_session_mem_recv(session_.get(), reinterpret_cast<const uint8_t*>(data), pkt.len());
  if (ret < 0) {
    LOG(ERROR) << "http2 parser err: " << nghttp2_strerror(ret);
    header_.parseState_ = ParseState::Error;
    return status_;
  }
  VLOG(8) << "processed " << ret << " bytes";

  // packet_.append(
  //     seastar::net::packet::from_static_data(data.data(), data.size()));

  // auto ret = nghttp2_session_recv(session_.get());
  // if (ret < 0) {
  //   LOG(ERROR) << "Error " << nghttp2_strerror(ret) << ": " << ret
  //              << nghttp2_strerror(ret);
  //   header_.parseState_ = ParseState::Error;
  //   return header_;
  // }
  return status_;
}

bool ConnectionImpl::isHeaderComplete() {
  LOG(INFO) << header_;
  return !(header_.path_.empty() || header_.host_.empty() || header_.method_.empty());
}

std::string_view ConnectionImpl::getBufferData(size_t length) {
  auto len = std::min((size_t)packet_.len(), length);
  auto buf = packet_.get_header(0, len);
  // packet_.trim_front(len);
  std::string_view data(buf, packet_.len());
  return data;
}

void ConnectionImpl::trimBufFront(size_t length) { packet_.trim_front(length); }

void ConnectionImpl::addFilter(HttpFilterPtr filter) {
  filters_manager_->addFilter(std::move(filter));
}

void ConnectionImpl::setFilterManager(HttpFilterManagerPtr filterManager) {
  filters_manager_ = filterManager;
}

} // namespace http2
} // namespace http
