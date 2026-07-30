FROM ubuntu:22.04

RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

RUN apt-get -y update \
  && apt-get -y install --no-install-recommends git clang clangd cmake make tar ca-certificates autoconf automake autotools-dev patch libtool libgflags-dev wget libfmt-dev libboost-dev \
  liblzma-dev zlib1g-dev libssl-dev 2>&1 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*p

# RUN wget https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz --no-check-certificate && tar -zxvf v9.0.1.tar.gz \
#   && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_STATIC_LIBS=ON .. && make && make install
# #COPY v9.0.1.tar.gz .
# RUN wget https://github.com/google/glog/archive/refs/tags/v0.6.0.tar.gz --no-check-certificate && tar -zxvf v0.6.0.tar.gz \
#   && cd glog-0.6.0  && cmake -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -S . -B build && cmake --build build --target install

# RUN wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-10.42.tar.gz && tar -zxvf pcre2-10.42.tar.gz \
#   && cd pcre2-pcre2-10.42 && cmake -S . -B build && cmake --build build --target install
# RUN tar -zxvf v9.0.1.tar.gz \
#     && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_STATIC_LIBS=ON .. && make && make install

RUN wget https://codeload.github.com/libunwind/libunwind/tar.gz/refs/tags/v1.8.0 -O libunwind-1.8.0.tar.gz && tar -zxvf libunwind-1.8.0.tar.gz \
  && cd libunwind-1.8.0 && autoreconf -i && ./configure && make && make install

RUN wget https://codeload.github.com/gperftools/gperftools/tar.gz/refs/tags/gperftools-2.15 -O gperftools-2.15.tar.gz && tar -zxvf gperftools-2.15.tar.gz \
  && cd gperftools-gperftools-2.15 && ./autogen.sh && ./configure --enable-shared=no --enable-frame-pointers && make && make install

RUN wget https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz && tar -zxvf v1.14.0.tar.gz \
  && cd googletest-1.14.0 && mkdir build && cd build && cmake .. && make && make install

RUN wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
  && echo 'export PATH="/root/.cargo/bin:$PATH"' >> /etc/bash.bashrc
ENV PATH="/root/.cargo/bin:${PATH}"

RUN wget https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz --no-check-certificate && tar -zxvf v9.0.1.tar.gz \
  && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON .. && make && make install

RUN wget https://github.com/google/glog/archive/refs/tags/v0.6.0.tar.gz --no-check-certificate && tar -zxvf v0.6.0.tar.gz \
  && cd glog-0.6.0  && cmake -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -S . -B build && cmake --build build --target install

RUN wget https://github.com/nghttp2/nghttp2/archive/refs/tags/v1.56.0.tar.gz && tar -zxvf v1.56.0.tar.gz \
  && cd nghttp2-1.56.0 && cmake -DENABLE_STATIC_LIB=ON . && make && make install

RUN wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-10.42.tar.gz && tar -zxvf pcre2-10.42.tar.gz \
  && cd pcre2-pcre2-10.42 && cmake -S . -B build && cmake --build build --target install

# --- gRPC control-plane toolchain (see proto/ and grpc/) ---
# Same "wget release tarball, cmake, install into system prefix" style as above.
# Built with `package` provider mode so each step links against the previously
# installed system packages instead of expecting git submodules.
RUN wget https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.1.tar.gz -O abseil-cpp-20230802.1.tar.gz && tar -zxvf abseil-cpp-20230802.1.tar.gz \
  && cd abseil-cpp-20230802.1 && cmake -DCMAKE_CXX_STANDARD=17 -DABSL_PROPAGATE_CXX_STD=ON -DABSL_ENABLE_INSTALL=ON -DBUILD_SHARED_LIBS=OFF -S . -B build && cmake --build build --target install

RUN wget https://github.com/c-ares/c-ares/archive/refs/tags/cares-1_19_1.tar.gz -O c-ares-1.19.1.tar.gz && tar -zxvf c-ares-1.19.1.tar.gz \
  && cd c-ares-cares-1_19_1 && cmake -DCARES_SHARED=OFF -DCARES_STATIC=ON -S . -B build && cmake --build build --target install

RUN wget https://github.com/google/re2/archive/refs/tags/2023-11-01.tar.gz -O re2-2023-11-01.tar.gz && tar -zxvf re2-2023-11-01.tar.gz \
  && cd re2-2023-11-01 && cmake -DBUILD_SHARED_LIBS=OFF -S . -B build && cmake --build build --target install

RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-3.21.12.tar.gz && tar -zxvf protobuf-cpp-3.21.12.tar.gz \
  && cd protobuf-3.21.12 && cmake -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF -S cmake -B build && cmake --build build --target install

RUN wget https://github.com/grpc/grpc/archive/refs/tags/v1.54.3.tar.gz -O grpc-1.54.3.tar.gz && tar -zxvf grpc-1.54.3.tar.gz \
  && cd grpc-1.54.3 && cmake -DgRPC_BUILD_TESTS=OFF \
       -DgRPC_INSTALL=ON \
       -DgRPC_ABSL_PROVIDER=package \
       -DgRPC_CARES_PROVIDER=package \
       -DgRPC_PROTOBUF_PROVIDER=package \
       -DgRPC_RE2_PROVIDER=package \
       -DgRPC_SSL_PROVIDER=package \
       -DgRPC_ZLIB_PROVIDER=package \
       -DBUILD_SHARED_LIBS=OFF \
       -S . -B build && cmake --build build --target install