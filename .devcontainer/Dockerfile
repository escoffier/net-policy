FROM ubuntu:22.04

RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

RUN apt-get -y update \
  && apt-get -y install --no-install-recommends git clang clangd cmake make tar ca-certificates autoconf automake autotools-dev patch libtool libgflags-dev wget libfmt-dev libboost-dev \
  liblzma-dev zlib1g-dev 2>&1 \
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

RUN wget https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz --no-check-certificate && tar -zxvf v9.0.1.tar.gz \
  && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON .. && make && make install

RUN wget https://github.com/google/glog/archive/refs/tags/v0.6.0.tar.gz --no-check-certificate && tar -zxvf v0.6.0.tar.gz \
  && cd glog-0.6.0  && cmake -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -S . -B build && cmake --build build --target install

RUN wget https://github.com/nghttp2/nghttp2/archive/refs/tags/v1.56.0.tar.gz && tar -zxvf v1.56.0.tar.gz \
  && cd nghttp2-1.56.0 && cmake -DENABLE_STATIC_LIB=ON . && make && make install

RUN wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-10.42.tar.gz && tar -zxvf pcre2-10.42.tar.gz \
  && cd pcre2-pcre2-10.42 && cmake -S . -B build && cmake --build build --target install