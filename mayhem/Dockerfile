FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake libeigen3-dev

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

RUN clang++ /repo/mayhem/fuzz_initialize_from_txt.cpp -fsanitize=fuzzer,address -I /install/include/ -I /usr/include/eigen3/ /install/lib/libPoseLib.a -o /fuzz

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_initialize_from_text
