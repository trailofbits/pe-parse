FROM alpine:latest
ARG BUILD_TYPE=Release

LABEL name "pe-parse"
LABEL src "https://github.com/trailofbits/pe-parse"
LABEL creator "Trail of Bits"
LABEL dockerfile_maintenance "William Woodruff <william@trailofbits>"
LABEL desc "Principled, lightweight C/C++ PE parser"

RUN apk add --no-cache cmake icu-dev clang build-base

COPY . /app/pe-parse
WORKDIR /app/pe-parse
ENV CC=clang CXX=clang++
RUN mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" .. && \
    cmake --build . && \
    cmake --build . --target install

ENTRYPOINT [ "/usr/bin/dump-pe" ]
CMD ["--help"]
