
FROM rust:1.59.0 as builder

RUN mkdir /usr/src/auth-service
WORKDIR /usr/src/auth-service
COPY . .

RUN apt-get update -yq 
RUN apt install openssl libssl-dev clang llvm-dev libclang-dev -yq

RUN rustup default 1.59.0
RUN cargo build --release

EXPOSE 3000
EXPOSE 5432


FROM rust:1.59.0



COPY --from=builder /usr/src/auth-service/target/release/auth-service /usr/src/auth-service/
COPY --from=builder /usr/src/auth-service/.env /usr/src/.env


WORKDIR /usr/src/auth-service

EXPOSE 3000
EXPOSE 5432

CMD ["./auth-service"]
