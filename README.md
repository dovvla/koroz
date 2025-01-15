# koroz

`koroz` is a DNS monitoring and caching system that leverages eBPF for high-performance packet processing. It captures DNS responses, processes them, and stores the data in a PostgreSQL database for further analysis. The project also includes a web server for exposing metrics and DNS data via APIs.

## Features

- **eBPF-based DNS Monitoring**: Uses eBPF to capture DNS responses directly from the network interface.
- **DNS Caching and Purging**: Implements a caching mechanism with TTL-based purging and repopulation.
- **PostgreSQL Integration**: Stores DNS responses in a PostgreSQL database for persistence and querying.
- **Prometheus Metrics**: Exposes metrics for monitoring system performance and DNS activity.
- **Warp-based Web Server**: Provides APIs for accessing DNS data and metrics.
- **Docker Support**: Includes Docker Compose configuration for running dependencies like PostgreSQL and Unbound DNS server.

## Prerequisites

1. **Rust Toolchains**:
   - Install stable Rust: `rustup toolchain install stable`
   - Install nightly Rust: `rustup toolchain install nightly --component rust-src`
2. **Cross-compilation (Optional)**:
   - Add target: `rustup target add ${ARCH}-unknown-linux-musl`
   - Install LLVM: `brew install llvm` (on macOS)
   - Install C toolchain: [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
3. **bpf-linker**: Install with `cargo install bpf-linker` (`--no-default-features` on macOS).
4. **Docker**: Required for running the Unbound DNS server and PostgreSQL.

## Project Structure

```
koroz/
├── src/
│   ├── main.rs               # Main application entry point
│   ├── event_manip.rs        # Handles DNS record invalidation and repopulation
│   ├── persistence.rs        # Database persistence logic
│   ├── settings.rs           # Configuration management
│   ├── structs.rs            # Core data structures
│   ├── warp_handlers.rs      # Warp-based HTTP handlers
│   └── migrations/           # Database migration scripts
├── build.rs                  # Build script for eBPF integration
├── Settings.toml             # Application configuration
├── Cargo.toml                # Rust package configuration
├── README.md                 # Project documentation
└── ...
```

## Build & Run

### Running Locally

1. **Build the Project**:
   ```sh
   cargo build
   ```

2. **Run the Application**:
   ```sh
   cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
   ```

3. **Run Dependencies**:
   Use the provided Docker Compose file to start PostgreSQL and Unbound:
   ```sh
   cd dev_utils
   sudo docker-compose up
   ```

### Cross-compiling on macOS

To cross-compile for Linux:
```sh
CC=${ARCH}-linux-musl-gcc cargo build --package koroz --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled binary will be available at:
```
target/${ARCH}-unknown-linux-musl/release/koroz
```

## API Endpoints

- **Metrics**: Exposes Prometheus metrics at `/metrics`.
- **DNS Data**: Provides DNS data at `/universe`.

## Configuration

The application uses `Settings.toml` for configuration. Example:
```toml
purge_wake_up_interval = 1
min_ttl_to_keep_record = 30
max_ttl_to_keep_record = 3600
max_records_to_refresh_in_cycle = 100
we_running_docker = true
min_time_to_expire_to_purge = 300
```

## Database Schema

The database schema is defined in the migration script:
```sql
CREATE TABLE dns_answers (
    domain_name VARCHAR NOT NULL,
    ttl INTEGER NOT NULL,
    record_type VARCHAR NOT NULL,
    read_from_buffer_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (domain_name, record_type)
);
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Aya](https://github.com/aya-rs/aya): Rust library for eBPF.
- [Warp](https://github.com/seanmonstar/warp): Web framework for Rust.
- [Prometheus](https://prometheus.io/): Monitoring and alerting toolkit.
- [Docker](https://www.docker.com/): Containerization platform.
