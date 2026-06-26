# Generate C++ bindings

1. Install `cxxbridge`
```bash
$ cargo install cxxbridge-cmd --locked
```

2. Compile the Rust code and generate the C++ headers.
```bash
$ cxxbridge --header --output "include/cxx.h"
$ cargo build --release
```

3. The Rust libraries and headers will be in `target/release` and `include/`. Include both of these directories in the C++ project build.
