# go-pkginstall

go-pkginstall is a command-line utility written in Go that serves as a secure replacement for Checkinstall, enabling developers to create Debian packages from source without requiring system-wide installation. This tool enhances security by redirecting operations targeting sensitive system directories to safer alternatives and implementing strict validation mechanisms.

## Features

- **Secure Path Management**: Automatically redirects installation paths from system directories (e.g., `/etc`, `/var`, `/home`) to their secure equivalents under `/opt/`.
- **Symlink Management**: Creates symlinks for essential files only when necessary, with strict collision detection to prevent overwriting existing files.
- **Checkinstall Compatibility**: Fully compatible with Checkinstall command-line arguments, allowing for seamless integration into existing workflows.
- **Package Creation**: Generates .deb packages without requiring root privileges, separating the package creation process from installation.
- **Validation Mechanisms**: Provides warnings for potential issues related to Debian packaging standards and validates paths before package creation.

## Installation

To install go-pkginstall, clone the repository and build the application:

```bash
git clone https://github.com/go-i2p/go-pkginstall.git
cd go-pkginstall
go build ./cmd/pkginstall
```

## Usage

After building the application, you can use it from the command line. The basic syntax is:

```bash
./pkginstall [options]
```

For a complete list of options and commands, run:

```bash
./pkginstall --help
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.# go-pkginstall
