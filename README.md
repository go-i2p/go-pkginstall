# go-pkginstall

WARNING: EXPERIMENTAL. I knocked this together based on my abuse of checkinstall and my experience with jpackage. It's very new, it's not been used in the real world very much. Be very careful using it. There's a good chance that some of this is a moving target too. All that said, so far it does what it says on the package. Pay attention and file issues if you have them.

go-pkginstall is a command-line utility written in Go that serves as a slightly more secure replacement for Checkinstall, enabling developers to create Debian packages from source without requiring system-wide installation. This tool enhances security by redirecting operations targeting sensitive system directories to safer alternatives and implementing strict validation mechanisms. These should **mostly** account for the shortcomings of checkinstall **that I understand and know about**.

I intend to use it to produce easy-to-install `.deb` packages of freestanding, statically-compiled Go applications.

## Features

- **Secure Path Management**: Automatically redirects installation paths from system directories (e.g., `/etc`, `/var`, `/home`) to their secure equivalents under `/opt/`.
- **Symlink Management**: Creates symlinks for essential files only when necessary, with strict collision detection to prevent overwriting existing files.
- **Checkinstall Compatibility**: Fully compatible with Checkinstall command-line arguments up to the limits of the above^, allowing for seamless integration into most existing workflows.
- **Package Creation**: Generates .deb packages without requiring root privileges, separating the package creation process from installation.
- **Validation Mechanisms**: Provides warnings for potential issues related to Debian packaging standards and validates paths before package creation.

## Guidelines

- **Keep it simple**: The more complicated your package installation is, the less likely this tool is to work.
- **Know your dependencies**: This tool does absolutely nothing to automatically generate lists of dependencies. You need to specify them in the arguments, or use entirely static applications.
- **Consider something else**: This is intended either for A: Very simple packages or B: Local only packages. Creating a real Debian package is ultimately a better option.

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

This project is licensed under the MIT License. See the LICENSE file for more details.
