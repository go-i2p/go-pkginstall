
CGO_ENABLED=0 go build -o pkginstall -tags netgo,osusergo -ldflags "-extldflags '-static'" ./cmd/pkginstall
mkdir -p ./build/usr/bin
cp ./pkginstall ./build/usr/bin/
mkdir -p ./build/usr/share/doc/go-pkginstall
cp README.md LICENSE ./build/usr/share/doc/go-pkginstall/
./pkginstall build \
            --name go-pkginstall \
            --version 1.0.0 \
            --maintainer "go-i2p <idk@i2pmail.org>" \
            --description "A replacement for Checkinstall with mildly enhanced security features" \
            --source ./build \
            --verbose