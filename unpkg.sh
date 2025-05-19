rm tmp build opt control data data.tar control.tar debian-binary -rfv
mkdir tmp
cd tmp
ar -x ../go-pkginstall_1.0.0_amd64.deb
unxz -f data.tar.xz
unxz -f control.tar.xz
tar -xvf data.tar
tar -xvf control.tar