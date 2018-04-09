ARCH=$(dpkg --print-architecture)
RELEASE_VERSION="$(lsb_release -is)$(lsb_release -rs | grep -Po "[0-9]{1,3}" | head -1)"
PKG_VERSION=1
DEB_DIR=packaging/deb
version=$(tr -d [:space:] < VERSION)

autoreconf -if
./configure $* 
make clean
make dist

# Rebuild debian changelog.
if command  -v dch > /dev/null; then
  echo "Generating debian changelog..."
  $DEB_DIR/rebuild_changelog.sh Changelog $DEB_DIR/control gttlvutil $DEB_DIR/changelog "0.3.64:unstable "
else
  >&2 echo "Error: Unable to generate Debian changelog file as dch is not installed!"
  >&2 echo "Install devscripts 'apt-get install devscripts'"
  exit 1
fi



tar xvfz gttlvutil-$version.tar.gz
mv gttlvutil-$version.tar.gz gttlvutil-$version.orig.tar.gz
mkdir gttlvutil-$version/debian
cp $DEB_DIR/control $DEB_DIR/changelog $DEB_DIR/rules $DEB_DIR/copyright gttlvutil-$version/debian
chmod +x gttlvutil-$version/debian/rules
cd gttlvutil-$version
# debuild cleans some environment variables, to keep LIBS -e is used.
debuild -D -e LIBS -us -uc
#$debuild_flags
cd ..

