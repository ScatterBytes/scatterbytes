#!/bin/bash

# check for overrides from environment
if [ "$SB_REPO_HOST" = "" ]; then
    SB_REPO_HOST="software.scatterbytes.net"
    SB_REPO_KEY_ID="E17566D2"
fi

if [ "$SB_PGP_KEYSERVER" = "" ]; then
    SB_PGP_KEYSERVER=subkeys.pgp.net
fi


APT_FILEPATH=/etc/apt/sources.list.d/scatterbytes.list
APT_LINE="deb http://$SB_REPO_HOST/apt/debian unstable main"


# Install the repository.
if [ ! -e $APT_FILEPATH ]; then
    echo "Installing Repository $APT_FILEPATH"
    echo $APT_LINE > $APT_FILEPATH
    # Fetch the key.
    echo "Installing the repository public key."
    apt-key adv --recv-keys --keyserver $SB_PGP_KEYSERVER $SB_REPO_KEY_ID
    # Install the package.
    if [ "$1" = "server" ]; then
        apt-get update && apt-get -y install scatterbytes-server
    else
        apt-get update && apt-get -y install scatterbytes-cli
    fi
else
    echo "Repository $APT_FILEPATH is already present."
fi
