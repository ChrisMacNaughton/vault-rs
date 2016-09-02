#!/bin/bash
set -eux

mkdir -p $HOME/bin

export GOPATH=$HOME/go
mkdir -p $GOPATH

export PATH=$GOPATH/bin:$PATH

git clone https://github.com/hashicorp/vault.git $GOPATH/src/github.com/hashicorp/vault
cd $GOPATH/src/github.com/hashicorp/vault
make bootstrap
# go get github.com/tools/godep
# go get github.com/mitchellh/gox
make dev

mv bin/vault $HOME/bin