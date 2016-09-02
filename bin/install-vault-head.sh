#!/bin/bash
set -eux

mkdir -p $HOME/bin

export GOPATH=$HOME/go
mkdir $GOPATH

export PATH=$GOPATH/bin:$PATH

bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
source /home/travis/.gvm/scripts/gvm
gvm get
gvm install 1.7 --binary || gvm install 1.7
gvm use 1.7

go get github.com/tools/godep
go get github.com/mitchellh/gox

git clone https://github.com/hashicorp/vault.git $GOPATH/src/github.com/hashicorp/vault
cd $GOPATH/src/github.com/hashicorp/vault
make dev

mv bin/vault $HOME/bin