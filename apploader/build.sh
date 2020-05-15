#!/bin/bash
export APP_PATH="\"\""
export COIN=$1
DIR=load_$COIN
mkdir $DIR
p=$PWD
cd $2
make clean
make
make loadcmd > $p/$DIR/load.sh
chmod u+x $p/$DIR/load.sh
#sed -i "s@--path@--path \"44\'/452\'/0\'/0\'\" --path \"44\'/452\'/0\'/1\'\" --path \"44\'/1\'/0\'/0\'\"  --path \"44\'/1\'/0\'/1\'\"  --path \"4541509\'\"@g" $p/$DIR/load.sh
#sed -i "s@--path@--path \"44\'/452\'\" --path \"44\'/1\'\"  --path \"4541509\'\"@g" $p/$DIR/load.sh
sed -i "s@--path@@g" $p/$DIR/load.sh
cp -r bin $p/$DIR
cp -r debug $p/$DIR
cd $p
tar cvfz $DIR.tar.gz $DIR
