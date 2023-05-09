# Define p4 name
P4_NAME=src
# Provide p4 path
#P4_PATH=/home/alex/bf-sde-9.9.0/pkgsrc/p4-examples/p4_16_programs/tna_port_metadata/tna_port_metadata.p4
P4_PATH=$REPO_PATH/tofino_acf_firewall/tofino_poc/p4/src.p4

cd build
cmake $BF_SDE_PATH/p4studio/ -DTOFINO=ON -DTOFINO2=OFF -DCMAKE_INSTALL_PREFIX=$BF_SDE_PATH/install -DCMAKE_MODULE_PATH=$BF_SDE_PATH/cmake \
	-DP4_NAME=$P4_NAME \
	-DP4_PATH=$P4_PATH \
	&& make $P4_NAME -j \
	&& make install
cd ..
