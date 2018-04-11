## Useful links:
- Ethernet ref: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
- IP ref: https://github.com/afabbro/netinet/blob/master/ip.h
- BPFabric ref: https://github.com/UofG-netlab/BPFabric

## Important Information:
To use count-min sketch (table cmin_sketch) it is necessary to replace some files in the BPFabric directory and execute make. It is also necessary to add an entry 'BPF_MAP_TYPE_CMIN_SKETCH' in bpf_map_type enum (in '/usr/include/linux/bpf.h' file).
