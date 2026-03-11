sudo bpftool feature probe kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
sudo bpftool prog trace
sudo bpftool map list # Shows all eBPF Maps loaded into the kernel 
---
sudo bpftool prog show id 15
sudo bpftool prog show name handle_execve_tp
sudo bpftool prog show tag 8236b54ceef5a3ce
---
sudo bpftool prog show id 15 --pretty
https://ebpfchirp.substack.com/p/how-to-find-supported-ebpf-helper