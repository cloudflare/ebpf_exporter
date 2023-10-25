package kallsyms

import (
	"reflect"
	"testing"
)

// kallsyms.txt is created from the stack below with the filter to wilt it down:
//
//   sudo cat /proc/kallsyms | grep -C3 -E ' (el0t_64_sync|el0t_64_sync_handler|el0_svc|do_el0_svc|invoke_syscall.constprop.0|__arm64_sys_execve|do_execveat_common|bprm_execve|load_elf_binary|begin_new_exec|mmput|__mmput|exit_mmap|unmap_vmas|unmap_page_range|mark_page_accessed|bpf_trampoline_6442507883.*|bpf_prog_.*_mark_page_accessed)$' > ksym/kallsyms.txt

func TestStack(t *testing.T) {
	stacks := [][]Addr{
		{
			{0xffffffc0801cee9c, "bpf_prog_9a4f2895a09f572a_mark_page_accessed\t[bpf]"},
			{0xffffffc0801cee9c, "bpf_prog_9a4f2895a09f572a_mark_page_accessed\t[bpf]"},
			{0xffffffc08012d06c, "bpf_trampoline_6442507883\t[bpf]"},
			{0xffffffeb19cadfc8, "mark_page_accessed"},
			{0xffffffeb19cf6148, "unmap_page_range"},
			{0xffffffeb19cf6694, "unmap_vmas"},
			{0xffffffeb19d04a60, "exit_mmap"},
			{0xffffffeb19a8a5fc, "__mmput"},
			{0xffffffeb19a8a7fc, "mmput"},
			{0xffffffeb19d900e4, "begin_new_exec"},
			{0xffffffeb19e06ba0, "load_elf_binary"},
			{0xffffffeb19d8f17c, "bprm_execve"},
			{0xffffffeb19d8f754, "do_execveat_common"},
			{0xffffffeb19d8f83c, "__arm64_sys_execve"},
			{0xffffffeb19a28a04, "invoke_syscall.constprop.0"},
			{0xffffffeb19a28afc, "do_el0_svc"},
			{0xffffffeb1a34d2d8, "el0_svc"},
			{0xffffffeb1a34d768, "el0t_64_sync_handler"},
			{0xffffffeb19a11558, "el0t_64_sync"},
		},
	}

	d, err := NewDecoder("kallsyms.txt")
	if err != nil {
		t.Fatalf("Error creating ksym decoder: %v", err)
	}

	for i, stack := range stacks {
		addrs := make([]uintptr, len(stack))
		for j, addr := range stack {
			addrs[j] = addr.Ptr
		}

		decoded := d.Stack(addrs)

		if !reflect.DeepEqual(stack, decoded) {
			t.Errorf("expected decoded stack %#v, got %#v", stack, decoded)

			for j, addr := range stack {
				if !reflect.DeepEqual(addr, decoded[j]) {
					t.Errorf("Expected stack %d at position %d to be %#v, got %#v", i, j, addr, decoded[j])
				}
			}
		}
	}
}

func TestSymLookup(t *testing.T) {
	addrs := []Addr{
		{0xffffffeb19a8a478, ""},
		{0xffffffeb19a8a480, "__pidfd_prepare"},
		{0xffffffeb19a8a482, ""},
		{0xffffffeb19cadfc0, "mark_page_accessed"},
	}

	d, err := NewDecoder("kallsyms.txt")
	if err != nil {
		t.Fatalf("Error creating ksym decoder: %v", err)
	}

	for _, addr := range addrs {
		sym := d.Sym(addr.Ptr)
		if sym != addr.Sym {
			t.Errorf("Expected addr 0x%x to resolve to %q, got %q instead", addr.Ptr, addr.Sym, sym)
		}
	}
}
