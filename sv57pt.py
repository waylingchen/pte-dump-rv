import gdb
import sys
import ctypes

#for SV57
PGD_MASK = 0x1ff000000000000
PGD_SHIFT = 48
P4D_MASK = 0xff8000000000
P4D_SHIFT = 39
PUD_MASK = 0x7fc0000000
PUD_SHIFT = 30
PMD_MASK = 0x3fe00000
PMD_SHIFT = 21
PAGE_MASK = 0x1ff000
PAGE_SHIFT = 12
PTE_SHIFT=10
VA_BITS = 57
DESCRIPTOR_SIZE = 8
PHYS_ADDR = 0x80200000
PAGE_OFFSET = 0xff60000000000000
VMEMMAP_BASE = 0xff1c000000000000

ker_map = gdb.parse_and_eval("kernel_map").address
VA_PA_OFFSET = ctypes.c_ulong(ker_map['va_pa_offset']).value

page_ptr = gdb.lookup_type("struct page").pointer()
vmem = gdb.Value(VMEMMAP_BASE)
vmemptr = vmem.cast(page_ptr)
init_taskg = gdb.parse_and_eval("init_task").address

def offsetof(_type, member):
    return (gdb.Value(0).cast(_type)[member]).address
def container_of(ptr, _type, member):
    ulong = gdb.lookup_type("unsigned long")
    top = ptr.cast(ulong) - offsetof(_type, member).cast(ulong)
    return top.cast(_type)
def task_lists():
    task_ptr_type = gdb.lookup_type("struct task_struct").pointer()
    init_taskm = gdb.parse_and_eval("init_task").address
    t = g = init_taskm
    while True:
        while True:
            yield t
            t = container_of(t['thread_group']['next'],task_ptr_type, "thread_group")
            if t == g:
                break
        t = g = container_of(g['tasks']['next'],task_ptr_type, "tasks")
        if t == init_taskm:
            return
def read_qword(addr):
    m = gdb.selected_inferior().read_memory(addr, 8);
    return int.from_bytes(m.tobytes(), byteorder='little')
def phys_to_virt(addr):
    return addr + VA_PA_OFFSET
def virt_to_phys(addr):
    return addr - VA_PA_OFFSET
def get_pgd_offset(addr):
    return ((addr & PGD_MASK) >> PGD_SHIFT) * DESCRIPTOR_SIZE
def get_p4d_offset(addr):
    return ((addr & P4D_MASK) >> P4D_SHIFT) * DESCRIPTOR_SIZE
def get_pud_offset(addr):
    return ((addr & PUD_MASK) >> PUD_SHIFT) * DESCRIPTOR_SIZE
def get_pmd_offset(addr):
    return ((addr & PMD_MASK) >> PMD_SHIFT) * DESCRIPTOR_SIZE
def get_pte_offset(addr):
    return ((addr & PAGE_MASK) >> PAGE_SHIFT) * DESCRIPTOR_SIZE
def get_pte_offset_huge(addr):
    return ((addr & PAGE_MASK) >> PAGE_SHIFT) * DESCRIPTOR_SIZE
def get_task_by_pid(pid):
    ulong = gdb.lookup_type("unsigned long")
    for task in task_lists():
        if int(task['pid']) == int(pid):
            print("{:>10} {:>12} {:>7}\n".format("TASK", "PID", "COMM"))
            print("{} {:^5} {}\n".format(task.format_string().split()[0],task["pid"].format_string(),task["comm"].string()))
            tmp = task['mm']
            if(tmp == 0):
                print("debug")
                return ctypes.c_ulong(init_taskg['active_mm']['pgd']).value
            else:
                return ctypes.c_ulong(task['mm']['pgd']).value
    return None

PTE_flags = ['V','R','W','X','U','G','A','D',...]
PG_flags = [
	'PG_locked',
	'PG_writeback',
	'PG_referenced',
	'PG_uptodate',
	'PG_dirty',
	'PG_lru',
	'PG_head',
	'PG_waiters',
	'PG_active',
	'PG_workingset',
	'PG_error',
	'PG_slab',
	'PG_owner_priv_1',
	'PG_arch_1',
	'PG_reserved',
	'PG_private',
	'PG_private_2',
	'PG_mappedtodisk',
	'PG_reclaim',
	'PG_swapbacked',
	'PG_unevictable',
	'PG_mlocked'
    ]

pgsize = {0 : "4KB", 1 : "2MB" , 2 : "1GB" }

def set_offset(addr_t):
    bits = addr_t & ((1 << PTE_SHIFT) - 1)
    bitmask = bits
    tmp = [flag for (index, flag) in enumerate(PTE_flags) if (bitmask & 2**index)]
    tmp.reverse()
    print('PTE flag : {name} {text}'.format(name=bin(bits), text=tmp))
    addr_t &= ~((1 << PTE_SHIFT) - 1)
    addr_t = addr_t >> PTE_SHIFT
    addr_t = addr_t << PAGE_SHIFT
    return addr_t

def leaf(addr_t):
	bits = addr_t & 0xf
	if(bits != 1):
		return True
	else:
		return False

def show_addr(phys_page_addr,offset,level):
	if phys_page_addr!=0:
		page_addr = phys_to_virt(phys_page_addr)
		pa = int(phys_page_addr)|offset
		va = int(page_addr)|offset
		print("PFN : %d" % int(phys_page_addr >> PAGE_SHIFT))
		print('page size = {sz:10}'.format(sz=pgsize[level]));
		print('{sz} page frame virtual address  = [{addr}]'.format(sz=pgsize[level],addr=hex(page_addr)))
		print('{sz} page frame physical address = [{addr}]'.format(sz=pgsize[level],addr=hex(phys_page_addr)))
		if pa >= PHYS_ADDR:
			val = vmemptr + (phys_page_addr >> PAGE_SHIFT)
			bitmask = ctypes.c_ulong(val['flags']).value
			tmp = [flag for (index, flag) in enumerate(PG_flags) if (bitmask & 2**index)]
			tmp.reverse()
			print("struct page * address : [0x%lx]" % val)
			print('struct page flag : {name} {text}'.format(name=val, text=tmp))
			print("=> target virtual address  = [0x%lx]" % va)
			print("=> target physical address = [0x%lx]" % pa)
		else:
			print("Can't get page struct")

class LxTaskMMU(gdb.Command):
	def __init__(self):
		super(LxTaskMMU, self).__init__("lxtask", gdb.COMMAND_DATA)
	def invoke(self, myarg,from_tty):
		args = gdb.string_to_argv(myarg)
		pid = int(args[0], 10)
		addr = int(args[1], 16) & 0xffffffffffffffff
		addroffset = addr & ((1 << PAGE_SHIFT) - 1)
		addroffsetpmd = addr & ((1 << PMD_SHIFT) - 1)
		addroffsetpud = addr & ((1 << PUD_SHIFT) - 1)
		pgd = get_task_by_pid(pid)
		if pgd:
			ptmp = pgd
			ptmp = virt_to_phys(ptmp) >> PAGE_SHIFT
			satp = 0xa << 60 | ptmp
			print("satp = 0x%lx\n" % satp)
			#print("=> target virtual address = 0x%lx\n" % addr)
			print("PGD virtual address = 0x%lx" % pgd)
			pgd_offset = get_pgd_offset(addr)
			print("PGD offset = 0x%lx" % pgd_offset)
			phys_p4d_addr = read_qword(pgd + pgd_offset)
			phys_p4d_addr = set_offset(phys_p4d_addr)
			print("P4D physical address = 0x%lx" % phys_p4d_addr)
			p4d_addr = phys_to_virt(phys_p4d_addr)
			p4d_offset = get_p4d_offset(addr)
			print("P4D offset = 0x%lx" % p4d_offset)
			print("P4D virtual address = 0x%lx" % (p4d_addr + p4d_offset))
			phys_pud_addr = read_qword(p4d_addr + p4d_offset)
			phys_pud_addr = set_offset(phys_pud_addr)
			print("PUD physical address = 0x%lx" % phys_pud_addr)
			pud_addr = phys_to_virt(phys_pud_addr)
			pud_offset = get_pud_offset(addr)
			print("PUD offset = 0x%lx" % pud_offset)
			print("PUD virtual address = 0x%lx" % (pud_addr + pud_offset))
			phys_pmd_addr = read_qword(pud_addr + pud_offset)
			if(leaf(phys_pmd_addr)):
				phys_pmd_addr = set_offset(phys_pmd_addr)
				show_addr(phys_pmd_addr,addroffsetpud,2)
				return
			phys_pmd_addr = set_offset(phys_pmd_addr)
			print("PMD physical address = 0x%lx" % phys_pmd_addr)
			pmd_addr = phys_to_virt(phys_pmd_addr)
			pmd_offset = get_pmd_offset(addr)
			print("PMD offset = 0x%lx" % pmd_offset)
			print("PMD virtual address = 0x%lx" % (pmd_addr + pmd_offset))
			phys_pte_addr = read_qword(pmd_addr + pmd_offset)
			if(leaf(phys_pte_addr)):
				phys_pte_addr = set_offset(phys_pte_addr)
				show_addr(phys_pte_addr,addroffsetpmd,1)
				return
			phys_pte_addr = set_offset(phys_pte_addr)
			print("PTE physical address = 0x%lx" % phys_pte_addr)
			pte_addr = phys_to_virt(phys_pte_addr)
			pte_offset = get_pte_offset(addr)
			print("PTE offset = 0x%lx" % pte_offset)
			print("PTE virtual address = 0x%lx" % (pte_addr + pte_offset))
			phys_page_addr = read_qword(pte_addr + pte_offset)
			phys_page_addr = set_offset(phys_page_addr)
			show_addr(phys_page_addr,addroffset,0)
			return
		else:
			raise print("No task of PID " + str(pid))
LxTaskMMU()

