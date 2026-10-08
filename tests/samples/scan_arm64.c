// Built by tests/conftest.py for aarch64-linux-gnu: -O1 -nostdlib -static.
// The tests refer to everything here by symbol name, never by address.
#define NOINLINE __attribute__((noinline))

typedef int (*fn_t)(int);

int g_counter = 1;
int g_unused = 7;
int g_bss[64];
const char g_msg[] = "hello idaslicer";

NOINLINE int leaf(int a) { return a + g_counter; }
NOINLINE int callee_a(int a) { return leaf(a) * 3; }

// Reached only through g_table, never called directly.
NOINLINE int via_ptr(int a) { return a - 1; }
NOINLINE int via_ptr2(int a) { return a ^ 0x55; }
fn_t g_table[] = {via_ptr, via_ptr2};
NOINLINE int dispatch(int i, int a) { return g_table[i & 1](a); }

struct node {
    struct node *next;
    int v;
};
struct node g_n2 = {0, 2};
struct node g_n1 = {&g_n2, 1};
NOINLINE int walk(void) {
    int s = 0;
    for (struct node *n = &g_n1; n; n = n->next) s += n->v;
    return s;
}

NOINLINE int tail_target(int a) { return a * 7 + 1; }
NOINLINE int tailer(int a) { return tail_target(a + 1); }

// The tail jump sits mid-function, not on the last instruction.
NOINLINE int tail_target2(int a) { return a * 5 - 2; }
NOINLINE int cond_tail(int a) {
    if (a > 5) return tail_target2(a);
    return a * 3;
}

// leaf's second caller: callee_a is reached first.
NOINLINE int fill_bss(int a) {
    g_bss[a & 63] = a;
    return g_bss[(a + 1) & 63] + leaf(a);
}

NOINLINE int uncalled(int a) { return a + 100; }

NOINLINE int root(int a) { return callee_a(a) + dispatch(a, a) + walk() + tailer(a) + cond_tail(a) + fill_bss(a) + g_msg[a & 7]; }

void _start(void) {
    root(3);
    for (;;) {
    }
}

// lld turns split_leaf's leading adrp+add into `nop; adr`. Unreachable from
// _start and placed after its endless loop, that nop looks like padding:
// without symbols IDA makes it a function of its own that falls through into
// the rest. (No `byte_` names: IDA renames those, they look like its own.)
char g_split[256];
NOINLINE int split_leaf(int a) {
    g_split[a & 0xff] = 1;
    return g_split[(a + 1) & 0xff];
}
int split_entry(int a) { return split_leaf(a) + root(a); }
