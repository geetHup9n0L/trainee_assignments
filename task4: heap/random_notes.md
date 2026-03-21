# pwn3_uaf Vulnerability Assessment

## 1. High-Level Exploitation Flow
Based on the provided source code, there is a prominent Use-After-Free (UAF) and Double Free vulnerability, specifically caused by a logic flaw in how self-transactions are processed when an account is deleted. The heap manipulation relies on chunks that fit identically into the `0x30` fastbin and `0x20` fastbin (libc 2.23).

### A. The Logic Flaw (Self-Transaction)
When a user sends a coin (`send_coin`), there is no check preventing the `active_user` from sending coins to themselves (`receiver_user == active_user`). If this occurs, two identical transaction chunks (`tx_node1` and `tx_node2`) are allocated and both are appended to the user's own `transaction` linked list. 

### B. Use-After-Free & Double Free
When `delete_user` is called on an account that has performed a self-transaction, the deletion loop iterates through the user's `tx_node` list. It calls `free_transactions(transaction->user, transaction->id)`. Because `transaction->user` points to the user themselves, this function searches the user's own list and frees the transaction chunk. However, the `delete_user` loop immediately after accesses `transaction->*next` (which is now reading the fastbin `fd` pointer - a **UAF Read**), clears the pointers (a **UAF Write** corrupting the fastbin), and then calls `free(transaction);` on the exact same chunk, causing a **Fastbin Double Free**.

### C. Fastbin Dup to Arbitrary Write
With a pristine Double Free on the `0x30` fastbin (`tx_node` size), we can perform a Fastbin Dup attack. By manipulating the overlapping chunks, we can trick `malloc` into returning a pointer that overlaps an existing `user` struct (which resides in the `0x20` fastbin). Controlling the `user` struct allows us to overwrite `user->name` to leak libc via `display_info`, and overwrite `user->password` to gain an **Arbitrary Write** via `change_pass()`, ultimately overwriting `__malloc_hook` with a `one_gadget`.

---

## 2. Function-by-Function Vulnerability Breakdown

### `send_coin()`
**Vulnerable Logic:**
There is no validation to ensure `active_user` != `receiver_user`.
```c
is_match = strcmp(*(&users)[idx],input);
if (is_match == 0) {
  receiver_user = (user *)(&users)[idx]; // Can be the active_user
```
**Evaluation:** 
This function builds the premise for the Double Free. It allocates `0x28` bytes for the `tx_node` (yielding a `0x30` fastbin chunk). By entering our own username, both the sender's and receiver's `tx_node` records are appended to our own `user->transaction` list.

### `delete_user()`
**Vulnerable Snippet:**
```c
transaction = active_user->transaction;
while( true ) {
  free_transactions(transaction->user, transaction->id & 0xffffffff);
  if (transaction->*next == (tx_node *)0x0) break; // UAF READ
  ptr = transaction->*next;
  transaction->user = (char **)0x0;                // UAF WRITE
  transaction->*next = (tx_node *)0x0;             // UAF WRITE (Fastbin Corruption)
  free(transaction);                               // DOUBLE FREE
  transaction = ptr;
}
```
**Evaluation:** 
This completes the vulnerability. `free_transactions` correctly unlinks and frees the reciprocal transaction. But when `transaction->user` is ourselves, it frees the *current* `transaction` chunk. The immediate subsequent uses of `transaction->*next` read and write to freed memory, followed by explicitly `free`ing it again, gifting us a trivial Double Free.

### `display_info()` / `display_transaction()`
**Evaluation:** 
Once the heap is manipulated (via the Double Free) to overlap a `tx_node` string or generic chunk over a `user` struct, we can overwrite `active_user->name`. Calling `display_info(active_user)` will dereference this forged pointer, giving us an **Arbitrary Read** to leak the `libc` base address.

### `change_pass()`
**Vulnerable Snippet:**
```c
void change_pass(users *active_user) {
  // ...
  printf("Please input password\n> ");
  // active_user->password is a pointer to a predictable 0x20 chunk
  read(active_user->password, 31); 
```
**Evaluation:** 
This holds the **Arbitrary Write** primitive. Once our overlapping chunk strategy lets us control the `active_user->password` pointer, `change_pass()` allows us to read 31 bytes of arbitrary data into that exact memory location. We can point it directly at `__malloc_hook` to achieve arbitrary code execution via a one_gadget.
