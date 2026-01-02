#!/bin/bash
# Add manual KernelSU hooks for non-GKI kernels
# This is required because kprobe doesn't work reliably on kernel 4.19

set -e

echo "Adding manual hooks for non-GKI kernel..."

# Hook 1: fs/exec.c - execveat hook for detecting su calls
echo "Patching fs/exec.c..."

# Add extern declarations after includes
cat > /tmp/exec_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern bool ksu_execveat_hook __read_mostly;
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
#endif
HOOKEOF
sed -i '/#include <linux\/fs_struct.h>/r /tmp/exec_hook.txt' fs/exec.c

# Add hook call in do_execveat_common function only (not other places using getname_flags)
# Use awk to be more precise
awk '
/^static int do_execveat_common\(/ { in_func = 1 }
in_func && /filename = getname_flags\(/ && !hook_added {
    print
    print "#ifdef CONFIG_KSU"
    print "\tif (unlikely(ksu_execveat_hook))"
    print "\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);"
    print "\telse"
    print "\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);"
    print "\tksu_handle_execveat_ksud(&fd, &filename, &argv, &envp, &flags);"
    print "#endif"
    hook_added = 1
    next
}
in_func && /^}$/ { in_func = 0 }
{ print }
' fs/exec.c > fs/exec.c.tmp && mv fs/exec.c.tmp fs/exec.c

# Hook 2: fs/open.c - faccessat hook
echo "Patching fs/open.c..."

cat > /tmp/open_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);
#endif
HOOKEOF
sed -i '/#include <linux\/rcupdate.h>/r /tmp/open_hook.txt' fs/open.c

# For do_faccessat - find the function and insert after the variable declarations
# Look for a statement line that starts the actual code
sed -i '/^static long do_faccessat/,/^}/{
  /res = user_path_at/i\
#ifdef CONFIG_KSU\
	ksu_handle_faccessat(\&dfd, \&filename, \&mode, NULL);\
#endif
}' fs/open.c

# Hook 3: fs/read_write.c - sys_read hook for init.rc injection (CRITICAL)
# This hook injects KernelSU service into init.rc during boot
echo "Patching fs/read_write.c..."

cat > /tmp/read_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern bool ksu_vfs_read_hook __read_mostly;
extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);
#endif
HOOKEOF

# Find a good include to add after
if grep -q "#include <linux/uio.h>" fs/read_write.c; then
    sed -i '/#include <linux\/uio.h>/r /tmp/read_hook.txt' fs/read_write.c
elif grep -q "#include <linux/pagemap.h>" fs/read_write.c; then
    sed -i '/#include <linux\/pagemap.h>/r /tmp/read_hook.txt' fs/read_write.c
fi

# Add hook call at the start of SYSCALL_DEFINE3(read, ...)
# The hook goes before the actual ksys_read call
sed -i '/^SYSCALL_DEFINE3(read,/,/^}/{
  /return ksys_read/i\
#ifdef CONFIG_KSU\
\tif (unlikely(ksu_vfs_read_hook))\
\t\tksu_handle_sys_read(fd, \&buf, \&count);\
#endif
}' fs/read_write.c

# Hook 4: fs/stat.c - stat hook
echo "Patching fs/stat.c..."

cat > /tmp/stat_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif
HOOKEOF
sed -i '/#include <linux\/compat.h>/r /tmp/stat_hook.txt' fs/stat.c

# For vfs_statx - find the retry: label or the first actual statement
sed -i '/^int vfs_statx/,/^}/{
  /getname_flags/i\
#ifdef CONFIG_KSU\
	ksu_handle_stat(\&dfd, \&filename, \&flags);\
#endif
}' fs/stat.c

# Hook 5: drivers/input/input.c - input event hook for volume key detection
echo "Patching drivers/input/input.c..."

cat > /tmp/input_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int type, unsigned int code, int value);
#endif
HOOKEOF

if grep -q "#include <linux/input/mt.h>" drivers/input/input.c; then
    sed -i '/#include <linux\/input\/mt.h>/r /tmp/input_hook.txt' drivers/input/input.c
elif grep -q "#include \"input-compat.h\"" drivers/input/input.c; then
    sed -i '/#include "input-compat.h"/r /tmp/input_hook.txt' drivers/input/input.c
fi

# Add hook in input_handle_event function
sed -i '/^static void input_handle_event/,/^}/{
  /add_input_randomness/i\
#ifdef CONFIG_KSU\
\tif (unlikely(ksu_input_hook))\
\t\tksu_handle_input_handle_event(type, code, value);\
#endif
}' drivers/input/input.c

# Hook 6: kernel/reboot.c - CRITICAL for SUSFS supercalls
# This hook allows KernelSU/SUSFS to receive commands via sys_reboot syscall
echo "Patching kernel/reboot.c (CRITICAL for SUSFS)..."

cat > /tmp/reboot_hook.txt << 'HOOKEOF'

#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
HOOKEOF
sed -i '/#include <linux\/uaccess.h>/r /tmp/reboot_hook.txt' kernel/reboot.c

# Insert the hook call at the beginning of SYSCALL_DEFINE4(reboot, ...)
# Find the function and add hook after ALL variable declarations (int ret = 0;)
sed -i '/^SYSCALL_DEFINE4(reboot,/,/^}/{
  /int ret = 0;/a\
\
#ifdef CONFIG_KSU\
	ksu_handle_sys_reboot(magic1, magic2, cmd, \&arg);\
#endif
}' kernel/reboot.c

echo "Manual hooks added successfully!"
