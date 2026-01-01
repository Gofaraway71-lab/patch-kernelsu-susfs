#!/bin/bash
# Add Frida detection bypass patches
# This hides Frida-related processes and memory mappings

set -e

echo "Adding Frida detection bypass patches..."

# Patch 1: fs/proc/task_mmu.c - Filter memory mappings
echo "Patching fs/proc/task_mmu.c for maps filtering..."

# Add bypass function after includes
cat > /tmp/frida_bypass.txt << 'HOOKEOF'

/* Frida detection bypass - filter suspicious memory mappings */
static int bypass_show_map_vma(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	if (file) {
		const char *name = file->f_path.dentry->d_name.name;
		/* Filter frida-agent and related files */
		if (strstr(name, "frida") ||
		    strstr(name, "gadget") ||
		    strstr(name, "linjector")) {
			return 1;  /* Skip this mapping */
		}
	}
	/* Filter anonymous mappings in suspicious locations */
	if (vma->vm_file == NULL) {
		/* Check for JIT cache regions that Frida creates */
		if (vma->anon_name) {
			if (strstr(vma->anon_name, "jit-cache") ||
			    strstr(vma->anon_name, "frida")) {
				return 1;
			}
		}
	}
	return 0;
}
HOOKEOF

# Insert after includes in task_mmu.c
if grep -q '#include <linux/hugetlb.h>' fs/proc/task_mmu.c; then
  sed -i '/#include <linux\/hugetlb.h>/r /tmp/frida_bypass.txt' fs/proc/task_mmu.c
elif grep -q '#include <linux/shmem_fs.h>' fs/proc/task_mmu.c; then
  sed -i '/#include <linux\/shmem_fs.h>/r /tmp/frida_bypass.txt' fs/proc/task_mmu.c
fi

# Add check at the beginning of show_map_vma
# Find show_map_vma function and add bypass check
sed -i '/^static void show_map_vma/,/^{/{
  /^{/a\
	/* Frida bypass */\
	if (bypass_show_map_vma(vma))\
		return;
}' fs/proc/task_mmu.c 2>/dev/null || echo "show_map_vma patch skipped"

# Patch 2: fs/proc/base.c - Filter task names (optional, more aggressive)
echo "Patching fs/proc/base.c for task filtering..."

cat > /tmp/task_filter.txt << 'HOOKEOF'

/* Filter Frida-related process names */
static inline int is_frida_task(struct task_struct *task)
{
	char tcomm[TASK_COMM_LEN];
	get_task_comm(tcomm, task);
	if (strstr(tcomm, "frida") ||
	    strstr(tcomm, "gmain") ||
	    strstr(tcomm, "gum-js") ||
	    strstr(tcomm, "linjector") ||
	    strstr(tcomm, "gdbus")) {
		return 1;
	}
	return 0;
}
HOOKEOF

# Only apply this if CONFIG_KSU is defined (optional patch)
if grep -q '#include <linux/pid_namespace.h>' fs/proc/base.c; then
  sed -i '/#include <linux\/pid_namespace.h>/a\
#ifdef CONFIG_KSU\
/* Filter Frida-related process names */\
static inline int is_frida_task(struct task_struct *task)\
{\
	char tcomm[TASK_COMM_LEN];\
	get_task_comm(tcomm, task);\
	if (strstr(tcomm, "frida") ||\
	    strstr(tcomm, "gmain") ||\
	    strstr(tcomm, "gum-js") ||\
	    strstr(tcomm, "linjector") ||\
	    strstr(tcomm, "gdbus")) {\
		return 1;\
	}\
	return 0;\
}\
#endif
' fs/proc/base.c 2>/dev/null || echo "base.c patch skipped"
fi

echo "Frida bypass patches added (some may be skipped if code structure differs)"
