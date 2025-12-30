#!/bin/bash
# Script to add SUSFS functions to KernelSU selinux.c
# This is needed when the SUSFS patch doesn't apply cleanly

SELINUX_C="$1"

if [ ! -f "$SELINUX_C" ]; then
    echo "ERROR: selinux.c not found at $SELINUX_C"
    exit 1
fi

echo "Checking SUSFS state in selinux.c..."

# Check if SUSFS variables already exist (partial patch may have added them)
VARS_EXIST=false
if grep -q "susfs_ksu_sid" "$SELINUX_C"; then
    VARS_EXIST=true
    echo "SUSFS variables already present"
fi

# Check if SUSFS functions already exist
FUNCS_EXIST=false
if grep -q "susfs_is_current_ksu_domain" "$SELINUX_C"; then
    FUNCS_EXIST=true
    echo "SUSFS functions already present"
fi

# Check if EXPORT_SYMBOL already exists
EXPORTS_EXIST=false
if grep -q "EXPORT_SYMBOL(susfs_is_current_ksu_domain)" "$SELINUX_C"; then
    EXPORTS_EXIST=true
    echo "EXPORT_SYMBOL already present"
fi

# If everything exists, nothing to do
if [ "$VARS_EXIST" = true ] && [ "$FUNCS_EXIST" = true ] && [ "$EXPORTS_EXIST" = true ]; then
    echo "SUSFS fully configured in selinux.c - nothing to add"
    exit 0
fi

# Add variables if missing
if [ "$VARS_EXIST" = false ]; then
    echo "Adding SUSFS variable declarations..."
    sed -i '/#define KERNEL_SU_DOMAIN/a \
\
#ifdef CONFIG_KSU_SUSFS\
#define KERNEL_INIT_DOMAIN "u:r:init:s0"\
#define KERNEL_ZYGOTE_DOMAIN "u:r:zygote:s0"\
u32 susfs_ksu_sid = 0;\
u32 susfs_init_sid = 0;\
u32 susfs_zygote_sid = 0;\
#endif' "$SELINUX_C"
fi

# Add functions if missing
if [ "$FUNCS_EXIST" = false ]; then
    echo "Adding SUSFS functions..."
    cat >> "$SELINUX_C" << 'EOF'

#ifdef CONFIG_KSU_SUSFS
static inline void susfs_set_sid(const char *secctx_name, u32 *out_sid)
{
	int err;
	if (!secctx_name || !out_sid) {
		pr_err("secctx_name || out_sid is NULL\n");
		return;
	}
	err = security_secctx_to_secid(secctx_name, strlen(secctx_name), out_sid);
	if (err) {
		pr_err("failed setting sid for '%s', err: %d\n", secctx_name, err);
		return;
	}
	pr_info("sid '%u' is set for secctx_name '%s'\n", *out_sid, secctx_name);
}

bool susfs_is_sid_equal(void *sec, u32 sid2) {
	struct task_security_struct *tsec = (struct task_security_struct *)sec;
	if (!tsec) return false;
	return tsec->sid == sid2;
}

u32 susfs_get_sid_from_name(const char *secctx_name)
{
	u32 out_sid = 0;
	int err;
	if (!secctx_name) {
		pr_err("secctx_name is NULL\n");
		return 0;
	}
	err = security_secctx_to_secid(secctx_name, strlen(secctx_name), &out_sid);
	if (err) {
		pr_err("failed getting sid from secctx_name: %s, err: %d\n", secctx_name, err);
		return 0;
	}
	return out_sid;
}

u32 susfs_get_current_sid(void) { return current_sid(); }

void susfs_set_zygote_sid(void) { susfs_set_sid(KERNEL_ZYGOTE_DOMAIN, &susfs_zygote_sid); }
bool susfs_is_current_zygote_domain(void) { return unlikely(current_sid() == susfs_zygote_sid); }

void susfs_set_ksu_sid(void) { susfs_set_sid(KERNEL_SU_DOMAIN, &susfs_ksu_sid); }
bool susfs_is_current_ksu_domain(void) { return unlikely(current_sid() == susfs_ksu_sid); }

void susfs_set_init_sid(void) { susfs_set_sid(KERNEL_INIT_DOMAIN, &susfs_init_sid); }
bool susfs_is_current_init_domain(void) { return unlikely(current_sid() == susfs_init_sid); }

/* SUSFS symbol exports for fs/susfs.c */
EXPORT_SYMBOL(susfs_is_current_ksu_domain);
EXPORT_SYMBOL(susfs_is_current_zygote_domain);
EXPORT_SYMBOL(susfs_is_current_init_domain);
EXPORT_SYMBOL(susfs_is_sid_equal);
EXPORT_SYMBOL(susfs_set_ksu_sid);
EXPORT_SYMBOL(susfs_set_zygote_sid);
EXPORT_SYMBOL(susfs_set_init_sid);
EXPORT_SYMBOL(susfs_get_current_sid);
EXPORT_SYMBOL(susfs_get_sid_from_name);
#endif
EOF
    echo "Added SUSFS functions"
fi

# Add EXPORT_SYMBOL if functions exist but exports don't
if [ "$FUNCS_EXIST" = true ] && [ "$EXPORTS_EXIST" = false ]; then
    echo "Adding EXPORT_SYMBOL declarations to existing functions..."
    cat >> "$SELINUX_C" << 'EOF'

/* SUSFS symbol exports for fs/susfs.c */
#ifdef CONFIG_KSU_SUSFS
EXPORT_SYMBOL(susfs_is_current_ksu_domain);
EXPORT_SYMBOL(susfs_is_current_zygote_domain);
EXPORT_SYMBOL(susfs_is_current_init_domain);
EXPORT_SYMBOL(susfs_is_sid_equal);
EXPORT_SYMBOL(susfs_set_ksu_sid);
EXPORT_SYMBOL(susfs_set_zygote_sid);
EXPORT_SYMBOL(susfs_set_init_sid);
EXPORT_SYMBOL(susfs_get_current_sid);
EXPORT_SYMBOL(susfs_get_sid_from_name);
#endif
EOF
    echo "Added EXPORT_SYMBOL declarations"
fi

echo "=== selinux.c tail ==="
tail -25 "$SELINUX_C"
