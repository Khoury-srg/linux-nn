#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

static struct btf *bpf_fs_ra_btf;
static s32 bpf_fs_ra_ops_id, bpf_fs_ra_state_id;

// stubs

static int fs_readahead_get_max_ra_stub(struct bpf_fs_ra_state *state)
{
	return 0;
}

static int fs_readahead_get_ra_stub(struct bpf_fs_ra_state *state)
{
	return 0;
}

struct bpf_fs_ra_ops __bpf_fs_ra_stubs = {
	.get_max_ra = fs_readahead_get_max_ra_stub,
	.get_ra = fs_readahead_get_ra_stub,
};

// verifier

static const struct bpf_func_proto *
bpf_fs_readahead_get_func_proto(enum bpf_func_id func_id,
				const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool fs_readahead_ops_is_valid_access(int off, int size,
					     enum bpf_access_type type,
					     const struct bpf_prog *prog,
					     struct bpf_insn_access_aux *info)
{
	if (info->btf_id == bpf_fs_ra_state_id)
		return true;

	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	return true;
}

static int fs_readahead_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	return 0;
}

struct bpf_verifier_ops bpf_fs_ra_verifier_ops = {
	.get_func_proto = bpf_fs_readahead_get_func_proto,
	.is_valid_access = fs_readahead_ops_is_valid_access,
	.btf_struct_access = fs_readahead_btf_struct_access,
};

// management

static int bpf_fs_ra_reg(void *kdata)
{
	return bpf_mm_fs_ra_set(kdata);
}

static void bpf_fs_ra_unreg(void *kdata)
{
	bpf_mm_fs_ra_unset(kdata);
}

static int bpf_fs_ra_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_fs_ra_init_member(const struct btf_type *t,
				 const struct btf_member *member, void *kdata,
				 const void *udata)
{
	// no-op for now
	return 0;
}

static int bpf_fs_ra_init(struct btf *btf)
{
	bpf_fs_ra_ops_id = btf_find_by_name_kind(btf, "bpf_fs_ra_ops",
						 BTF_KIND_STRUCT);
	bpf_fs_ra_state_id = btf_find_by_name_kind(
		btf, "bpf_fs_ra_state", BTF_KIND_STRUCT);

	bpf_fs_ra_btf = btf;

	if (bpf_fs_ra_ops_id < 0 || bpf_fs_ra_state_id < 0)
		return -EINVAL;

	return 0;
}

static struct bpf_struct_ops bpf_bpf_fs_ra_ops = {
	.verifier_ops = &bpf_fs_ra_verifier_ops,
	.reg = bpf_fs_ra_reg,
	.unreg = bpf_fs_ra_unreg,
	.update = NULL, // cannot be updated
	.check_member = bpf_fs_ra_check_member,
	.init_member = bpf_fs_ra_init_member,
	.init = bpf_fs_ra_init,

	.name = "bpf_fs_ra_ops",
	.cfi_stubs = &__bpf_fs_ra_stubs,
	.owner = THIS_MODULE,
};

static int __init bpf_fs_ra_kfunc_init(void)
{
	return register_bpf_struct_ops(&bpf_bpf_fs_ra_ops,
				       bpf_fs_ra_ops);
}
late_initcall(bpf_fs_ra_kfunc_init);
