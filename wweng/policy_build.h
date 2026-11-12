/* policy_build.h -- build a WWFLT_POLICY (driver policy table) from a
 * loaded .xcf file. Phase 1: Encrypt + File rules only; per-process
 * dir/wild/include path rules are not yet in the .xcf parse (the driver's
 * path_rules are left empty = match all paths).
 *
 * Merge semantics (matches the vendor engine): the Kernel section is the
 * main policy; the active group (from the User section) overlays it --
 * a program listed in the group uses the group's Encrypt/File values,
 * everything else uses the Kernel values.
 */
#pragma once
#include <windows.h>
#include "wwflt.h"
#include "xcf.h"

/* Build a policy from a loaded .xcf. Allocates *out_policy (caller frees
 * with free()). Returns 0 on success, <0 on failure (err gets a message).
 * On success, *out_policy is a heap WWFLT_POLICY, *out_count is the
 * number of process rules filled, and *out_group is the active group
 * name (GBK, for logging).
 * group_override (GBK, may be NULL/empty): which group to overlay on the
 * Kernel main policy. NULL/empty = first entry of the User section
 * (vendor behaviour). "Kernel" or "main" = no overlay, main policy only.
 * Any other name = overlay that named section (e.g. "office不加密" is
 * section "3"). Needed because one .xcf carries several groups and the
 * test machine must be able to pick the main policy (notepad=Write) even
 * when the User section points at the don't-encrypt group. */
int policy_build_from_xcf(const xcf_t *x, WWFLT_POLICY **out_policy,
                          ULONG *out_count, char *out_group, size_t out_group_cap,
                          const char *group_override,
                          char *err, size_t err_cap);

/* Reserved for later: fetch a policy from the server (wss/tcp/http).
 * Phase 1 always returns "not configured" and the caller falls back to
 * the local .xcf. This is the spot where the server fetch will plug in. */
int policy_fetch_from_server(const char *server_url, WWFLT_POLICY **out_policy,
                             char *err, size_t err_cap);
