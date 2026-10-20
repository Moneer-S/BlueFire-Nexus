#include <fcntl.h>
#include <errno.h>
#include <mach/mach_time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>

_Static_assert(sizeof(struct proc_bsdinfo) == 136, "proc_bsdinfo size changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_flags) == 0, "proc_bsdinfo flags offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_status) == 4, "proc_bsdinfo status offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_xstatus) == 8, "proc_bsdinfo exit status offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_pid) == 12, "proc_bsdinfo pid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_ppid) == 16, "proc_bsdinfo parent offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_uid) == 20, "proc_bsdinfo uid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_gid) == 24, "proc_bsdinfo gid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_ruid) == 28, "proc_bsdinfo real uid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_rgid) == 32, "proc_bsdinfo real gid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_svuid) == 36, "proc_bsdinfo saved uid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_svgid) == 40, "proc_bsdinfo saved gid offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, rfu_1) == 44, "proc_bsdinfo reserved offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_comm) == 48, "proc_bsdinfo command offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_name) == 64, "proc_bsdinfo name offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_nfiles) == 96, "proc_bsdinfo files offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_pgid) == 100, "proc_bsdinfo group offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_pjobc) == 104, "proc_bsdinfo job offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, e_tdev) == 108, "proc_bsdinfo terminal offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, e_tpgid) == 112, "proc_bsdinfo terminal group offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_nice) == 116, "proc_bsdinfo nice offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_start_tvsec) == 120,
               "proc_bsdinfo start seconds offset changed");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_start_tvusec) == 128,
               "proc_bsdinfo start microseconds offset changed");
_Static_assert(sizeof(struct proc_bsdshortinfo) == 64, "proc_bsdshortinfo size changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_pid) == 0, "short BSD pid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_ppid) == 4, "short BSD parent offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_pgid) == 8, "short BSD group offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_status) == 12, "short BSD status offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_comm) == 16, "short BSD command offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_flags) == 32, "short BSD flags offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_uid) == 36, "short BSD uid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_gid) == 40, "short BSD gid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_ruid) == 44, "short BSD real uid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_rgid) == 48, "short BSD real gid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_svuid) == 52, "short BSD saved uid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_svgid) == 56, "short BSD saved gid offset changed");
_Static_assert(offsetof(struct proc_bsdshortinfo, pbsi_rfu) == 60, "short BSD reserved offset changed");
_Static_assert(PROC_PIDTBSDINFO == 3, "full BSD query flavor changed");
_Static_assert(PROC_PIDT_SHORTBSDINFO == 13, "short BSD query flavor changed");
_Static_assert(PROC_FLAG_SYSTEM == 1, "system process flag changed");
_Static_assert(PROC_FLAG_TRACED == 2, "traced process flag changed");
_Static_assert(PROC_FLAG_INEXIT == 4, "exiting process flag changed");
_Static_assert(PROC_FLAG_LP64 == 0x10, "64-bit process flag changed");
_Static_assert(sizeof(struct proc_fdinfo) == 8, "proc_fdinfo size changed");
_Static_assert(offsetof(struct proc_fdinfo, proc_fdtype) == 4,
               "proc_fdinfo type offset changed");
_Static_assert(sizeof(mach_timebase_info_data_t) == 8,
               "mach_timebase_info_data_t size changed");
_Static_assert(offsetof(mach_timebase_info_data_t, denom) == 4,
               "mach_timebase_info_data_t denominator offset changed");
_Static_assert(sizeof(struct statfs) == 2168, "statfs size changed");
_Static_assert(offsetof(struct statfs, f_flags) == 64, "statfs flags offset changed");
_Static_assert(offsetof(struct statfs, f_fstypename) == 72,
               "statfs filesystem name offset changed");
_Static_assert(O_NOFOLLOW == 0x100, "O_NOFOLLOW changed");
_Static_assert(O_CLOEXEC == 0x01000000, "O_CLOEXEC changed");
_Static_assert(O_DIRECTORY == 0x00100000, "O_DIRECTORY changed");
_Static_assert(O_ACCMODE == 0x3, "O_ACCMODE changed");
_Static_assert(O_RDONLY == 0, "O_RDONLY changed");
_Static_assert(F_GETFL == 3, "F_GETFL changed");
_Static_assert(F_SETFD == 2, "F_SETFD changed");
_Static_assert(FD_CLOEXEC == 1, "FD_CLOEXEC changed");
_Static_assert(MNT_LOCAL == 0x1000, "MNT_LOCAL changed");
_Static_assert(MNT_IGNORE_OWNERSHIP == 0x00200000,
               "MNT_IGNORE_OWNERSHIP changed");
_Static_assert(ACL_TYPE_EXTENDED == 0x100, "ACL_TYPE_EXTENDED changed");
_Static_assert(AF_UNIX == 1, "AF_UNIX changed");
_Static_assert(SOL_SOCKET == 0xffff, "SOL_SOCKET changed");
_Static_assert(SO_TYPE == 0x1008, "SO_TYPE changed");
_Static_assert(SOCK_STREAM == 1, "SOCK_STREAM changed");
_Static_assert(S_IFMT == 0xf000, "S_IFMT changed");
_Static_assert(S_IFIFO == 0x1000, "S_IFIFO changed");
_Static_assert(S_IFCHR == 0x2000, "S_IFCHR changed");
_Static_assert(S_IFSOCK == 0xc000, "S_IFSOCK changed");
_Static_assert(ENOENT == 2, "ENOENT changed");
_Static_assert(EPERM == 1, "EPERM changed");
_Static_assert(EACCES == 13, "EACCES changed");
_Static_assert(EINVAL == 22, "EINVAL changed");
_Static_assert(sizeof(void *) == 8, "arm64 pointer size changed");

int main(void) {
    printf(
        "{\"schema_version\":\"bluefire.macos-file-access-sdk-abi.v1\","
        "\"proc_bsdinfo_size\":%zu,\"proc_bsdinfo_start_seconds_offset\":%zu,"
        "\"proc_bsdinfo_start_microseconds_offset\":%zu,"
        "\"proc_bsdshortinfo_size\":%zu,\"proc_bsdshortinfo_uid_offset\":%zu,"
        "\"proc_bsdshortinfo_saved_gid_offset\":%zu,"
        "\"proc_fdinfo_size\":%zu,\"proc_fdinfo_type_offset\":%zu,"
        "\"mach_timebase_size\":%zu,\"mach_timebase_denom_offset\":%zu,"
        "\"statfs_size\":%zu,\"statfs_flags_offset\":%zu,"
        "\"statfs_fstypename_offset\":%zu,\"pointer_size\":%zu,"
        "\"O_NOFOLLOW\":%lld,\"O_CLOEXEC\":%lld,\"O_DIRECTORY\":%lld,"
        "\"MNT_LOCAL\":%lld,\"MNT_IGNORE_OWNERSHIP\":%lld}\n",
        sizeof(struct proc_bsdinfo),
        offsetof(struct proc_bsdinfo, pbi_start_tvsec),
        offsetof(struct proc_bsdinfo, pbi_start_tvusec),
        sizeof(struct proc_bsdshortinfo),
        offsetof(struct proc_bsdshortinfo, pbsi_uid),
        offsetof(struct proc_bsdshortinfo, pbsi_svgid),
        sizeof(struct proc_fdinfo),
        offsetof(struct proc_fdinfo, proc_fdtype),
        sizeof(mach_timebase_info_data_t),
        offsetof(mach_timebase_info_data_t, denom),
        sizeof(struct statfs),
        offsetof(struct statfs, f_flags),
        offsetof(struct statfs, f_fstypename),
        sizeof(void *),
        (long long)O_NOFOLLOW,
        (long long)O_CLOEXEC,
        (long long)O_DIRECTORY,
        (long long)MNT_LOCAL,
        (long long)MNT_IGNORE_OWNERSHIP);
    return 0;
}
