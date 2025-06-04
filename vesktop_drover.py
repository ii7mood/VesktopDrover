#!/usr/bin/env python3
"""
discord_direct_ipv6.py

“Direct mode” for Vesktop on Linux—no proxy. We compile an LD_PRELOAD
library that intercepts UDP sendto() calls and, when sending SRTP (ports
50000–65535) to Discord’s Voice servers (Cloudflare anycast), flips one
“extension‐bit” in the RTP header—but only every third packet. We also
log (but do not flip) any DTLS packets on UDP 443.

Usage:
  sudo ./discord_direct_ipv6.py --setup
      • Builds droverdirect.c → libdroverdirect.so in the same folder,
        including IPv4+IPv6 support.

  ./discord_direct_ipv6.py --launch /path/to/vesktop
      • Requires that you’ve already run “--setup” (so libdroverdirect.so
        exists). Sets LD_PRELOAD and execs Vesktop.

  sudo ./discord_direct_ipv6.py --cleanup
      • Deletes droverdirect.c and libdroverdirect.so.

Notes:
  • After “--launch”, join a voice channel. DTLS on UDP 443 (IPv4/IPv6)
    will be logged but left unmodified. Only SRTP (50000–65535) is XOR’d
    on its RTP extension bit (0x08), and only every third packet.
  • We match all Cloudflare‐VoIP prefixes (not just 162.159.0.0/16
    or 2606:4700::/32), so new voice nodes will be caught without a rebuild.
"""

import argparse, os, sys, subprocess, textwrap

BASE_DIR    = os.path.abspath(os.path.dirname(__file__))
C_FILENAME  = os.path.join(BASE_DIR, "droverdirect.c")
SO_FILENAME = os.path.join(BASE_DIR, "libdroverdirect.so")

# ------------------------------------------------------------------------------------
# Updated C code:                                                          droverdirect.c
# • Matches all Cloudflare VoIP IPs (IPv4+IPv6) as of mid-2025.
# • Logs any DTLS (UDP 443) candidate but does NOT flip it (breaking DTLS handshake
#   would fail voice, so we only log here).
# • For SRTP on 50000–65535, flips only the RTP “extension” bit (0x08) instead of
#   xor-with 0x01, and only every 3rd matching packet.
# • All other traffic is forwarded unmodified.
C_CODE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>   // for fprintf, stderr

// Typedef for the real sendto() function
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static sendto_t real_sendto = NULL;

// SRTP flip counter: we only mutate every 3rd packet
static uint64_t srtp_counter = 0;

// Lazy-load the genuine sendto()
static void bind_real_sendto() {
    if (!real_sendto) {
        real_sendto = (sendto_t)dlsym(RTLD_NEXT, "sendto");
        // If dlsym fails, real_sendto remains NULL → crash, meaning LD_PRELOAD failed.
    }
}

// Check if IPv4 address is in any Cloudflare VoIP block (June 2025 list)
static int is_disc_ipv4(uint32_t dip) {
    // dip is in host-byte-order after ntohl

    // 103.21.244.0/22  → 0x6715F400 & 0xFFFFFC00
    if ((dip & 0xFFFFFC00U) == 0x6715F400U) return 1;
    // 103.22.200.0/22  → 0x6716C800 & 0xFFFFFC00
    if ((dip & 0xFFFFFC00U) == 0x6716C800U) return 1;
    // 103.31.4.0/22    → 0x671F0400 & 0xFFFFFC00
    if ((dip & 0xFFFFFC00U) == 0x671F0400U) return 1;
    // 104.16.0.0/13    → 0x68100000 & 0xFFF80000
    if ((dip & 0xFFF80000U) == 0x68100000U) return 1;
    // 104.24.0.0/14    → 0x68180000 & 0xFFFC0000
    if ((dip & 0xFFFC0000U) == 0x68180000U) return 1;
    // 108.162.192.0/18 → 0x6CA2C000 & 0xFFFFC000
    if ((dip & 0xFFFFC000U) == 0x6CA2C000U) return 1;
    // 131.0.72.0/22    → 0x83004800 & 0xFFFFFC00
    if ((dip & 0xFFFFFC00U) == 0x83004800U) return 1;
    // 141.101.64.0/18  → 0x8D654000 & 0xFFFFC000
    if ((dip & 0xFFFFC000U) == 0x8D654000U) return 1;
    // 162.158.0.0/15   → 0xA29E0000 & 0xFFFE0000
    if ((dip & 0xFFFE0000U) == 0xA29E0000U) return 1;
    // 172.64.0.0/13    → 0xAC400000 & 0xFFF80000
    if ((dip & 0xFFF80000U) == 0xAC400000U) return 1;
    // 173.245.48.0/20  → 0xADF53000 & 0xFFFFF000
    if ((dip & 0xFFFFF000U) == 0xADF53000U) return 1;
    // 188.114.96.0/20  → 0xBC726000 & 0xFFFFF000
    if ((dip & 0xFFFFF000U) == 0xBC726000U) return 1;
    // 190.93.240.0/20  → 0xBE5DF000 & 0xFFFFF000
    if ((dip & 0xFFFFF000U) == 0xBE5DF000U) return 1;
    // 197.234.240.0/22 → 0xC5EAF000 & 0xFFFFFC00
    if ((dip & 0xFFFFFC00U) == 0xC5EAF000U) return 1;
    // 198.41.128.0/17  → 0xC6298000 & 0xFFFF8000
    if ((dip & 0xFFFF8000U) == 0xC6298000U) return 1;

    return 0;
}

// Check if IPv6 address is in any Cloudflare VoIP block (June 2025 list)
static int is_disc_ipv6(const struct in6_addr *addr6) {
    // Extract the top 32 bits
    uint32_t high = ntohl(addr6->s6_addr32[0]);

    // 2400:cb00::/32  → high == 0x2400CB00
    if (high == 0x2400CB00U) return 1;
    // 2606:4700::/32  → high == 0x26064700
    if (high == 0x26064700U) return 1;
    // 2803:f800::/32  → high == 0x2803F800
    if (high == 0x2803F800U) return 1;
    // 2405:b500::/32  → high == 0x2405B500
    if (high == 0x2405B500U) return 1;
    // 2405:8100::/32  → high == 0x24058100
    if (high == 0x24058100U) return 1;
    // 2a06:98c0::/29  → (high & 0xFFFFFFF8) == 0x2A0698C0
    if ((high & 0xFFFFFFF8U) == 0x2A0698C0U) return 1;
    // 2c0f:f248::/32  → high == 0x2C0FF248
    if (high == 0x2C0FF248U) return 1;

    return 0;
}

// Hooked sendto()
ssize_t sendto(int sockfd,
               const void *buf,
               size_t len,
               int flags,
               const struct sockaddr *dest_addr,
               socklen_t addrlen) {
    bind_real_sendto();
    if (!dest_addr || len < 1) {
        // No dest or empty payload → just forward unmodified
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    // IPv4 case
    if (dest_addr->sa_family == AF_INET) {
        struct sockaddr_in *dst = (struct sockaddr_in*)dest_addr;
        uint16_t dport = ntohs(dst->sin_port);
        uint32_t dip  = ntohl(dst->sin_addr.s_addr);

        // 1) DTLS handshake on UDP 443  → log but do NOT flip!
        if (dport == 443 && is_disc_ipv4(dip)) {
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dst->sin_addr, ipstr, sizeof(ipstr));
            fprintf(stderr, "[drover] DTLS packet ➔ %s:443 (unmodified)\n", ipstr);
            return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        // 2) SRTP on 50000–65535  → flip every 3rd packet, toggling only the RTP extension bit (0x08)
        if (dport >= 50000 && dport <= 65535 && is_disc_ipv4(dip)) {
            srtp_counter++;
            if ((srtp_counter % 3) == 0) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dst->sin_addr, ipstr, sizeof(ipstr));
                fprintf(stderr, "[drover] flipping SRTP (pkt #%llu) ➔ %s:%u\n",
                        (unsigned long long)srtp_counter, ipstr, dport);

                unsigned char *temp = malloc(len);
                if (!temp) {
                    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
                }
                memcpy(temp, buf, len);
                // Toggle only the RTP extension bit instead of XOR 0x01
                temp[0] ^= 0x08;
                ssize_t ret = real_sendto(sockfd, temp, len, flags, dest_addr, addrlen);
                free(temp);
                return ret;
            }
            // If not our 3rd-packet, send unmodified
            return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        // Otherwise, send unmodified
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    // IPv6 case
    else if (dest_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *dst6 = (struct sockaddr_in6*)dest_addr;
        uint16_t dport = ntohs(dst6->sin6_port);

        // 1) DTLS on UDP 443 → log but do NOT flip
        if (dport == 443 && is_disc_ipv6(&dst6->sin6_addr)) {
            char ipstr6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dst6->sin6_addr, ipstr6, sizeof(ipstr6));
            fprintf(stderr, "[drover] DTLS packet ➔ [%s]:443 (unmodified)\n", ipstr6);
            return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        // 2) SRTP on 50000–65535 → flip every 3rd pkt, toggling RTP extension bit
        if (dport >= 50000 && dport <= 65535 && is_disc_ipv6(&dst6->sin6_addr)) {
            srtp_counter++;
            if ((srtp_counter % 3) == 0) {
                char ipstr6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &dst6->sin6_addr, ipstr6, sizeof(ipstr6));
                fprintf(stderr, "[drover] flipping SRTP (pkt #%llu) ➔ [%s]:%u\n",
                        (unsigned long long)srtp_counter, ipstr6, dport);

                unsigned char *temp = malloc(len);
                if (!temp) {
                    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
                }
                memcpy(temp, buf, len);
                // Toggle only the RTP extension bit (0x08)
                temp[0] ^= 0x08;
                ssize_t ret = real_sendto(sockfd, temp, len, flags, dest_addr, addrlen);
                free(temp);
                return ret;
            }
            // If not our 3rd-packet, send unmodified
            return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        // Otherwise, send unmodified
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    // All other families or ports → send unmodified
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
'''


def run(cmd, **kwargs):
    """Run a subprocess command (print it first)."""
    print("Running:", " ".join(cmd))
    return subprocess.run(cmd, check=kwargs.get("check", True),
                         capture_output=kwargs.get("capture_output", False),
                         text=kwargs.get("text", False))


def ensure_root():
    if os.geteuid() != 0:
        print("→ This script must be run as root for --setup and --cleanup.")
        sys.exit(1)


def build_direct_library():
    """
    Write droverdirect.c to disk and compile it into libdroverdirect.so.
    """
    print("Writing C source to:", C_FILENAME)
    with open(C_FILENAME, "w") as f:
        f.write(C_CODE.lstrip())

    gcc_cmd = [
        "gcc",
        "-O2",
        "-fPIC",
        "-shared",
        "-o", SO_FILENAME,
        C_FILENAME,
        "-ldl"
    ]
    run(gcc_cmd)
    if os.path.isfile(SO_FILENAME):
        print(f"\n✅ Built direct‐mode library: {SO_FILENAME}")
    else:
        print("❌ Failed to build libdroverdirect.so")
        sys.exit(1)


def cleanup_direct_library():
    """
    Remove droverdirect.c and libdroverdirect.so if they exist.
    """
    for path in (SO_FILENAME, C_FILENAME):
        if os.path.isfile(path):
            print(f"Removing {path}")
            try:
                os.remove(path)
            except Exception as e:
                print(f"  [!] Could not remove {path}: {e}")
    print("Cleanup complete.")


def launch_vesktop(vesktop_path):
    """
    Exec Vesktop with LD_PRELOAD=./libdroverdirect.so
    """
    if not os.path.isfile(SO_FILENAME):
        print(f"⛔ libdroverdirect.so not found. Run “--setup” first.")
        sys.exit(1)
    if not os.path.isfile(vesktop_path) or not os.access(vesktop_path, os.X_OK):
        print(f"⛔ Vesktop binary not found or not executable: {vesktop_path}")
        sys.exit(1)

    env = os.environ.copy()
    env["LD_PRELOAD"] = SO_FILENAME
    print(f"\nLaunching Vesktop with LD_PRELOAD={SO_FILENAME} …\n")
    os.execvpe(vesktop_path, [vesktop_path], env)


def main():
    parser = argparse.ArgumentParser(description="Discord Direct‐mode for Vesktop (IPv4+IPv6).")
    parser.add_argument("--setup",   action="store_true", help="Build the LD_PRELOAD library.")
    parser.add_argument("--cleanup", action="store_true", help="Remove .so + source files.")
    parser.add_argument("--launch",  metavar="VESKTOP_PATH", help="Exec Vesktop with LD_PRELOAD.")
    args = parser.parse_args()

    if args.cleanup:
        ensure_root()
        cleanup_direct_library()
        sys.exit(0)

    if args.setup:
        ensure_root()
        build_direct_library()
        print(textwrap.dedent(f"""
            -------------------------------
            ✅ “Direct mode (IPv6+)” is now ready.
            To launch Vesktop with UDP manipulation, run:

              {sys.argv[0]} --launch /path/to/vesktop

            (E.g.: /usr/bin/vesktop or ~/bin/vesktop)

            Make sure the Vesktop binary is executable.
            -------------------------------
            """))
        sys.exit(0)

    if args.launch:
        launch_vesktop(args.launch)

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
