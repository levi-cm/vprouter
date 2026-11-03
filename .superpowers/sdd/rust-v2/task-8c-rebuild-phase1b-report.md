# Task 8c rebuild — Phase 1B: x86_64 VM substrate acquisition

Observed UTC: 2026-11-03T23:01:09.425344+00:00. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`. Host `debdev`, Debian 13, user `opsec` (UID 1000).

**Acquisition and guest-free substrate checks completed. Guest boot, guest runtime, preservation, Bootstrap and acceptance: NOT_RUN.** The archived launcher was read and analyzed, never executed. No overlay, seed ISO, cloud-init input, SSH key, guest state directory or persistent QEMU process was created. No subagents, Git writes, sudo, package installation, network/firewall/Tailscale changes, or writes to `target/*.py`, `target/candidates`, `crates/` or `docs/` were performed by this phase. Concurrent Phase 1A changes observed in `docs/rust-v2/programs-*.json` and its build helper were left untouched. Files written by this phase are in the two authorized durable directories, scratch `/tmp`, and this explicitly requested report.

## Sources and verification

Read the rebuild assessment (inputs/storage and plan step 3), and the full archived `start-additional-clean-debian.py`, `download-inputs.py`, `start-cloud-guests.py` and `start-void-live.py`. No Arch, ARM64 or Void image, emulator executable or separate tooling was acquired. The standard Debian `qemu-system-data` package naturally includes firmware data for multiple machine families.

### Debian image

- Image URL: https://cloud.debian.org/images/cloud/trixie/20261021-2638/debian-13-genericcloud-amd64-20261021-2638.qcow2
- Manifest URL: https://cloud.debian.org/images/cloud/trixie/20261021-2638/SHA512SUMS
- Local image: `/DATA/vprouter-lab/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2`
- Local manifest: `/DATA/vprouter-lab/lab-images/SHA512SUMS-20261021-2638` (unaltered upstream bytes).
- Downloaded size: 342,294,528 bytes.
- SHA512, exact filename entry matched once: `16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c`.
- Image SHA256: `d3a5c93cc98b34651421e0fa3a37db428f07355a3bc4cf46d6fbeb001f258e90`.
- SHA512SUMS SHA256: `5e22239e7bcb7ac4056324aa1829620f2853bff0c3b77b3af8c4578642c0f359`.
- SHA512 comparison: PASS on download and again after read-only `qemu-img info`. Exact requested build was available; no substitution was needed. The manifest was fetched over official HTTPS; its detached signature was not checked or claimed.

### Debian packages

Downloaded 95 packages, 40,904,756 compressed bytes, with `apt-get download NAME=VERSION ...` using the host-configured APT sources. Recursively selected amd64/all `Depends` and `PreDepends` alternatives with Python APT; no recommended/suggested GUI, block-extra or unrelated guest tools were added. Extracted each verified package using `dpkg-deb -x FILE /DATA/vprouter-lab/lab-tools/root`; no maintainer scripts ran and the host dpkg database was not changed.

Each downloaded SHA256 was compared to its exact package/version record from APT metadata, then independently matched to the signed package index. `gpgv --keyring /usr/share/keyrings/debian-archive-keyring.gpg InRelease` succeeded for both Debian repositories; the SHA256 and byte count of each uncompressed `main/binary-amd64/Packages` matched the corresponding signed InRelease entry. All 95 `.deb` hashes were rechecked after extraction. Full command log, original signed InRelease files, signature output and matched package records are retained in `phase1b-evidence/`.

This used the host’s existing cached metadata, without `apt update` or any host source changes. Trixie InRelease is dated 2026-09-12; security InRelease is dated 2026-10-21 and its `Valid-Until` is 2026-10-28, already past at acquisition. Signature and hash integrity are verified against that historical snapshot; current repository freshness/latest security status is not claimed. APT successfully served every pinned package.

Package URLs below are the exact APT-resolved URLs. Every listed actual SHA256 matched its metadata SHA256.

| Package | Version | Architecture | SHA256 | URL |
| --- | --- | --- | --- | --- |
| adduser | `3.152` | all | `e50984d2e1ef6300e3fd51303839842189a077b10cb5cadff1923df10c61c493` | http://deb.debian.org/debian/pool/main/a/adduser/adduser_3.152_all.deb |
| base-passwd | `3.6.7` | amd64 | `cf31c6956ab5f65815d9d9ea1615c4f78ecd2893c31119658248a4756cee83e7` | http://deb.debian.org/debian/pool/main/b/base-passwd/base-passwd_3.6.7_amd64.deb |
| debconf | `1.5.91` | all | `1ddc7e6c5925f748eefb7ca811d98e049f18c158bb21fbc7e122262ce6011e49` | http://deb.debian.org/debian/pool/main/d/debconf/debconf_1.5.91_all.deb |
| gcc-14-base | `14.2.0-19` | amd64 | `5b6825de4263824b78c4c51f6476414f3b4e89c2ab63e81dc8b9b5501e867cf6` | http://deb.debian.org/debian/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_amd64.deb |
| genisoimage | `9:1.1.11-4` | amd64 | `e6dc605d0ef3fc375d6cc96c16af32b48a1053e2f08db769d3483d3c7fdb6884` | http://deb.debian.org/debian/pool/main/c/cdrkit/genisoimage_1.1.11-4_amd64.deb |
| ipxe-qemu | `1.21.1+git20250501.dad20602+dfsg-1` | all | `b3b799d90b87ef2d6defa925cd48cf1691a19806f08041733a4f884d4a218b17` | http://deb.debian.org/debian/pool/main/i/ipxe/ipxe-qemu_1.21.1%2bgit20250501.dad20602%2bdfsg-1_all.deb |
| libacl1 | `2.3.2-2+b1` | amd64 | `08074f01e384bc07c0c2d79a58cf4a6523f71cf75d1808101c79617656c9a39d` | http://deb.debian.org/debian/pool/main/a/acl/libacl1_2.3.2-2%2bb1_amd64.deb |
| libaio1t64 | `0.3.113-8+b1` | amd64 | `490c8a2d116001a5f3b0a6d7a7aabf6a7b629366590dc5c3f75b078e931dd129` | http://deb.debian.org/debian/pool/main/liba/libaio/libaio1t64_0.3.113-8%2bb1_amd64.deb |
| libasound2-data | `1.2.14-1+deb13u1` | all | `04688afdff3769c0f685541daed7b2f6f0cb946799ddf1d5847ddf11fe245559` | http://deb.debian.org/debian/pool/main/a/alsa-lib/libasound2-data_1.2.14-1%2bdeb13u1_all.deb |
| libasound2t64 | `1.2.14-1+deb13u1` | amd64 | `5495496142d57e5ad6d581ac5456ec3c87f872c109a2bfb815d154b673eebc67` | http://deb.debian.org/debian/pool/main/a/alsa-lib/libasound2t64_1.2.14-1%2bdeb13u1_amd64.deb |
| libatomic1 | `14.2.0-19` | amd64 | `212b399aae2f7299203d261a57e49372e09565a9a5ea971905f94a3960366c05` | http://deb.debian.org/debian/pool/main/g/gcc-14/libatomic1_14.2.0-19_amd64.deb |
| libattr1 | `1:2.5.2-3` | amd64 | `606b5ee12ea2786be607a17f40c1fb5e65c76ceaff66665bdf8f8c6c1b71d1fb` | http://deb.debian.org/debian/pool/main/a/attr/libattr1_2.5.2-3_amd64.deb |
| libaudit-common | `1:4.0.2-2+deb13u1` | all | `b9d32e5ff04fd747aacb7d6b3ebbbbf734ddefb2f1695f0b1b2a4b5e51b1052e` | http://deb.debian.org/debian/pool/main/a/audit/libaudit-common_4.0.2-2%2bdeb13u1_all.deb |
| libaudit1 | `1:4.0.2-2+deb13u1` | amd64 | `3d1dd3f031a56f01b747e2acc0e14575212580e6fa63d800c44cb0a31f1edfd7` | http://deb.debian.org/debian/pool/main/a/audit/libaudit1_4.0.2-2%2bdeb13u1_amd64.deb |
| libblkid1 | `2.41.5-0+deb13u1` | amd64 | `81535f3c2c0efc732965907c8749103a0a26377c761622c9ce39b4c92dcde52f` | http://deb.debian.org/debian/pool/main/u/util-linux/libblkid1_2.41.5-0%2bdeb13u1_amd64.deb |
| libbpf1 | `1:1.5.0-3` | amd64 | `04c96ead3024888d80d08c8d08cc8cf4589f4614627acc69519f87ffb5adc1c2` | http://deb.debian.org/debian/pool/main/libb/libbpf/libbpf1_1.5.0-3_amd64.deb |
| libbrlapi0.8 | `6.7-3.1+deb13u3` | amd64 | `d8767805735bfae0edbe793fc8b6f6266ac9e55bec88c3d36b567c41b6438ca2` | http://deb.debian.org/debian/pool/main/b/brltty/libbrlapi0.8_6.7-3.1%2bdeb13u3_amd64.deb |
| libbsd0 | `0.12.2-2` | amd64 | `e5a85986fa6bec3307ab1bc860736b478b331882bc45e17675a7bdf88eecb43a` | http://deb.debian.org/debian/pool/main/libb/libbsd/libbsd0_0.12.2-2_amd64.deb |
| libbz2-1.0 | `1.0.8-6` | amd64 | `cba4cda04244b5e481bb15524bc3c983a7d1b6f330013b9b381706a2fcb65310` | http://deb.debian.org/debian/pool/main/b/bzip2/libbz2-1.0_1.0.8-6_amd64.deb |
| libc6 | `2.41-12+deb13u4` | amd64 | `967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9` | http://deb.debian.org/debian/pool/main/g/glibc/libc6_2.41-12%2bdeb13u4_amd64.deb |
| libcacard0 | `1:2.8.0-3+b2` | amd64 | `1d6a8d17b893e54dfea8fe78df16c9a8ab4a6e626f9312881784592d480d9317` | http://deb.debian.org/debian/pool/main/libc/libcacard/libcacard0_2.8.0-3%2bb2_amd64.deb |
| libcap-ng0 | `0.8.5-4+b1` | amd64 | `20a9e4b0619a3eb2566338223bed135dde5a601eaa2f8fdd5f20b94506addcac` | http://deb.debian.org/debian/pool/main/libc/libcap-ng/libcap-ng0_0.8.5-4%2bb1_amd64.deb |
| libcap2 | `1:2.75-10+deb13u1+b3` | amd64 | `89fc4d34fc7a28ad6f0fcd0c561ab253b9dedf6f77f5a000b47c276c8295bf67` | http://deb.debian.org/debian/pool/main/libc/libcap2/libcap2_2.75-10%2bdeb13u1%2bb3_amd64.deb |
| libcapstone5 | `5.0.7-1~deb13u1` | amd64 | `775187a7be26bb0b076d1979a02163b943dbc13eb4adb0efc503223a03c75422` | http://deb.debian.org/debian/pool/main/c/capstone/libcapstone5_5.0.7-1%7edeb13u1_amd64.deb |
| libcrypt1 | `1:4.4.38-1` | amd64 | `0ebc144d662e3197982d1bf3a7b8b35ca845e54c68811de0328b1f0d7c67585c` | http://deb.debian.org/debian/pool/main/libx/libxcrypt/libcrypt1_4.4.38-1_amd64.deb |
| libdaxctl1 | `81-1` | amd64 | `6296eb5c976743ba0defb7a061ef081238ca072cf569c6bb96fd3f9095c58a30` | http://deb.debian.org/debian/pool/main/n/ndctl/libdaxctl1_81-1_amd64.deb |
| libdb5.3t64 | `5.3.28+dfsg2-9` | amd64 | `18d02510ee78b67e4504ba050176797a200ff24214a7cd318082ab60ad7bf3fc` | http://deb.debian.org/debian/pool/main/d/db5.3/libdb5.3t64_5.3.28%2bdfsg2-9_amd64.deb |
| libdebconfclient0 | `0.280` | amd64 | `25acadc8b394bc86d05df16e70975e523f8f839a7d8d6d5e22c1cafdcef741aa` | http://deb.debian.org/debian/pool/main/c/cdebconf/libdebconfclient0_0.280_amd64.deb |
| libelf1t64 | `0.192-4` | amd64 | `94497b7e17b6f574a0605b380d454e20d3f01a9c63b70c2a2263f679d30053e1` | http://deb.debian.org/debian/pool/main/e/elfutils/libelf1t64_0.192-4_amd64.deb |
| libexecs1 | `1.4-2+b2` | amd64 | `05b578fead365a81141fe834c3b3b6df89d17a050784a237f736489fbd426105` | http://deb.debian.org/debian/pool/main/libe/libexecs/libexecs1_1.4-2%2bb2_amd64.deb |
| libfdt1 | `1.7.2-2+b1` | amd64 | `8e37034d7864807ae2063efcc82fc79aad59069546212e6e0908ed67f9f7e107` | http://deb.debian.org/debian/pool/main/d/device-tree-compiler/libfdt1_1.7.2-2%2bb1_amd64.deb |
| libffi8 | `3.4.8-2` | amd64 | `0ebdc340de33333639c3c63874cd4b15ac2e83dfa1ef3053b7eefaf4919f4f68` | http://deb.debian.org/debian/pool/main/libf/libffi/libffi8_3.4.8-2_amd64.deb |
| libfuse3-4 | `3.17.2-3` | amd64 | `92e2d521ff872755a13aa69dba7b24025a7dc0f0f5aa708c9a86cd3565f570da` | http://deb.debian.org/debian/pool/main/f/fuse3/libfuse3-4_3.17.2-3_amd64.deb |
| libgcc-s1 | `14.2.0-19` | amd64 | `3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150` | http://deb.debian.org/debian/pool/main/g/gcc-14/libgcc-s1_14.2.0-19_amd64.deb |
| libglib2.0-0t64 | `2.84.4-3~deb13u5` | amd64 | `e2baf92c57d1db1753e5781a61450d9a01e7833c7bd2dfe87776a6811c11ecc2` | http://deb.debian.org/debian/pool/main/g/glib2.0/libglib2.0-0t64_2.84.4-3%7edeb13u5_amd64.deb |
| libgmp10 | `2:6.3.0+dfsg-3` | amd64 | `d0d0265eb01770f17afd0f7c8c0622f80479dcfbbe13653a0debeec61464e622` | http://deb.debian.org/debian/pool/main/g/gmp/libgmp10_6.3.0%2bdfsg-3_amd64.deb |
| libgnutls30t64 | `3.8.9-3+deb13u4` | amd64 | `18a8bdfd91c7e3bcb01719d55a2b56849c7160b34f1f52b1c4fdfdd41bf1352b` | http://deb.debian.org/debian/pool/main/g/gnutls28/libgnutls30t64_3.8.9-3%2bdeb13u4_amd64.deb |
| libhogweed6t64 | `3.10.1-1` | amd64 | `b059ed155115ac09da295322de48ee1ed58ef5fa45edcc9e12ff0e94636ef25f` | http://deb.debian.org/debian/pool/main/n/nettle/libhogweed6t64_3.10.1-1_amd64.deb |
| libibverbs1 | `56.1-1` | amd64 | `4c3b889607586e6328964a5f98e01ef01daa415be24334d743d6654aab4c47a4` | http://deb.debian.org/debian/pool/main/r/rdma-core/libibverbs1_56.1-1_amd64.deb |
| libidn2-0 | `2.3.8-2` | amd64 | `90b039bcdc4578f8e1c4935adf8dbb525e36a164deefdbbb8c45bac347d48278` | http://deb.debian.org/debian/pool/main/libi/libidn2/libidn2-0_2.3.8-2_amd64.deb |
| libjpeg62-turbo | `1:2.1.5-4` | amd64 | `5504299ad0e3c0a9ca9f962a68a650a040db52f9f416a109e74df48d55601d3f` | http://deb.debian.org/debian/pool/main/libj/libjpeg-turbo/libjpeg62-turbo_2.1.5-4_amd64.deb |
| libkmod2 | `34.2-2` | amd64 | `ee6c50ebac79aa9795e8bf9aa01d94c99984d09d22598c66be0f8ba917b62179` | http://deb.debian.org/debian/pool/main/k/kmod/libkmod2_34.2-2_amd64.deb |
| liblzma5 | `5.8.1-1+deb13u2` | amd64 | `b38acab30f295bf1066a6632e31cbd0a1980f2924b38040cda131d5dea5384ec` | http://security.debian.org/debian-security/pool/updates/main/x/xz-utils/liblzma5_5.8.1-1%2bdeb13u2_amd64.deb |
| libmagic-mgc | `1:5.46-5` | amd64 | `1368da7c4c7dd10fb2f9ee3ed8a70801650c0c1d249a4076af15e2ddfbb14b46` | http://deb.debian.org/debian/pool/main/f/file/libmagic-mgc_5.46-5_amd64.deb |
| libmagic1t64 | `1:5.46-5` | amd64 | `53f653873216b135570b42c423ea93825c008ac464780b4578e80ee424237a4e` | http://deb.debian.org/debian/pool/main/f/file/libmagic1t64_5.46-5_amd64.deb |
| libmd0 | `1.1.0-2+b1` | amd64 | `7244ec3839b61fac0c1884fe08aaa040f26e8f1f35f1f5d3482eacefd30d1b44` | http://deb.debian.org/debian/pool/main/libm/libmd/libmd0_1.1.0-2%2bb1_amd64.deb |
| libmount1 | `2.41.5-0+deb13u1` | amd64 | `6d00f45f2e80e078e906e3eedecd3ba6913e39fef49bff361ee583f17f00ec05` | http://deb.debian.org/debian/pool/main/u/util-linux/libmount1_2.41.5-0%2bdeb13u1_amd64.deb |
| libncursesw6 | `6.5+20250216-2` | amd64 | `47baa2e11579583654583a066b69bd5a5d2f22423081f707ed6c0c3ba6d538b7` | http://deb.debian.org/debian/pool/main/n/ncurses/libncursesw6_6.5%2b20250216-2_amd64.deb |
| libndctl6 | `81-1` | amd64 | `fe60a05d42e61cb9f49a90b872aa5ca569363b13459ee0d405243c37a7de7c93` | http://deb.debian.org/debian/pool/main/n/ndctl/libndctl6_81-1_amd64.deb |
| libnettle8t64 | `3.10.1-1` | amd64 | `1b03d4a9cd9c8143ba50fe6396f36937e901a317d492d179f4596862c1731cfe` | http://deb.debian.org/debian/pool/main/n/nettle/libnettle8t64_3.10.1-1_amd64.deb |
| libnl-3-200 | `3.7.0-2` | amd64 | `ce5c153953016be42def7b105f37d55eae07a9608d1dfe6bcb03cc017fc384cb` | http://deb.debian.org/debian/pool/main/libn/libnl3/libnl-3-200_3.7.0-2_amd64.deb |
| libnl-route-3-200 | `3.7.0-2` | amd64 | `1c8c95542688996cff8e954583642b10a3bd78b69954f565fda62144c2bc3897` | http://deb.debian.org/debian/pool/main/libn/libnl3/libnl-route-3-200_3.7.0-2_amd64.deb |
| libnspr4 | `2:4.36-1` | amd64 | `87fc2039ee89cff2b8010fa9535706b1def40031acfc52bf12197dcb3cb7b064` | http://deb.debian.org/debian/pool/main/n/nspr/libnspr4_4.36-1_amd64.deb |
| libnss3 | `2:3.110-1+deb13u4` | amd64 | `8d20d0754039e15e9bd2c8484e98dc9c2982907d4f20834da29a9501913d00b5` | http://deb.debian.org/debian/pool/main/n/nss/libnss3_3.110-1%2bdeb13u4_amd64.deb |
| libnuma1 | `2.0.19-1` | amd64 | `e578583f73f8208564e5035b18aa729c441fc7ecb389c666923552e123f4d655` | http://deb.debian.org/debian/pool/main/n/numactl/libnuma1_2.0.19-1_amd64.deb |
| libp11-kit0 | `0.25.5-3` | amd64 | `784bf2063e166c8bc851a32623b74ebd85c499043a9d57c5bbd64fa63447f45a` | http://deb.debian.org/debian/pool/main/p/p11-kit/libp11-kit0_0.25.5-3_amd64.deb |
| libpam-modules | `1.7.0-5` | amd64 | `9679ade117f8775ac0471f48a92652ab8e8dcda4e2ff06de75158cded9cfd83c` | http://deb.debian.org/debian/pool/main/p/pam/libpam-modules_1.7.0-5_amd64.deb |
| libpam-modules-bin | `1.7.0-5` | amd64 | `cc72066d008444317738e8e931d6131b301466b4e2dd5ef5baa75fb1a45d61a7` | http://deb.debian.org/debian/pool/main/p/pam/libpam-modules-bin_1.7.0-5_amd64.deb |
| libpam0g | `1.7.0-5` | amd64 | `4f5bde27d8df2de6ea8990319b42d9974f56a3ba9907ce7296fd0f8964fc9fb1` | http://deb.debian.org/debian/pool/main/p/pam/libpam0g_1.7.0-5_amd64.deb |
| libpcre2-8-0 | `10.46-1~deb13u3` | amd64 | `e226f661d918f04daf38cdbc4806b7ed7d6ef95c7eb0ade692fc350e31970040` | http://security.debian.org/debian-security/pool/updates/main/p/pcre2/libpcre2-8-0_10.46-1%7edeb13u3_amd64.deb |
| libpcsclite1 | `2.3.3-1` | amd64 | `a8bc4725549060d1e696d358e32a3699d947d5381871553a290389830bebccbd` | http://deb.debian.org/debian/pool/main/p/pcsc-lite/libpcsclite1_2.3.3-1_amd64.deb |
| libpixman-1-0 | `0.44.0-3` | amd64 | `3862c87596f6b4b60fc916395fd69aa10af28a875a8e5c081a8cf30ddd120bd6` | http://deb.debian.org/debian/pool/main/p/pixman/libpixman-1-0_0.44.0-3_amd64.deb |
| libpmem1 | `1.13.1-1.1+b1` | amd64 | `7d972d6958e915ce602e4b90debc6b4b91a01dfea1fe003d0b013756e7d9d863` | http://deb.debian.org/debian/pool/main/p/pmdk/libpmem1_1.13.1-1.1%2bb1_amd64.deb |
| libpng16-16t64 | `1.6.48-1+deb13u6` | amd64 | `0f8034d1c2547760430c81e8d87e5d6acd533a3493c80cf76dbecd0343b6773c` | http://security.debian.org/debian-security/pool/updates/main/libp/libpng1.6/libpng16-16t64_1.6.48-1%2bdeb13u6_amd64.deb |
| librdmacm1t64 | `56.1-1` | amd64 | `5b56911725905b8e2a8389c99416ca078395c4ca8ce0d516bc758d5be0134687` | http://deb.debian.org/debian/pool/main/r/rdma-core/librdmacm1t64_56.1-1_amd64.deb |
| libsasl2-2 | `2.1.28+dfsg1-9` | amd64 | `66e49d7ae026811b49a0050f18b0325960a2625ffd1ff60d91b7844a815fa9d2` | http://deb.debian.org/debian/pool/main/c/cyrus-sasl2/libsasl2-2_2.1.28%2bdfsg1-9_amd64.deb |
| libsasl2-modules-db | `2.1.28+dfsg1-9` | amd64 | `a5c38659fbd62c33c6d9bfa2be43e75a572d1818531aad32dd74d0a58cc4bd19` | http://deb.debian.org/debian/pool/main/c/cyrus-sasl2/libsasl2-modules-db_2.1.28%2bdfsg1-9_amd64.deb |
| libseccomp2 | `2.6.0-2` | amd64 | `89d5138e05fb6a86b9afd8b54dc0fb4b14f4c27c05e6c5f767c2132bdf808531` | http://deb.debian.org/debian/pool/main/libs/libseccomp/libseccomp2_2.6.0-2_amd64.deb |
| libselinux1 | `3.8.1-1` | amd64 | `68bb8d32bd8d6d7d2f5952a169db03d1484b46ae1e52abccdec42a19dccea5d5` | http://deb.debian.org/debian/pool/main/libs/libselinux/libselinux1_3.8.1-1_amd64.deb |
| libsemanage-common | `3.8.1-1` | all | `65375d886749c236bd1da4d9990b7c2469d2fe66019a28e5614f6814376d3dcb` | http://deb.debian.org/debian/pool/main/libs/libsemanage/libsemanage-common_3.8.1-1_all.deb |
| libsemanage2 | `3.8.1-1` | amd64 | `f97da7505d17ad3bdd8fc56302256df7e158e5e0d8b02cb766654199cbc406a9` | http://deb.debian.org/debian/pool/main/libs/libsemanage/libsemanage2_3.8.1-1_amd64.deb |
| libsepol2 | `3.8.1-1` | amd64 | `3595d2d3a6d24695e7953f4f00cdfe6974c9242d9a8dfee8998e77fbf7b2ba09` | http://deb.debian.org/debian/pool/main/libs/libsepol/libsepol2_3.8.1-1_amd64.deb |
| libslirp0 | `4.8.0-1+deb13u1` | amd64 | `6125698173f8be0d0de01ff897a0df3c5e50fb09f70238b26dd6574aaa0934e1` | http://deb.debian.org/debian/pool/main/libs/libslirp/libslirp0_4.8.0-1%2bdeb13u1_amd64.deb |
| libsqlite3-0 | `3.46.1-7+deb13u2` | amd64 | `0a459adaffd901109f7811ab65f58e7a957b4907d05539cf3d1184efdcde0468` | http://deb.debian.org/debian/pool/main/s/sqlite3/libsqlite3-0_3.46.1-7%2bdeb13u2_amd64.deb |
| libssl3t64 | `3.5.7-1~deb13u3` | amd64 | `ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074` | http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl3t64_3.5.7-1%7edeb13u3_amd64.deb |
| libsystemd0 | `257.13-1~deb13u1` | amd64 | `ab0d4127b5e46e6f8c015a1db15a62ba9ae274cdefa150083adf90ada0600ea1` | http://deb.debian.org/debian/pool/main/s/systemd/libsystemd0_257.13-1%7edeb13u1_amd64.deb |
| libtasn1-6 | `4.20.0-2+deb13u1` | amd64 | `23fec6e06583ce2bad9b2c04c9b485e90440e259b1abf8677cd80d3ce60831ad` | http://deb.debian.org/debian/pool/main/libt/libtasn1-6/libtasn1-6_4.20.0-2%2bdeb13u1_amd64.deb |
| libtinfo6 | `6.5+20250216-2` | amd64 | `8b9f6a7983e9418564e48a627518de4c03917b56efe68d7f3e93bd8fffa1cc10` | http://deb.debian.org/debian/pool/main/n/ncurses/libtinfo6_6.5%2b20250216-2_amd64.deb |
| libudev1 | `257.13-1~deb13u1` | amd64 | `5d41c284f5a93b05bc7d648b61a02dd2bb9ff05b2261ad1a8b7d96044a0cfa88` | http://deb.debian.org/debian/pool/main/s/systemd/libudev1_257.13-1%7edeb13u1_amd64.deb |
| libunistring5 | `1.3-2` | amd64 | `6dd3490bef06ea1096f32d10766b7e016cf579bfae8451d1b7df15ce05b8aa46` | http://deb.debian.org/debian/pool/main/libu/libunistring/libunistring5_1.3-2_amd64.deb |
| liburing2 | `2.9-1` | amd64 | `4b589c00c7a51172aace2cb2fb3d3ff32daf86c644023126dcfcaa840cc941ea` | http://deb.debian.org/debian/pool/main/libu/liburing/liburing2_2.9-1_amd64.deb |
| libusb-1.0-0 | `2:1.0.28-1` | amd64 | `bb6467a002915c4ac464aa1b22204907951a30e43bcb86596ebd3539e84458e9` | http://deb.debian.org/debian/pool/main/libu/libusb-1.0/libusb-1.0-0_1.0.28-1_amd64.deb |
| libusbredirparser1t64 | `0.15.0-1` | amd64 | `4b039802dac140bae5a6f3fb6341eeeb9ea8c3e4d7b95ad36a07a8c28572f177` | http://deb.debian.org/debian/pool/main/u/usbredir/libusbredirparser1t64_0.15.0-1_amd64.deb |
| libuuid1 | `2.41.5-0+deb13u1` | amd64 | `c1bf4c4c3ff48c57fabf93307dfb56996b60cfa33927afc4158b5db36fb2721e` | http://deb.debian.org/debian/pool/main/u/util-linux/libuuid1_2.41.5-0%2bdeb13u1_amd64.deb |
| libvdeplug2t64 | `4.0.1-5.1+b1` | amd64 | `01291e2c8e28e91eac6b59c983a3a44e29ad0ddb8622699fbb84cbd5f26334a4` | http://deb.debian.org/debian/pool/main/v/vdeplug4/libvdeplug2t64_4.0.1-5.1%2bb1_amd64.deb |
| libzstd1 | `1.5.7+dfsg-1` | amd64 | `2f6a2aeacfc925eba8b00ac9139bc4bfccf8cacb09eb93de067074b26948eef9` | http://deb.debian.org/debian/pool/main/libz/libzstd/libzstd1_1.5.7%2bdfsg-1_amd64.deb |
| login.defs | `1:4.17.4-2` | all | `b4bbb8242cbf5588de7aafeb9d578a3dee1db2891f444ab454fd30bd80ccf2b4` | http://deb.debian.org/debian/pool/main/s/shadow/login.defs_4.17.4-2_all.deb |
| openssl-provider-legacy | `3.5.7-1~deb13u3` | amd64 | `c12e0266c4780749a4702b8959ac979689f4182e18eed85a8a5eb90ed0e16eab` | http://security.debian.org/debian-security/pool/updates/main/o/openssl/openssl-provider-legacy_3.5.7-1%7edeb13u3_amd64.deb |
| passwd | `1:4.17.4-2` | amd64 | `c5eaef41c6947d2888fa3462f787a7e02158b997bd0119154283f425ba57b8b8` | http://deb.debian.org/debian/pool/main/s/shadow/passwd_4.17.4-2_amd64.deb |
| qemu-system-common | `1:10.0.13+ds-0+deb13u1` | amd64 | `3a99dc23c42c66bb7e96dc1f2ba12b1797d154a472fbdb1cfcd822d9fb69e85b` | http://deb.debian.org/debian/pool/main/q/qemu/qemu-system-common_10.0.13%2bds-0%2bdeb13u1_amd64.deb |
| qemu-system-data | `1:10.0.13+ds-0+deb13u1` | all | `a0e03c526cc09d4c2ab20aa19a8c12e916cdc49a170acb16a6563c28f70eafd3` | http://deb.debian.org/debian/pool/main/q/qemu/qemu-system-data_10.0.13%2bds-0%2bdeb13u1_all.deb |
| qemu-system-x86 | `1:10.0.13+ds-0+deb13u1` | amd64 | `5e841d0723a657fd8bc2e9e1a085d24f47fcb3e4a0f94762e6c38b429f22fbb1` | http://deb.debian.org/debian/pool/main/q/qemu/qemu-system-x86_10.0.13%2bds-0%2bdeb13u1_amd64.deb |
| qemu-utils | `1:10.0.13+ds-0+deb13u1` | amd64 | `6d31339b1630153fe7c5f8a51426b8fa6ce35731aeb015a84f2d333c4e4dca30` | http://deb.debian.org/debian/pool/main/q/qemu/qemu-utils_10.0.13%2bds-0%2bdeb13u1_amd64.deb |
| seabios | `1.16.3-2` | all | `2b590534250b940f43222eeab9a8f57f337a9d9a73fc412a43ab8cd07a7e56f6` | http://deb.debian.org/debian/pool/main/s/seabios/seabios_1.16.3-2_all.deb |
| zlib1g | `1:1.3.dfsg+really1.3.1-1+b1` | amd64 | `015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d` | http://deb.debian.org/debian/pool/main/z/zlib/zlib1g_1.3.dfsg%2breally1.3.1-1%2bb1_amd64.deb |

## Final tree and launcher compatibility

```text
target/lab-tools -> /DATA/vprouter-lab/lab-tools
  root/                         # unmodified Debian package extraction
    usr/bin/qemu-system-x86_64
    usr/bin/qemu-img
    usr/bin/genisoimage
    usr/bin/isoinfo              # also supplied by genisoimage
    usr/lib/x86_64-linux-gnu/    # all resolved ELF dependencies, including libc
      qemu/                     # QEMU modules
    usr/share/seabios/bios-256k.bin
    usr/share/qemu/              # QEMU data + packaged iPXE ROMs
  packages/                     # 95 retained .deb files
  phase1b-evidence/             # manifests, logs, metadata and reproduction scripts
target/lab-images -> /DATA/vprouter-lab/lab-images
  debian-13-genericcloud-amd64-20261021-2638.qcow2
  SHA512SUMS-20261021-2638
  phase1b-image-verification.json
```

The direct ELF executables work with the launcher’s exact environment; **no wrappers, renaming or launcher edits were needed**:

```sh
tools=/DATA/AppData/vprouter-rust-v2/target/lab-tools/root
export LD_LIBRARY_PATH="$tools/usr/lib/x86_64-linux-gnu"
export QEMU_MODULE_DIR="$tools/usr/lib/x86_64-linux-gnu/qemu"
```

`ldd` for all three called tools reported no missing libraries. Every `=>` library resolved inside this tree. The ELF interpreter remains the host’s `/lib64/ld-linux-x86-64.so.2`; this is a local Debian-13-compatible extraction, not a chroot or a claim of portability to arbitrary hosts. Direct invocation without the launcher environment is not the supported contract.

Dry analysis of the archived launcher confirms:

- The exact base filename and `SHA512SUMS-20261021-2638` checksum parsing match the acquired files. Its restored `target/platform-lab/start-additional-clean-debian.py` is byte-identical to the archive (SHA256 `5db133313f666171adc5227972d681f3aae95b4db2c74e0f92b551ef13b43842`). Only read that concurrently restored file.
- All three absolute executable paths, module directory, `-L .../usr/share/qemu`, and explicit `-bios .../usr/share/seabios/bios-256k.bin` exist. SeaBIOS is 262144 bytes; QEMU data includes `kvmvapic.bin` and `linuxboot_dma.bin`. Package-extracted paths need no repair.
- Help-only inspections list `pc` (alias `pc-i440fx-10.0`), `smm`, `virtio-net-pci`, `netdev`, and `romfile`. The launcher’s `pc,smm=off`, virtio disks, readonly CD-ROM, `-boot c`, `-vga none`, display/serial/QMP/PID paths and sandbox arguments are consistent with QEMU 10.0.13. `libslirp.so.0` resolves locally for its later user-mode networking; no network backend or forwarding listener was started here.
- The full launcher argument set was not executed. In particular, `-cpu host`, two vCPUs, the PC board, BIOS loading, disks, seed media, user networking/forwarding and guest execution remain untested as a combined launch. `-cpu host` support is not established by the CPU-less KVM probe.
- Future-phase inputs are intentionally absent: `target/lab-state/id_ed25519.pub` and `target/platform-lab/debian-clean-x86_64`. Therefore the unchanged launcher cannot yet complete; future dedicated-key provisioning and explicitly authorized overlay/seed/guest creation are still required. No private keys were opened. Port 22036 availability was not probed by this phase.
- No substrate path mismatch requires a controller change. No Arch/ARM64/Void launch readiness is claimed.

## Smoke checks: commands and verbatim output

The following commands used the environment above. All successful commands exited 0. Stdout is reproduced without reformatting; stderr was empty for these checks. A 15-second `subprocess.run` timeout bounded each invocation.

```sh
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-system-x86_64 --version
```

Verbatim stdout:

```text
QEMU emulator version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)
Copyright (c) 2003-2025 Fabrice Bellard and the QEMU Project developers
```

Exit: `0`; stderr: empty.

```sh
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-img --version
```

Verbatim stdout:

```text
qemu-img version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)
Copyright (c) 2003-2025 Fabrice Bellard and the QEMU Project developers
```

Exit: `0`; stderr: empty.

```sh
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/genisoimage --version
```

Verbatim stdout:

```text
genisoimage 1.1.11 (Linux)
```

Exit: `0`; stderr: empty.

```sh
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-img info --output=json /DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2
```

Verbatim stdout:

```text
{
    "children": [
        {
            "name": "file",
            "info": {
                "children": [
                ],
                "virtual-size": 342294528,
                "filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
                "format": "file",
                "actual-size": 342294528,
                "format-specific": {
                    "type": "file",
                    "data": {
                    }
                },
                "dirty-flag": false
            }
        }
    ],
    "virtual-size": 3221225472,
    "filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
    "cluster-size": 65536,
    "format": "qcow2",
    "actual-size": 342294528,
    "format-specific": {
        "type": "qcow2",
        "data": {
            "compat": "1.1",
            "compression-type": "zlib",
            "lazy-refcounts": false,
            "refcount-bits": 16,
            "corrupt": false,
            "extended-l2": false
        }
    },
    "dirty-flag": false
}
```

Exit: `0`; stderr: empty.

Python capability check (no machine creation):

```python
with open('/dev/kvm', 'r+b', buffering=0) as f:
    version = fcntl.ioctl(f.fileno(), 0xAE00, 0)  # KVM_GET_API_VERSION
```

Recorded output:

```json
{
  "probe": "open /dev/kvm O_RDWR; ioctl KVM_GET_API_VERSION (0xAE00)",
  "uid": 1000,
  "username": "opsec",
  "api_version": 12
}
```

```sh
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-system-x86_64 -accel kvm -machine none -nodefaults -no-user-config -nographic -S -monitor none -qmp stdio -L /DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/share/qemu -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
```

Exact QMP stdin (no `cont` command):

```json
{"execute":"qmp_capabilities","id":"caps"}
{"execute":"query-kvm","id":"kvm"}
{"execute":"query-status","id":"status"}
{"execute":"quit","id":"quit"}
```

Verbatim stdout:

```text
{"QMP": {"version": {"qemu": {"micro": 13, "minor": 0, "major": 10}, "package": "Debian 1:10.0.13+ds-0+deb13u1"}, "capabilities": ["oob"]}}
{"return": {}, "id": "caps"}
{"return": {"enabled": true, "present": true}, "id": "kvm"}
{"return": {"status": "prelaunch", "running": false}, "id": "status"}
{"timestamp": {"seconds": 1793746744, "microseconds": 350894}, "event": "SHUTDOWN", "data": {"guest": false, "reason": "host-qmp-quit"}}
{"return": {}, "id": "quit"}
```

Exit: `0`; stderr: empty.

KVM result: `/dev/kvm` opened read/write as opsec; API version 12; QMP reported `enabled=true`, `present=true`, `status=prelaunch`, `running=false`, followed immediately by a host-QMP quit. `-machine none`, `-nodefaults`, `-no-user-config` and `-S` attached no disk, BIOS, NIC or guest media and executed no guest code. This proves guest-free KVM initialization under opsec, not guest runtime or acceptance. The QEMU process terminated with exit 0.

### Preserved initial probe failure

The first probe included `-cpu host` with `-machine none` (and the same `-S`/no disks/no NICs). It exited 1 after its QMP greeting with this verbatim stderr:

```text
qemu-system-x86_64: apic-id property was not initialized properly
```

This was the CPU/board combination in the empty-machine probe, not a tested PC guest failure. Removed `-cpu host` to use the authorized CPU-less capability probe; did not try a PC machine or boot anything. The initial full argv/stdout/stderr and traceback remain in `phase1b-evidence/smoke-tests-first-attempt.log`; successful raw results, including complete `ldd` output, are in `smoke-tests.json` and `smoke-tests.log`. Help-only outputs are retained alongside them.

## Evidence and disk use

Primary evidence directory: `/DATA/vprouter-lab/lab-tools/phase1b-evidence`. It contains `packages-planned.json`, `packages-verified.json`, `apt-get-download.log`, `apt-metadata-trust.json`, signed package records/InRelease files and gpgv logs, all smoke output and `final-verification.json`. The acquire, trust, smoke and final-verification Python scripts are retained there for review; none creates an overlay, seed or guest. Do not rerun acquisition scripts into the populated tree without reviewing their exclusive-create behavior.

Disk measurements below use `du -s -B1` (allocated bytes, filesystem accounting rather than unique physical Btrfs extents); apparent sizes use `du -s --apparent-size -B1`. Counts include retained downloads and evidence; the report lives separately in the repository.

| Path | Allocated bytes | Apparent bytes |
| --- | ---: | ---: |
| `/DATA/vprouter-lab/lab-tools/root` | 199,774,208 | 194,967,172 |
| `/DATA/vprouter-lab/lab-tools/packages` | 41,111,552 | 40,904,756 |
| `/DATA/vprouter-lab/lab-tools/phase1b-evidence` | 487,424 | 433,859 |
| `/DATA/vprouter-lab/lab-tools` | 241,373,184 | 236,305,787 |
| `/DATA/vprouter-lab/lab-images` | 342,310,912 | 342,303,979 |

Total durable substrate allocation: **583,684,096 bytes (556.64 MiB)** at measurement. Metadata/script sizes may differ slightly after report finalization. No sparse overlay capacity is included because none exists.

## Six-line summary

1. Acquired QEMU 10.0.13, qemu-img, genisoimage, BIOS/data and 95 hash-verified Debian packages.
2. Acquired exact Debian 13 AMD64 build 20261021-2638; official SHA512 matched twice.
3. Launcher executable/library/firmware paths resolve unchanged; no wrappers were needed.
4. Guest-free KVM probe passed as opsec: enabled=true, present=true, running=false; clean quit.
5. Durable substrate allocated 583,684,096 bytes (556.64 MiB), including downloads and evidence.
6. No guest/overlay/seed created or booted; guest runtime and acceptance remain NOT_RUN.
