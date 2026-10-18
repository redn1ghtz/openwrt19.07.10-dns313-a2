#!/usr/bin/env python3
"""DNS-313 A2: patch a locally downloaded OpenWrt 19.07.10 factory image.
Never accesses block devices. Needs python3, fdtget/fdtput, debugfs, e2fsck.
"""
import argparse
import gzip
import hashlib
import os
import re
import secrets
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib

HEADER = 104
MAGIC = bytes.fromhex('27051956')
DTMAGIC = bytes.fromhex('d00dfeed')
MODEL = b'DNS-313v2'
VERSION = b'1.04b08'
ARGS = 'console=ttyS0,19200n8 root=/dev/sda4 rw rootwait cma=0'
BOOT_START, BOOT_SECTORS = 63, 32949
ROOT_START, ROOT_SECTORS = 33075, 524349
SWAP_START, SWAP_SECTORS = 559104, 262144
DATA_START = 821248
SWAP_UUID = "4abeb6a0-66dc-48bb-ba47-48dcc3d1f516"
DISABLE_SERVICES = ('samba', 'samba4', 'smbd', 'nmbd', 'mdadm', 'dnsmasq', 'odhcpd', 'firewall')
# Exact autoload files observed on DNS-313; never remove module packages.
DISABLE_MODULE_FILES = ('28-md-linear', '28-md-raid456', '29-md-multipath',
                        '30-fs-ntfs', '30-fs-reiserfs', '30-fs-vfat',
                        '31-fs-nfs-common-rpcsec')



def run(*args):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f'{args!r}: {p.stderr.strip()} {p.stdout.strip()}')
    return p.stdout.strip()


def crc(data):
    return zlib.crc32(data) & 0xffffffff


def verify_header(raw, name):
    if len(raw) < HEADER or raw[:4] != MAGIC:
        raise ValueError(f'{name}: no D-Link 104-byte header')
    declared = struct.unpack_from('>I', raw, 12)[0]
    if declared != len(raw) - HEADER:
        raise ValueError(f'{name}: declared payload size {declared}, actual {len(raw)-HEADER}')
    h = bytearray(raw[:HEADER]); h[4:8] = b'\0'*4
    expected = struct.unpack_from('>I', raw, 4)[0]
    if crc(h) != expected:
        raise ValueError(f'{name}: bad 104-byte header CRC: {expected:08x} != {crc(h):08x}')
    if name == 'zImage' and crc(raw[HEADER:]) != struct.unpack_from('>I', raw, 24)[0]:
        raise ValueError('zImage: bad payload CRC')


def patch_header(raw, kernel=False):
    b = bytearray(raw)
    b[0x40:0x50] = MODEL.ljust(16, b'\0')
    b[0x50:0x60] = VERSION.ljust(16, b'\0')
    struct.pack_into('>I', b, 12, len(b)-HEADER)
    if kernel:
        struct.pack_into('>I', b, 24, crc(b[HEADER:]))
    b[4:8] = b'\0'*4
    struct.pack_into('>I', b, 4, crc(b[:HEADER]))
    return bytes(b)


def patch_dtb(blob, td):
    if blob[:4] != MAGIC:
        raise ValueError('Unexpected zImage header')
    payload = blob[HEADER:]
    matches = []
    start = 0
    while True:
        pos = payload.find(DTMAGIC, start)
        if pos < 0:
            break
        start = pos + 4
        if pos + 40 <= len(payload):
            length = struct.unpack_from('>I', payload, pos+4)[0]
            if 40 <= length <= 1_000_000 and pos+length == len(payload):
                matches.append(pos)
    if len(matches) != 1:
        raise ValueError(f'Expected one appended DTB at end of kernel, found {len(matches)}')
    pos = matches[0]
    dtb = td/'kernel.dtb'; dtb.write_bytes(payload[pos:])
    nodes = run('fdtget', '-l', dtb, '/').split()
    mem = [x for x in nodes if x == 'memory' or x.startswith('memory@')]
    if len(mem) != 1:
        raise ValueError(f'Unexpected memory nodes: {mem}')
    m = '/'+mem[0]
    values = [int(x, 16) for x in run('fdtget','-t','x',dtb,m,'reg').split()]
    if values not in ([0,0x2000000],[0,0x4000000]):
        raise ValueError(f'Unexpected RAM reg: {values}')
    run('fdtput','-t','x',dtb,m,'reg','0','0x2000000')
    run('fdtput','-t','s',dtb,'/chosen','bootargs',ARGS)
    # Linux 4.14 i2c-gpio binding: combined gpios, not separate sda-gpios/scl-gpios.
    try:
        existing = run('fdtget','-t','x',dtb,'/gpio-i2c','gpios').split()
    except RuntimeError:
        existing = []
    if existing:
        if len(existing) != 6:
            raise ValueError(f'Unexpected existing /gpio-i2c/gpios: {existing}')
    else:
        sda = run('fdtget','-t','x',dtb,'/gpio-i2c','sda-gpios').split()
        scl = run('fdtget','-t','x',dtb,'/gpio-i2c','scl-gpios').split()
        if len(sda) != 3 or len(scl) != 3:
            raise ValueError(f'Unexpected GPIO cell counts: {sda} {scl}')
        # Verified DNS-313 A2 GPIO: phandle 0x15, offsets 15/16, flags 6.
        vals = [int(x,16) for x in sda+scl]
        if vals != [0x15,0x0f,0x06,0x15,0x10,0x06]:
            raise ValueError(f'GPIO values differ from tested A2: {vals}')
        run('fdtput','-t','x',dtb,'/gpio-i2c','gpios',*('0x%x'%x for x in vals))
        run('fdtput','-d',dtb,'/gpio-i2c','sda-gpios')
        run('fdtput','-d',dtb,'/gpio-i2c','scl-gpios')
    if [int(x,16) for x in run('fdtget','-t','x',dtb,m,'reg').split()] != [0,0x2000000]:
        raise ValueError('RAM verification failed')
    if run('fdtget','-t','s',dtb,'/chosen','bootargs') != ARGS:
        raise ValueError('bootargs verification failed')
    gpio = [int(x,16) for x in run('fdtget','-t','x',dtb,'/gpio-i2c','gpios').split()]
    if gpio != [0x15,15,6,0x15,16,6]:
        raise ValueError('GPIO verification failed')
    new = patch_header(blob[:HEADER] + payload[:pos] + dtb.read_bytes(), True)
    verify_header(new, 'zImage')
    print('DTB: RAM=32MiB, I2C gpios=0x15/15/6 + 0x15/16/6, bootargs verified')
    return new




def check_rootfs(root):
    """Immediately preen temporary ext4 copy; reject uncorrectable problems."""
    fixed = subprocess.run(['e2fsck', '-p', str(root)], capture_output=True, text=True)
    if fixed.returncode not in (0, 1):
        raise RuntimeError('Root ext4 cannot be safely repaired: ' + fixed.stdout + fixed.stderr)
    print('Root ext4 preen completed on temporary image')


def configure_lan_mac(root, td, mac):
    """Persist a stable bridge MAC in UCI; tolerate factory images lacking network config."""
    original = td / 'network-original'
    stat = run('debugfs', '-R', 'stat /etc/config/network', root)
    if 'Inode:' in stat and 'Type: regular' in stat:
        # debugfs may return exit status 0 even when a dump operation failed.
        run('debugfs', '-R', f'dump /etc/config/network {original}', root)
        if not original.is_file():
            raise RuntimeError('debugfs could not dump /etc/config/network: ' + stat)
        content = original.read_text(encoding='utf-8', errors='surrogateescape')
        if '\x00' in content:
            raise ValueError('/etc/config/network contains NUL bytes; refusing to edit binary data')
    elif 'Inode:' in stat:
        raise RuntimeError('/etc/config/network exists but is not a regular file: ' + stat)
    else:
        # Some factory images create /etc/config/network only at first boot.
        # Reproduce the verified DNS-313 A2 LAN configuration in the image.
        content = "config interface 'lan'\n\toption type 'bridge'\n\toption ifname 'eth0'\n\toption proto 'dhcp'\n"
        print('Factory image has no /etc/config/network; creating LAN DHCP configuration')
    lines = content.splitlines(keepends=True)
    headers = [i for i, line in enumerate(lines) if re.match(r"^\s*config\s+interface\s+['\"]?lan['\"]?\s*(?:#.*)?$", line.strip())]
    if len(headers) != 1:
        raise ValueError(f'Expected exactly one network.lan interface, found {len(headers)}')
    start = headers[0]
    end = next((i for i in range(start + 1, len(lines)) if re.match(r'^\s*config\s+', lines[i])), len(lines))
    section = [line for line in lines[start+1:end] if not re.match(r'^\s*option\s+macaddr\s+', line)]
    lines = lines[:start+1] + [f"\toption macaddr '{mac}'\n"] + section + lines[end:]
    replacement = td / 'network-patched'
    replacement.write_text(''.join(lines), encoding='utf-8', errors='surrogateescape')
    if 'Inode:' in stat:
        run('debugfs', '-w', '-R', 'rm /etc/config/network', root)
    run('debugfs', '-w', '-R', f'write {replacement} /etc/config/network', root)
    run('debugfs', '-w', '-R', 'sif /etc/config/network mode 0100644', root)
    check = td / 'network-verify'
    run('debugfs', '-R', f'dump /etc/config/network {check}', root)
    if not check.is_file() or check.read_bytes() != replacement.read_bytes():
        raise ValueError('MAC configuration verification failed')
    print('Persistent LAN bridge MAC:', mac)


def choose_mac():
    while True:
        raw = input('DNS-313 label MAC ID (press Enter to generate a persistent random MAC): ').strip()
        if not raw:
            octets = bytearray(secrets.token_bytes(6))
            octets[0] = (octets[0] | 0x02) & 0xfe  # locally administered unicast
            mac = ':'.join(f'{x:02x}' for x in octets)
            print('Generated MAC for this firmware image:', mac)
            return mac
        normalized = raw.replace('-', ':').lower()
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', normalized):
            print('Invalid MAC format. Example: 00:21:91:51:94:9e')
            continue
        octets = bytes.fromhex(normalized.replace(':', ''))
        if octets[0] & 1 or not any(octets) or all(o == 255 for o in octets):
            print('Enter a valid unicast MAC address (not multicast or broadcast).')
            continue
        return normalized


def rootfs_patch(image, td, mac, disable_optional):
    """Patch OpenWrt ext4 root partition inside an ordinary image file."""
    off, length = ROOT_START * 512, ROOT_SECTORS * 512
    if len(image) < off + length:
        raise ValueError('Factory image has no complete root partition 4')
    root = td / 'root.img'
    root.write_bytes(image[off:off + length])
    check_rootfs(root)
    # Fail rather than silently produce a kernel-only image.
    release = run('debugfs', '-R', 'stat /etc/openwrt_release', root)
    if 'Inode:' not in release:
        raise ValueError('Root partition is not an OpenWrt ext4 filesystem')
    listing = run('debugfs', '-R', 'ls -p /etc/rc.d', root)
    disabled = []
    import re
    # debugfs -p: /inode/mode/uid/gid/name/size/
    for name in (DISABLE_SERVICES if disable_optional else ()):
        for entry in listing.splitlines():
            fields = entry.strip().split('/')
            if len(fields) < 6:
                continue
            filename = fields[5]
            if re.fullmatch(r'S\d\d' + re.escape(name), filename):
                run('debugfs', '-w', '-R', f'rm /etc/rc.d/{filename}', root)
                disabled.append(filename)
    # Install a native OpenWrt rc.common service; it runs on every boot.
    init = td / 'dns313-swap'
    init.write_text("""#!/bin/sh /etc/rc.common
START=00
STOP=90
start() {
    grep -q '^/dev/sda2 ' /proc/swaps && return 0
    if [ -b /dev/sda2 ]; then
        /sbin/swapon /dev/sda2 || swapon /dev/sda2
    else
        logger -t dns313-swap 'swap partition /dev/sda2 not present'
    fi
}
stop() {
    swapoff /dev/sda2 2>/dev/null || true
}
""", encoding='utf-8')
    run('debugfs', '-w', '-R', f'write {init} /etc/init.d/dns313-swap', root)
    run('debugfs', '-w', '-R', 'sif /etc/init.d/dns313-swap mode 0100755', root)
    # debugfs symlink syntax: symlink <new link> <target>
    run('debugfs', '-w', '-R',
        'symlink /etc/rc.d/S00dns313-swap ../init.d/dns313-swap', root)
    script_copy = td / 'swap-verify'
    run('debugfs', '-R', f'dump /etc/init.d/dns313-swap {script_copy}', root)
    if script_copy.read_bytes() != init.read_bytes():
        raise ValueError('Swap init script verification failed')
    # Only the opt-in profile modifies optional kernel module autoload entries.
    # Process regular files in modules.d; remove corresponding early-boot symlinks
    # before deleting their targets to avoid kmodloader "failed to open" warnings.
    changed_modules = []
    if disable_optional:
        def entries(directory):
            try:
                listing = run('debugfs', '-R', f'ls -p {directory}', root)
            except RuntimeError:
                return {}
            result = {}
            for line in listing.splitlines():
                fields = line.strip().split('/')
                if len(fields) >= 6 and re.fullmatch(r'[A-Za-z0-9_.+-]+', fields[5]):
                    result[fields[5]] = fields[2]  # octal file mode
            return result

        boot_entries = entries('/etc/modules-boot.d')
        module_entries = entries('/etc/modules.d')
        # Earlier firmware profiles filtered these module names. Extend with
        # the actual modules seen on this device; do not remove lib-xor.
        blocked = re.compile(
            r'^(?:btrfs|raid[0-9]*|raid456|md_mod|md-mod|md-raid[0-9]*|'
            r'md-linear|md-multipath|linear|multipath|ntfs|reiserfs|vfat|'
            r'nfs|nfsd|nfsv[234]|sunrpc|lockd|grace|fscache|'
            r'dns_resolver|rpcsec_gss_krb5|auth_rpcgss|cifs)(?:\s|$|[-_])'
        )
        for filename, mode in module_entries.items():
            if filename in ('.', '..'):
                continue
            path = f'/etc/modules.d/{filename}'
            extracted = td / ('module-' + filename)
            try:
                run('debugfs', '-R', f'dump {path} {extracted}', root)
                raw = extracted.read_text(encoding='utf-8')
            except (RuntimeError, UnicodeError):
                continue
            lines = raw.splitlines(keepends=True)
            kept = [line for line in lines if not blocked.match(line.strip())]
            if filename not in DISABLE_MODULE_FILES and len(kept) == len(lines):
                continue
            # For a removed module file, remove the same-named early-boot
            # entry first (usually a symlink). Never touch unrelated entries.
            if not kept or filename in DISABLE_MODULE_FILES:
                if filename in boot_entries:
                    run('debugfs', '-w', '-R', f'rm /etc/modules-boot.d/{filename}', root)
                    changed_modules.append('/etc/modules-boot.d/' + filename)
                run('debugfs', '-w', '-R', f'rm {path}', root)
            else:
                # Replace the regular autoload file, retaining unrelated lines.
                replacement = td / ('filtered-' + filename)
                replacement.write_text(''.join(kept), encoding='utf-8')
                run('debugfs', '-w', '-R', f'rm {path}', root)
                run('debugfs', '-w', '-R', f'write {replacement} {path}', root)
                run('debugfs', '-w', '-R', f'sif {path} mode 0100644', root)
            changed_modules.append(path)
        # The supplied factory root may already contain a dangling Btrfs link.
        # It was seen on the real device and produces a harmless boot error.
        for name in ('30-fs-btrfs', '30-fs-reiserfs'):
            if name in boot_entries and name not in entries('/etc/modules.d'):
                boot_path = f'/etc/modules-boot.d/{name}'
                if boot_path not in changed_modules:
                    run('debugfs', '-w', '-R', f'rm {boot_path}', root)
                    changed_modules.append(boot_path)
    print('Optional module autoload cleanup:',
          ', '.join(changed_modules) if changed_modules else
          ('nothing to change' if disable_optional else 'skipped (user choice)'))
    configure_lan_mac(root, td, mac)
    check_rootfs(root)
    print('Disabled startup services:' , ', '.join(disabled) if disabled else
          '(no matching startup links found)')
    print('Early swap autostart installed: /etc/rc.d/S00dns313-swap -> /dev/sda2')
    return off, length, root.read_bytes()

def patch_partition_table(image):
    """MBR with partitions 2-4; leave partition 1 absent for manual creation."""
    if image[510:512] != b'\x55\xaa':
        raise ValueError('Missing DOS MBR signature')
    entries = []
    for i in range(4):
        e = image[446+i*16:462+i*16]
        entries.append((e[4], *struct.unpack_from('<II', e, 8)))
    expected = {2:(SWAP_START,SWAP_SECTORS),3:(BOOT_START,BOOT_SECTORS),4:(ROOT_START,ROOT_SECTORS)}
    for num,(start,count) in expected.items():
        typ,old_start,old_count = entries[num-1]
        if typ and (old_start,old_count) != (start,count):
            raise ValueError(f'MBR partition {num} differs: {entries[num-1]}')
    if entries[0][0] and entries[0][1] != DATA_START:
        raise ValueError(f'MBR partition 1 starts at unexpected sector: {entries[0]}')
    out=bytearray(image)
    # The original installation instructions create partition 1 manually.
    # Clear its MBR entry; do not create or format a data partition here.
    out[446:462] = b"\0" * 16
    for num,typ,start,count in (
        (2,0x82,SWAP_START,SWAP_SECTORS),
        (3,0x83,BOOT_START,BOOT_SECTORS),
        (4,0x83,ROOT_START,ROOT_SECTORS),
    ):
        entry=bytes([0,0xfe,0xff,0xff,typ,0xfe,0xff,0xff])+struct.pack('<II',start,count)
        out[446+(num-1)*16:462+(num-1)*16]=entry
    return out


def make_swap(td):
    swap = td / 'swap.img'
    with swap.open('wb') as f:
        f.truncate(SWAP_SECTORS*512)
    run('mkswap', '-f', '-U', SWAP_UUID, str(swap))
    with swap.open('rb') as f:
        f.seek(4096-10)
        # swap signature resides at end of first page
        if f.read(10) != b'SWAPSPACE2':
            raise ValueError('Swap signature missing')
    return swap


def prepare(source, dest, mac, disable_optional):
    if not source.is_file() or dest.exists() or source.resolve() == dest.resolve():
        raise ValueError('Input must exist, output must not exist')
    os.environ['PATH'] = '/usr/sbin:/sbin:' + os.environ.get('PATH', '')
    for tool in ('debugfs','e2fsck','fdtget','fdtput','mkswap'):
        if not shutil.which(tool):
            raise RuntimeError(f'Missing tool {tool}: apt install e2fsprogs device-tree-compiler')
    with tempfile.TemporaryDirectory(prefix='dns313-a2-') as tmp:
        td = Path(tmp)
        if source.suffix == '.gz':
            with gzip.open(source,'rb') as src, (td/'factory.bin').open('wb') as out:
                shutil.copyfileobj(src,out)
            source = td/'factory.bin'
        image = source.read_bytes()
        image = patch_partition_table(image)
        swap_end = (SWAP_START + SWAP_SECTORS)*512
        if len(image) > SWAP_START*512:
            # Original image may already have a swap region, but must not
            # carry another filesystem or content there.
            if any(image[SWAP_START*512:min(len(image),swap_end)]):
                raise ValueError('Original image has nonzero swap region; refusing overwrite')
        if len(image) < swap_end:
            image.extend(b'\0'*(swap_end-len(image)))
        off = BOOT_START*512; length = BOOT_SECTORS*512
        if len(image) < off+length:
            raise ValueError('Factory image too short for boot partition')
        part = td/'boot.img'; part.write_bytes(image[off:off+length])
        run('e2fsck','-fn',part)
        updates = {}
        for name in ('zImage','rd.gz','rootfs.tgz'):
            extracted = td/('original-'+name)
            run('debugfs','-R',f'dump /.boot/{name} {extracted}',part)
            raw = extracted.read_bytes()
            if raw[:4] != MAGIC:
                raise ValueError(f'{name} missing D-Link header')
            if struct.unpack_from('>I',raw,12)[0] != len(raw)-HEADER:
                raise ValueError(f'{name} unexpected payload size')
            if name == 'zImage':
                updates[name] = patch_dtb(raw, td)
            else:
                updates[name] = patch_header(raw)
            verify_header(updates[name],name)
        # Modifies only an isolated image, never physical block devices.
        for name, data in updates.items():
            f = td/('patched-'+name); f.write_bytes(data)
            run('debugfs','-w','-R',f'rm /.boot/{name}',part)
            run('debugfs','-w','-R',f'write {f} /.boot/{name}',part)
            run('debugfs','-w','-R',f'sif /.boot/{name} mode 0100740',part)
            verify = td/('verify-'+name)
            run('debugfs','-R',f'dump /.boot/{name} {verify}',part)
            if verify.read_bytes() != data:
                raise ValueError(f'{name} readback differs')
            print(f'{name}: {len(data)} bytes, header CRC {struct.unpack_from(">I",data,4)[0]:08x}')
        run('e2fsck','-fn',part)
        patched = part.read_bytes()
        if len(patched) != length:
            raise ValueError('Boot partition length changed')
        root_off, root_length, root_patched = rootfs_patch(image, td, mac, disable_optional)
        if root_off < off + length:
            raise ValueError('Boot and root partition ranges overlap')
        swap = make_swap(td)
        swap_off=SWAP_START*512
        swap_end=swap_off+SWAP_SECTORS*512
        with swap.open('rb') as sw:
            image[swap_off:swap_end]=sw.read()
        with dest.open('xb') as out:
            out.write(image[:off]); out.write(patched)
            out.write(image[off+length:root_off]); out.write(root_patched)
            out.write(image[root_off+root_length:])
        print('Output:',dest,'bytes=',dest.stat().st_size)
        print('SHA256:',hashlib.sha256(dest.read_bytes()).hexdigest())
        print('MBR partitions 2-4 prepared; partition 1 intentionally absent.')
        print('After flashing, create partition 1 manually with fdisk, then mkfs.ext4.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True, help='Locally downloaded factory .bin or .bin.gz')
    ap.add_argument('--output', type=Path, default=Path('openwrt-19.07.10-DNS313-A2.bin'))
    a = ap.parse_args()
    source = a.input
    if not source.is_file() or a.output.exists():
        raise ValueError("Input must exist and output must not exist")
    mac = choose_mac()
    while True:
        answer = input('Disable optional services and unused modules? [Y/n]: ').strip().lower()
        if answer in ('n', 'no', 'н', 'нет'):
            disable_optional = False
            break
        if answer in ('', 'y', 'yes', 'д', 'да'):
            disable_optional = True
            break
        print('Please answer y or n.')
    print('Optional startup cleanup:', 'enabled' if disable_optional else 'disabled')
    prepare(source, a.output, mac, disable_optional)

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as e:
        raise SystemExit(f'ERROR: {e}')
