#!/usr/bin/env python3

## Parser for the mysterious RICH header added by MSVC to PE files.
## Use as library or standalone tool.
## Version 0.3, by kirschju.re
## Version History:
##   0.1 Initial release
##   0.2 Add original name database for product ids
##   0.3 Add extra error checking during parsing

import sys, struct

try:
    import prodids
    have_pids = True
except:
    print("[.] Could not find product ID database.")
    have_pids = False

SIZE_DOS_HEADER = 0x40
POS_E_LFANEW = 0x3c

u32 = lambda x: struct.unpack("<I", x)[0]
p32 = lambda x: struct.pack("<I", x)
rol32 = lambda v, n: ((v << (n & 0x1f)) & 0xffffffff) | (v >> (32 - (n & 0x1f)))

def parse(fname):

    ## If the header is not within the first 4k bytes, something really strange
    ## is going on here ...
    try:
        dat = bytearray(open(fname, 'rb').read()[:0x1000])
    except:
        return {'err': -1}

    ## Do basic sanity checks on the PE
    if len(dat) < SIZE_DOS_HEADER:
        return {'err': -2}

    if dat[0:][:2] != b'MZ':
        return {'err': -3}

    e_lfanew = u32(dat[POS_E_LFANEW:][:4])

    if e_lfanew + 1 > len(dat):
        return {'err': -4}

    if dat[e_lfanew:][:2] != b'PE':
        return {'err': -5}

    ## IMPORTANT: Do not assume the data to start at 0x80, this is not always
    ## the case (modified DOS stub). Instead, start searching backwards for
    ## 'Rich', stopping at the end of the DOS header.
    rich = 0
    for rich in range(e_lfanew, SIZE_DOS_HEADER, -1):
        if dat[rich:][:4] == b'Rich':
            break

    if rich <= SIZE_DOS_HEADER:
        return {'err': -6}

    ## We found a valid 'Rich' signature in the header from here on
    csum = u32(dat[rich + 4:][:4])

    ## xor backwards with csum until either 'DanS' or end of the DOS header,
    ## inverse the list to get original order
    upack = [ u32(dat[i:][:4]) ^ csum for i in range(rich - 4, SIZE_DOS_HEADER, -4) ][::-1]
    if u32(b'DanS') not in upack:
        return {'err': -7}

    upack = upack[upack.index(u32(b'DanS')):]
    dans = e_lfanew - len(upack) * 4 - (e_lfanew - rich)

    ## DanS is _always_ followed by three zero dwords
    if not all([upack[i] == 0 for i in range(1, 4)]):
        return {'err': -8}

    upack = upack[4:]

    if len(upack) & 1:
        return {'err': -9}

    cmpids = []

    ## Bonus feature: Calculate and check the checksum csum
    chk = dans
    for i in range(dans):
        ## Mask out the e_lfanew field as it's not initialized at checksum
        ## calculation time
        if i in range(0x3c, 0x40):
            continue
        chk += rol32(dat[i], i)

    for i in range(0, len(upack), 2):
        cmpids.append({
            'mcv': (upack[i + 0] >>  0) & 0xffff,
            'pid': (upack[i + 0] >> 16) & 0xffff,
            'cnt': (upack[i + 1] >>  0)
        })
        chk += rol32(upack[i + 0], upack[i + 1])

    ## Truncate calculated checksum to 32 bit
    chk &= 0xffffffff

    return {'err': 0, 'cmpids': cmpids, 'csum_calc': chk, 'csum_file': csum,
            'offset': dans}

def err2str(code):
    if code == -1:
        return "Could not open file."
    elif code == -2:
        return "File too small to contain required headers."
    elif code == -3:
        return "MZ signature not found."
    elif code == -4:
        return "MZ Header pointing beyond end of file."
    elif code == -5:
        return "PE signature not found."
    elif code == -6:
        return "Rich signature not found. This file probably has no Rich header."
    elif code == -7:
        return "DanS signature not found. Rich header corrupt."
    elif code == -8:
        return "Wrong header padding behind DanS signature. Rich header corrupt."
    elif code == -9:
        return "Rich data length not a multiple of 8. Rich header corrupt."
    else:
        return "--- NO ERROR DESCRIPTION ---"

def pprint_cmpids(cmpids):
    print("-" * (20 + 16 + 16 + 32 + 39))
    print("{:>20s}{:>16s}{:>16s}{:>32s}{:>39s}".format("Compiler Patchlevel", "Product ID",
        "Count", "MS Internal Name", "Visual Studio Release"))
    print("-" * (20 + 16 + 16 + 32 + 39))

    cnt = 0
    for e in cmpids:
        print("{:>20s}{:>16s}{:>16s}{:>32s}{:>39s}".format(
            "{:5d}".format(e['mcv']),
            "0x{:04x}".format(e['pid']),
            "0x{:08x}".format(e['cnt']),
            prodids.int_names[e['pid']] if have_pids else '<unknown>',
            "{:18s} ({})".format(*prodids.vs_version(e['pid'])) if have_pids else '<unknown>'))
        vs, num = prodids.vs_version(e['pid'])
        num = int(float(num) * 100)
    print("-" * (20 + 16 + 16 + 32 + 39))

def pprint_header(data):
    pprint_cmpids(data['cmpids'])
    if rich['csum_calc'] == rich['csum_file']:
        print("\x1b[32mChecksums match! (0x{:08x})".format(rich['csum_calc']))
    else:
        print("\x1b[33mChecksum corrupt! (calc 0x{:08x}, file "
        "0x{:08x})".format(rich['csum_calc'], rich['csum_file']))
    print("\x1b[39m" + "-" * (20 + 16 + 16 + 32 + 39))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <pe-files>".format(sys.argv[0]))
        sys.exit(-1)
    for arg in sys.argv[1:]:
        rich = parse(arg)
        if rich['err'] < 0:
            print("\x1b[33m[-] " + err2str(rich['err']) + "\x1b[39m")
            sys.exit(rich['err'])

        pprint_header(rich)
