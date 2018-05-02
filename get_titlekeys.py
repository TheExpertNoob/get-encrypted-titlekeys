import os, sys
from struct import unpack as up, pack as pk
from binascii import unhexlify as uhx, hexlify as hx
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib

# Note: Insert correct RSA kek here, or disable correctness enforcement.
enforce_rsa_kek_correctneess = True
rsa_kek = uhx('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')

def safe_open(path, mode):
    import os
    dn = os.path.split(path)[0]
    try: 
        os.makedirs(dn)
    except OSError:
        if not os.path.isdir(dn):
            raise
    except WindowsError:
        if not os.path.isdir(dn):
            raise
    return open(path, mode)
    
def hex2ctr(x):
    return Counter.new(128, initial_value=int(x, 16))

def b2ctr(x):
    return Counter.new(128, initial_value=int(hx(x), 16))
    
def read_at(fp, off, len):
    fp.seek(off)
    return fp.read(len)

def read_u8(fp, off):
    return up('<B', read_at(fp, off, 1))[0]

def read_u16(fp, off):
    return up('<H', read_at(fp, off, 2))[0]

def read_u32(fp, off):
    return up('<I', read_at(fp, off, 4))[0]

def read_u64(fp, off):
    return up('<Q', read_at(fp, off, 8))[0]

def read_str(fp, off, l):
    if l == 0:
        return ''
    s = read_at(fp, off, l)
    if '\0' in s:
        s = s[:s.index('\0')]
    return s

def sxor(x, y):
    return ''.join([chr(ord(a) ^ ord(b)) for a,b in zip(x,y)])
    
def MGF1(seed, mask_len, hash=hashlib.sha256):
    mask = ''
    i = 0
    while len(mask) < mask_len:
        mask += hash(seed + pk('>I', i)).digest()
        i += 1
    return mask[:mask_len]

def get_rsa_keypair(cal0):
    if read_at(cal0, 0, 4) != 'CAL0':
        print 'Invalid CAL0 magic!'
        sys.exit(1)
    if read_at(cal0, 0x20, 0x20) != hashlib.sha256(read_at(cal0, 0x40, read_u32(cal0, 0x8))).digest():
        print 'Invalid CAL0 hash!'
        sys.exit(1)
    dec = AES.new(rsa_kek, AES.MODE_CTR, counter=b2ctr(read_at(cal0, 0x3890, 0x10))).decrypt(read_at(cal0, 0x38A0, 0x230))
    D = int(hx(dec[:0x100]), 0x10)
    N = int(hx(dec[0x100:0x200]), 0x10)
    E = int(hx(dec[0x200:0x204]), 0x10)
    if E != 0x10001:
        print '[WARN]: Public Exponent is not 65537. rsa_kek is probably wrong.'
    if pow(pow(0xCAFEBABE, D, N), E, N) != 0xCAFEBABE:
        print 'Failed to verify ETicket RSA keypair!'
        print 'Decrypted key was %s' % hx(dec)
        sys.exit(1)
    return (E, D, N)
    
def extract_titlekey(S, kp):
    E, D, N = kp
    M = uhx('%0512X' % pow(S, D, N))
    M = M[0] + sxor(M[1:0x21], MGF1(M[0x21:], 0x20)) + sxor(M[0x21:], MGF1(sxor(M[1:0x21], MGF1(M[0x21:], 0x20)), 0xDF))
    pref, salt, DB = M[0], M[1:0x21], M[0x21:]
    if pref != '\x00':
        return None
    label_hash, DB = DB[:0x20], DB[0x20:]
    if label_hash != uhx('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'):
        return None
    for i in xrange(1, len(DB)):
        if DB.startswith('\x00'*i + '\x01'):
            return DB[i+1:]
    return None
    
    
def get_titlekeys(tik, tik_size, kp):
    if tik_size & 0x3FF:
        print 'Invalid ticket binary!'
        sys.exit(1)
    num_tiks = tik_size >> 10
    for i in xrange(num_tiks):
        ofs = i << 10
        CA = read_at(tik, ofs + 0x140, 4)
        if CA == '\x00'*4:
            continue
        if CA != 'Root':
            print 'Unknown Ticket verifier: %s' % read_str(tik, ofs + 0x140, 0x40)
        tkey_block = read_at(tik, ofs + 0x180, 0x100)
        if tkey_block[0x10:] == '\x00'*0xF0:
            # Common Ticket
            titlekey = tkey_block[:0x10]
        else:
            # Personalized Ticket
            titlekey = extract_titlekey(int(hx(tkey_block), 16), kp)
        if titlekey is not None:
            print 'Ticket %d:' % i
            print '    Rights ID: %s' % hx(read_at(tik, ofs + 0x2A0, 0x10))
            print '    Title ID:  %s' % hx(read_at(tik, ofs + 0x2A0, 8))
            print '    Titlekey:  %s' % hx(titlekey)
    return

def main(argc, argv):
    if argc != 3:
        print 'Usage: %s CAL0 ticket.bin' % argv[0]
        return 1
    if enforce_rsa_kek_correctneess and hashlib.sha256(rsa_kek).hexdigest().upper() != '46CCCF288286E31C931379DE9EFA288C95C9A15E40B00A4C563A8BE244ECE515':
        print 'Error: rsa_kek is incorrect (hash mismatch detected)'
        print 'Please insert the correct rsa_kek at the top of the script.'
        return 1
    try:
        cal0 = open(argv[1], 'rb')
        kp = get_rsa_keypair(cal0)
        cal0.close()
    except:
        print 'Failed to open %s!' % argv[1]
        return 1
    try:
        tik = open(argv[2], 'rb')
        get_titlekeys(tik, os.path.getsize(argv[2]), kp)
        tik.close()
    except:
        print 'Failed to open %s!' % argv[2]
        return 1
    print 'Done!'
    return 0

if __name__=='__main__':
    sys.exit(main(len(sys.argv), sys.argv))
