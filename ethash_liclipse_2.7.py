'''
Created on Apr 24, 2021

@author: OGDCL
'''


WORD_BYTES = 4                    # bytes in word
DATASET_BYTES_INIT = 2**30        # bytes in dataset at genesis
DATASET_BYTES_GROWTH = 2**23      # dataset growth per epoch
CACHE_BYTES_INIT = 2**24          # bytes in cache at genesis
CACHE_BYTES_GROWTH = 2**17        # cache growth per epoch
CACHE_MULTIPLIER=1024             # Size of the DAG relative to the cache
EPOCH_LENGTH = 30000              # blocks per epoch
ETC_EPOCH_LENGTH = 60000              # ETC blocks per epoch
MIX_BYTES = 128                   # width of mix
HASH_BYTES = 64                   # hash length in bytes
DATASET_PARENTS = 256             # number of parents of each dataset element
CACHE_ROUNDS = 3                  # number of rounds in cache production
ACCESSES = 64                     # number of accesses in hashimoto loop
ETCHASH_FORK_BLOCK = 11700000 
activationBlock = ETCHASH_FORK_BLOCK
import sha3, copy

# Assumes little endian bit ordering (same as Intel architectures)
def decode_int(s):
    #print("decode_int passed argument = %s"%s)
    t1 = s[::-1].encode('hex')
    #print("decode_int s[::-1].encode('hex') = %s"%t1)
    t2 = int(t1,16)
    #print("decode_int t2 = %x"%t2)
    return int(s[::-1].encode('hex'), 16) if s else 0

def encode_int(s):
    a = "%x" % s
    return '' if s == 0 else ('0' * (len(a) % 2) + a).decode('hex')[::-1]

def zpad(s, length):
    return s + '\x00' * max(0, length - len(s))

def serialize_hash(h):
    # here "h' is list
    print("serialize_hash h = %s"%h)
    return ''.join([zpad(encode_int(x), 4) for x in h])

def deserialize_hash(h):
    #print("deserialize_hash h is hex values in string format = %s"%h)
    #print("deserialize_hash length of h %d"%len(h))
    
    return [decode_int(h[i:i+WORD_BYTES]) for i in range(0, len(h), WORD_BYTES)]

def hash_words(h, sz, x):
    #print("hash_word h = %s"%h)
    #print("hash_word sz = %d"%sz)
    #print("hash_word x = %s"%x)
    if isinstance(x, list):
        print("hash_word x is instance of list Calling serialize_hash" )
        x = serialize_hash(x)
    y = h(x)
    # y = sha3_512(x).digest()
    print("hash_word y (digest, hash) Will call  deserialize_hash on this digest, hash %s "%y)
    return deserialize_hash(y)

def serialize_cache(ds):
    return ''.join([serialize_hash(h) for h in ds])

serialize_dataset = serialize_cache

# sha3 hash function, outputs 64 bytes
def sha3_512(x):
    return hash_words(lambda v: sha3.sha3_512(v).digest(), 64, x)

def sha3_256(x):
    return hash_words(lambda v: sha3.sha3_256(v).digest(), 32, x)

def xor(a, b):
    return a ^ b

def isprime(x):
    for i in range(2, int(x**0.5)):
        if x % i == 0:
            return False
    return True



# Latest Block Number 25th April 2021 12306444 
#


def get_cache_size(block_number):
    sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number // EPOCH_LENGTH)
    print("get_cache_size block_number = %d, sz = %d \n"%(block_number,sz))
   
    sz -= HASH_BYTES
    while not isprime(sz / HASH_BYTES):
        sz -= 2 * HASH_BYTES
        
    print("final sz = %d"%sz)
    return sz

def get_etc_cache_size(block_number):
    #cacheInitBytes + cacheGrowthBytes*epoch - hashBytes
    sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number // ETC_EPOCH_LENGTH)
    sz -= HASH_BYTES
    while not isprime(sz / HASH_BYTES):
        sz -= 2 * HASH_BYTES
        
    return sz

def get_full_size(block_number):
    sz = DATASET_BYTES_INIT + DATASET_BYTES_GROWTH * (block_number // EPOCH_LENGTH)
    sz -= MIX_BYTES
    while not isprime(sz / MIX_BYTES):
        sz -= 2 * MIX_BYTES
    return sz


def mkcache(cache_size, seed):
    n = cache_size // HASH_BYTES
    print("mkcache n = %d"%n)
    # Sequentially produce the initial dataset
    o = [sha3_512(seed)]
    print("mkcache initial size of o  %d "%len(o))
    print("mkcache type of o  %s "%o)
    for i in range(1, n):
        o.append(sha3_512(o[-1]))

    # Use a low-round version of randmemohash
    for _ in range(CACHE_ROUNDS):
        for i in range(n):
            v = o[i][0] % n
            o[i] = sha3_512(map(xor, o[(i-1+n) % n], o[v]))

    return o


FNV_PRIME = 0x01000193

def fnv(v1, v2):
    return ((v1 * FNV_PRIME) ^ v2) % 2**32


def calc_dataset_item(cache, i):
    n = len(cache)
    r = HASH_BYTES // WORD_BYTES
    # initialize the mix
    mix = copy.copy(cache[i % n])
    mix[0] ^= i
    mix = sha3_512(mix)
    # fnv it with a lot of random cache nodes based on i
    for j in range(DATASET_PARENTS):
        cache_index = fnv(i ^ j, mix[j % r])
        mix = map(fnv, mix, cache[cache_index % n])
    return sha3_512(mix)


def calc_dataset(full_size, cache):
    return [calc_dataset_item(cache, i) for i in range(full_size // HASH_BYTES)]




# Main Loop



def hashimoto(header, nonce, full_size, dataset_lookup):
    n = full_size / HASH_BYTES
    w = MIX_BYTES // WORD_BYTES
    mixhashes = MIX_BYTES / HASH_BYTES
    # combine header+nonce into a 64 byte seed
    s = sha3_512(header + nonce[::-1])
    # start the mix with replicated s
    mix = []
    for _ in range(MIX_BYTES / HASH_BYTES):
        mix.extend(s)
    # mix in random dataset nodes
    for i in range(ACCESSES):
        p = fnv(i ^ s[0], mix[i % w]) % (n // mixhashes) * mixhashes
        newdata = []
        for j in range(MIX_BYTES / HASH_BYTES):
            newdata.extend(dataset_lookup(p + j))
        mix = map(fnv, mix, newdata)
    # compress mix
    cmix = []
    for i in range(0, len(mix), 4):
        cmix.append(fnv(fnv(fnv(mix[i], mix[i+1]), mix[i+2]), mix[i+3]))
    return {
        "mix digest": serialize_hash(cmix),
        "result": serialize_hash(sha3_256(s+cmix))
    }

def hashimoto_light(full_size, cache, header, nonce):
    return hashimoto(header, nonce, full_size, lambda x: calc_dataset_item(cache, x))

def hashimoto_full(full_size, dataset, header, nonce):
    return hashimoto(header, nonce, full_size, lambda x: dataset[x])



def mine(full_size, dataset, header, difficulty):
    # zero-pad target to compare with hash on the same digit
    target = zpad(encode_int(2**256 // difficulty), 64)[::-1]
    from random import randint
    nonce = randint(0, 2**64)
    while hashimoto_full(full_size, dataset, header, nonce) > target:
        nonce = (nonce + 1) % 2**64
    return nonce


# Defining the Seed Hash

def get_seedhash(block):
    s = '\x00' * 32
    print('size of s = %d'%(len(s)))
    for i in range(block // ETC_EPOCH_LENGTH):
        s = serialize_hash(sha3_256(s))
    return s


def get_epoch_seedhash(epoch):
    s = '\x00' * 32
    
    print('size of s = %d'%(len(s)))
    for i in range(epoch):
        s = serialize_hash(sha3_256(s))
    return s


def main():
    #print("The value of __name__ is:", repr(__name__))
    #print("cache size of latest block %d"%(get_cache_size(12306444)))
   
    print("Ethereum Classic Current cache size %d"%(get_etc_cache_size(12665669)))
    
    s1 = get_seedhash(12665669)    
    s2 = get_epoch_seedhash(211)
    
    cache_size = get_etc_cache_size(12665669)
    mkcache(cache_size,s2)
    
    print("seed-hash from block %s"%s1)
    print("seed-hash from epock %s"%s2)
    
    
    # print("sha3_256 value AAAA = %s "%sha3_256("AAAA"))
    # print("sha3_512 value AAAA = %s "%sha3_512("AAAA"))
    #print("hash value = %x, serialize_hash = %x %s"%(hash_value, serialize_hash(hash_value), serialize_hash(hash_value)))
    

if __name__ == "__main__":
    main()
