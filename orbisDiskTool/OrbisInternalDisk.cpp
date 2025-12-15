//
//  OrbisInternalDisk.cpp
//  orbisDiskTool
//
//  Created by tihmstar on 12.12.25.
//

#include "OrbisInternalDisk.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Mem.hpp>
#include <libgeneral/Event.hpp>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <thread>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#ifdef HAVE_SYS_DISK_H
#   include <sys/disk.h>
#endif //HAVE_SYS_DISK_H

#define INNER_SECTOR_SIZE 0x200
#define OUTER_SECTOR_SIZE 0x10000

#define PARTITION_LAYOUT_SECTOR_INDEX 0
#define PARTITION_LAYOUT_SIZE 0x4400

#define METADATA_SECTOR_INDEX 1
#define METADATA_EXPECTED_MAGIC "M2Strg::MetaData"

#define DATA_START_SECTOR_INDEX 2

struct OrbisMeta {
    char magic[0x10];               // 0x00     //M2Strg::MetaData
    uint32_t version;               // 0x10     //1
    uint8_t _pad1[0xc];             // 0x14
    uint8_t seed[0x20];             // 0x20
    uint8_t unique_id[0x10];        // 0x40
    uint8_t passphrase[0x20];       // 0x50
    uint8_t _pad2[0x170];           // 0x70
    uint8_t digest[0x20];           // 0x1E0
};

using namespace orbisDiskTool;

#pragma mark OrbisInternalDisk
OrbisInternalDisk::OrbisInternalDisk(const char *path, bool writeable)
: _writeable(writeable)
, _fd(-1)
, _mem(NULL), _memsize(0)
, _diskKeys{}
{    
    retassure((_fd = open(path, writeable ? O_RDWR : O_RDONLY)) != -1, "Failed to open=%s",path);
    {
        struct stat st = {};
        retassure(!fstat(_fd, &st), "Failed to stat file");
        
        if (S_ISBLK(st.st_mode)){
            uint64_t count = 0;
            uint64_t bsize = 0;
#ifdef DKIOCGETBLOCKCOUNT
            retassure(!ioctl(_fd, DKIOCGETBLOCKCOUNT, &count), "Failed to get blk count");
#endif
#ifdef DKIOCGETBLOCKSIZE
            retassure(!ioctl(_fd, DKIOCGETBLOCKSIZE, &bsize), "Failed to get blk size");
#endif
            debug("Got blkcnt=0x%llx",count);
            debug("Got blksize=0x%llx",bsize);
            _memsize = count * bsize;
        }else{
            _memsize = st.st_size;
        }
    }
    retassure(_memsize, "Failed to detect image size!");
    if ((_mem = (uint8_t*)mmap(NULL, _memsize, PROT_READ | (writeable ? PROT_WRITE : 0), MAP_FILE | (writeable ? MAP_SHARED : MAP_PRIVATE), _fd, 0)) == MAP_FAILED){
        _mem = NULL;
        warning("Failed to mmap '%s', using fallback strategy",path);
    }
}

OrbisInternalDisk::~OrbisInternalDisk(){
    if (_mem && _memsize){
        munmap(_mem, _memsize); _mem = NULL; _memsize = 0;
    }
    safeClose(_fd);
}

#pragma mark OrbisInternalDisk private
size_t OrbisInternalDisk::aes_run_xts_block(const void *inbuf_, void *outbuf_, size_t bufSize, const AES_KEY *tweak, const AES_KEY *key, uint64_t index, bool doEncrypt){
    const uint8_t *inbuf = (const uint8_t *)inbuf_;
    uint8_t *outbuf = (uint8_t *)outbuf_;

    uint8_t tweakBuf[0x10] = {};
    size_t didProcess = 0;
    
    if (bufSize > OUTER_SECTOR_SIZE) bufSize = OUTER_SECTOR_SIZE;
    
    memcpy(tweakBuf, &index, sizeof(index));
    AES_encrypt(tweakBuf, tweakBuf, tweak);

    for (; didProcess+0x10 <= bufSize; didProcess+=0x10) {
        uint64_t *in = (uint64_t*)&inbuf[didProcess];
        uint64_t *out = (uint64_t*)&outbuf[didProcess];
        uint64_t *t = (uint64_t*)tweakBuf;
        out[0] = in[0] ^ t[0];
        out[1] = in[1] ^ t[1];
        AES_ecb_encrypt((const unsigned char *)out, (unsigned char *)out, key, doEncrypt);
        out[0] ^= t[0];
        out[1] ^= t[1];

        //update tweak
        uint8_t carry = t[1] >> 63;
        t[1] = (t[1] << 1) | (t[0] >> 63);
        t[0] = (t[0] << 1) ^ (carry*0x87);
    }

    return didProcess;
}


#pragma mark OrbisInternalDisk public
void OrbisInternalDisk::setMetaDataKey(const void *key, size_t keySize){
    assure(!AES_set_encrypt_key((const unsigned char *)key, 8*keySize, &_diskKeys[kDiskKeyIDMetaKeyEnc]));
    assure(!AES_set_decrypt_key((const unsigned char *)key, 8*keySize, &_diskKeys[kDiskKeyIDMetaKeyDec]));
}

void OrbisInternalDisk::setMetaTweakKey(const void *key, size_t keySize){
    assure(!AES_set_encrypt_key((const unsigned char *)key, 8*keySize, &_diskKeys[kDiskKeyIDMetaTweakEnc]));
}

void OrbisInternalDisk::setDataKeygenKey(const void *key, size_t keySize){
    retassure(_memsize >= METADATA_SECTOR_INDEX * OUTER_SECTOR_SIZE + INNER_SECTOR_SIZE, "Image too small");

    OrbisMeta meta = {};
    uint8_t realDgst[SHA256_DIGEST_LENGTH] = {};
    
    retassure(_diskKeys[kDiskKeyIDMetaTweakEnc].rounds, "Metadata tweak not set!");
    retassure(_diskKeys[kDiskKeyIDMetaKeyDec].rounds, "Metadata key not set!");
    retassure(keySize, "Data key not set!");

    retassure(readDataBlock(&meta, sizeof(meta), METADATA_SECTOR_INDEX) == sizeof(meta), "Failed to decrypt metadata");
#define dumpHex(v) for (int i=0; i<sizeof(v); i++) printf("%02x",v[i]); printf("\n");
    printf("Magic:      '%.*s'\n",(int)sizeof(meta.magic),meta.magic);
    printf("Versin:     0x%x\n",meta.version);
    printf("seed:       "); dumpHex(meta.seed);
    printf("unique_id:  "); dumpHex(meta.unique_id);
    printf("passphrase: "); dumpHex(meta.passphrase);
    printf("digest:     "); dumpHex(meta.digest);
    retassure(!memcmp(meta.magic, METADATA_EXPECTED_MAGIC, sizeof(meta.magic)), "Bad magic '%.*s'",sizeof(meta.magic),meta.magic);
    retassure(meta.version == 1, "Unexpected meta version 0x%x",meta.version);
    
    SHA256((const unsigned char *)&meta, offsetof(OrbisMeta, digest), realDgst);
    printf("realDGST:   "); dumpHex(realDgst);
    retassure(!memcmp(meta.digest, realDgst, sizeof(realDgst)), "Meta dgst mismatch!",sizeof(meta.magic),meta.magic);
    
    {
        uint8_t dataKeyBuf[SHA256_DIGEST_LENGTH] = {};
        unsigned int dataKeyBufLen = sizeof(dataKeyBuf);
        HMAC(EVP_sha256(), key, keySize, meta.seed, sizeof(meta.seed), dataKeyBuf, &dataKeyBufLen);
        assure(!AES_set_encrypt_key((const unsigned char *)&dataKeyBuf[0], 8*0x10, &_diskKeys[kDiskKeyIDDataTweakEnc]));
        assure(!AES_set_encrypt_key((const unsigned char *)&dataKeyBuf[0x10], 8*0x10, &_diskKeys[kDiskKeyIDDataKeyEnc]));
        assure(!AES_set_decrypt_key((const unsigned char *)&dataKeyBuf[0x10], 8*0x10, &_diskKeys[kDiskKeyIDDataKeyDec]));
    }
#undef dumpHex
}

bool OrbisInternalDisk::isWriteable(){
    return _writeable;
}

uint64_t OrbisInternalDisk::getDataSize(){
    return _memsize;
}

uint64_t OrbisInternalDisk::getBlockSize(){
    return OUTER_SECTOR_SIZE;
}

size_t OrbisInternalDisk::readDataBlock(void *outbuf, size_t outbufSize, uint64_t index){
    retassure(OUTER_SECTOR_SIZE * index < _memsize, "Trying to access out of bounds index");

    if (outbufSize > OUTER_SECTOR_SIZE) outbufSize = OUTER_SECTOR_SIZE;

    uint8_t *ptr = NULL;
    if (_mem){
        ptr = &_mem[OUTER_SECTOR_SIZE * index];
        if (outbufSize > _memsize - (ptr - _mem)) outbufSize = _memsize - (ptr - _mem);
    }else{
        ptr = (uint8_t*)outbuf;
        ssize_t didread = pread(_fd, ptr, outbufSize, OUTER_SECTOR_SIZE * index);
        retassure(didread > 0, "Failed to pread data");
        outbufSize = didread;
    }
    
    if (index == 1) {
        return aes_run_xts_block(ptr, outbuf, outbufSize, &_diskKeys[kDiskKeyIDMetaTweakEnc], &_diskKeys[kDiskKeyIDMetaKeyDec], index, false);
    }else{
        return aes_run_xts_block(ptr, outbuf, outbufSize, &_diskKeys[kDiskKeyIDDataTweakEnc], &_diskKeys[kDiskKeyIDDataKeyDec], index, false);
    }
}

size_t OrbisInternalDisk::read(void *outbuf_, size_t size, uint64_t offset){
    uint8_t *outbuf = (uint8_t*)outbuf_;
    size_t ret = 0;
    
    tihmstar::Mem blk;
    
    while (size) {
        uint64_t curOffset = offset % OUTER_SECTOR_SIZE;
        uint64_t curIDX = offset / OUTER_SECTOR_SIZE;
        size_t curread = 0;
        
        if (curOffset) {
            blk.resize(OUTER_SECTOR_SIZE);
            curread = readDataBlock(blk.data(), blk.size(), curIDX);
            if (curread < curOffset) return 0;
            size_t curCopy = curread-curOffset;
            if (curCopy > size) curCopy = size;
            memcpy(outbuf, blk.data()+curOffset, curCopy);
            curread = curCopy;
            blk.resize(0);
        }else{
            curread = readDataBlock(outbuf, size, curIDX);
            if (!curread) break;
        }
        ret += curread;
        size -= curread;
        outbuf += curread;
        offset += curread;
    }
    return ret;
}

size_t OrbisInternalDisk::write(const void *inbuf, size_t size, uint64_t offset){
    reterror("Writing not implemented");
}

void OrbisInternalDisk::decryptImage(const char *outPath, uint16_t threads){
    int fdout = -1;
    uint8_t *mem = NULL;
    cleanup([&]{
        if (mem){
            munmap(mem, _memsize); mem = NULL;
        }
        safeClose(fdout);
    });
    if (!threads) threads = 1;

    retassure((fdout = open(outPath, O_RDWR | O_CREAT, 0644)) != -1, "Failed to open outfile '%s'",outPath);
    {
        struct stat st = {};
        retassure(!fstat(fdout, &st), "Failed to stat out file");
        if (st.st_size < _memsize) {
            debug("growing file to 0x%llx bytes",_memsize);
            uint8_t zero = 0;
            lseek(fdout, _memsize-1, SEEK_SET);
            ::write(fdout, &zero, 1);
            lseek(fdout, 0, SEEK_SET);
        }
    }
    retassure((mem = (uint8_t*)mmap(NULL, _memsize, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fdout, 0)) != MAP_FAILED, "Failed to mmap '%s'",outPath);

    uint64_t blkSize = getBlockSize();
    uint64_t cntBlocks = getDataSize()/blkSize;
    if (getDataSize() % blkSize) {
        cntBlocks++;
    }
    info("Decrypting %d blocks using %d threads",cntBlocks,threads);
    
    std::vector<std::thread> workers;
    std::atomic<uint64_t> decryptedBlocks{0};
    tihmstar::Event decryptBlockEvent;
    bool decryptionFailed = false;
    for (uint16_t i=0; i<threads; i++) {
        workers.push_back(std::thread([&](uint16_t tid){
            debug("[%2d] Worker started",tid);
            
            try {
                for (uint64_t blk = tid; !decryptionFailed && blk < cntBlocks; blk += threads) {
                    readDataBlock(&mem[blkSize*blk], blkSize, blk);
                    ++decryptedBlocks;
                    decryptBlockEvent.notifyAll();
                }
            } catch (tihmstar::exception &e) {
                e.dump();
                decryptionFailed = true;
            } catch (...){
                decryptionFailed = true;
            }
            
            debug("[%2d] Worker retired",tid);
        },i));
    }
    
    
    {
        time_t lastProgressUpdate = 0;
        uint64_t wevent = decryptBlockEvent.getNextEvent();
        info("Waiting for decryption to finish...");
        while (decryptedBlocks < cntBlocks) {
            time_t curtime = time(NULL);
            if (curtime - lastProgressUpdate >= 3) {
                lastProgressUpdate = curtime;
                info("[+] Decrypted 0x%llx out of 0x%llx blocks", (uint64_t)decryptedBlocks, cntBlocks);
            }
            decryptBlockEvent.waitForEvent(wevent);
            wevent = decryptBlockEvent.getNextEvent();
        }
    }
    
    for (auto &w : workers) {
        w.join();
    }
    
    retassure(!decryptionFailed, "decryption failed!");
    
    info("Done decrypting");
}
