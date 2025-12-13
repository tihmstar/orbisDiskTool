//
//  OrbisInternalDisk.hpp
//  orbisDiskTool
//
//  Created by tihmstar on 12.12.25.
//

#ifndef OrbisInternalDisk_hpp
#define OrbisInternalDisk_hpp

#include <openssl/aes.h>

#include <stdint.h>
#include <stddef.h>

namespace orbisDiskTool {

class OrbisInternalDisk {
private:
    enum DiskKeyID{
        kDiskKeyIDMetaKeyEnc = 0,
        kDiskKeyIDMetaKeyDec,
        kDiskKeyIDMetaTweakEnc,
        kDiskKeyIDDataKeyEnc,
        kDiskKeyIDDataKeyDec,
        kDiskKeyIDDataTweakEnc,
        
        kDiskKeyIDTotalNum
    };
private:
    bool _writeable;
    int _fd;
    uint8_t *_mem;
    size_t _memsize;
    
    AES_KEY _diskKeys[kDiskKeyIDTotalNum];
    
    size_t aes_run_xts_block(const void *inbuf, void *outbuf, size_t bufSize, const AES_KEY *tweak, const AES_KEY *key, uint64_t index, bool doEncrypt);
public:
    OrbisInternalDisk(const char *path, bool writeable = false);
    ~OrbisInternalDisk();
    
    void setMetaDataKey(const void *key, size_t keySize);
    void setMetaTweakKey(const void *key, size_t keySize);
    void setDataKeygenKey(const void *key, size_t keySize); //must be set after meta key/tweak were set
    
    bool isWriteable();
    uint64_t getDataSize();
    uint64_t getBlockSize();
    size_t readDataBlock(void *outbuf, size_t outbufSize, uint64_t index);
    size_t read(void *outbuf, size_t size, uint64_t offset);
    
    size_t write(const void *inbuf, size_t size, uint64_t offset);

    void decryptImage(const char *outPath, uint16_t threads = 0);
    
};

}

#endif /* OrbisInternalDisk_hpp */
