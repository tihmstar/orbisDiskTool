//
//  OrbisDiskFuse.hpp
//  orbisDiskTool
//
//  Created by tihmstar on 13.12.25.
//

#ifndef OrbisDiskFuse_hpp
#define OrbisDiskFuse_hpp

#include "OrbisInternalDisk.hpp"

#include <memory>
#include <iostream>

struct fuse;
struct fuse_chan;

namespace orbisDiskTool {

class OrbisDiskFuse {
    std::shared_ptr<OrbisInternalDisk> _disk;
    std::string _mountpoint;
    
    struct fuse *_fuse;
    struct fuse_chan *_ch;
public:
    OrbisDiskFuse(std::shared_ptr<OrbisInternalDisk> disk, const char *mountPath);
    ~OrbisDiskFuse();
    
    void loopSession();
    void stopSession();
};

}

#endif /* OrbisDiskFuse_hpp */
