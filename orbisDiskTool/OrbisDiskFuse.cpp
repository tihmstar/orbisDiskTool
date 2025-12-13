//
//  OrbisDiskFuse.cpp
//  orbisDiskTool
//
//  Created by tihmstar on 13.12.25.
//

#include "OrbisDiskFuse.hpp"

#include <libgeneral/macros.h>

#ifdef HAVE_FUSE
#   define FUSE_USE_VERSION 28
#   include <fuse/fuse.h>
#endif

#define VIRT_FILENAME "orbisdisk-file"
#define VIRT_FILERELATIVEPATH "/" VIRT_FILENAME

using namespace orbisDiskTool;

#ifdef HAVE_FUSE
static int fs_getattr(const char *path, struct stat *stbuf) noexcept{
     struct fuse_context *ctx = fuse_get_context();
     OrbisInternalDisk *disk = (OrbisInternalDisk*)ctx->private_data;
     int res = 0;

     if(!path || !stbuf)
         return -EINVAL;

     memset(stbuf, 0, sizeof(struct stat));
     if(strcmp(path, "/") == 0) {
         stbuf->st_mode = S_IFDIR | 0555;
         stbuf->st_nlink = 2;
     } else if(strcmp(path, VIRT_FILERELATIVEPATH) == 0) {
         mode_t m = !disk->isWriteable() ? 0444 : 0666;
         stbuf->st_mode = S_IFREG | m;
         stbuf->st_nlink = 1;
         stbuf->st_size = disk->getDataSize();
     } else {
         res = -ENOENT;
     }

     return res;
 }

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) noexcept{
    (void) offset;
    (void) fi;

    if(!path || !buf || !filler)
        return -EINVAL;

    if(strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, VIRT_FILENAME, NULL, 0);

    return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi) noexcept{
    struct fuse_context *ctx = fuse_get_context();
    OrbisInternalDisk *disk = (OrbisInternalDisk*)ctx->private_data;
    if(!path || !fi)
        return -EINVAL;

    if (strcmp(path, VIRT_FILERELATIVEPATH) != 0)
        return -ENOENT;


    if(!disk->isWriteable()){
        if((fi->flags & O_ACCMODE) != O_RDONLY)
            return -EACCES;
    } else {
        if((fi->flags & O_ACCMODE) != O_RDWR   &&
           (fi->flags & O_ACCMODE) != O_RDONLY &&
           (fi->flags & O_ACCMODE) != O_WRONLY)
            return -EACCES;
    }
    
    return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) noexcept{
    struct fuse_context *ctx = fuse_get_context();
    OrbisInternalDisk *disk = (OrbisInternalDisk*)ctx->private_data;
    if(!path || !buf)
        return -EINVAL;

    if(strcmp(path, VIRT_FILERELATIVEPATH) != 0) {
        debug("Unknown entry requested: '%s'\n", path);
        return -ENOENT;
    }
    try {
        return (int)disk->read(buf, size, offset);
    } catch (tihmstar::exception &e) {
        e.dump();
        return -EIO;
    }
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) noexcept{
    struct fuse_context *ctx = fuse_get_context();
    OrbisInternalDisk *disk = (OrbisInternalDisk*)ctx->private_data;
    // Check parameters
    if(!path || !buf)
        return -EINVAL;

    if(strcmp(path, VIRT_FILERELATIVEPATH) != 0) {
        debug("Unknown entry requested: '%s'\n", path);
        return -ENOENT;
    }
    try {
        return (int)disk->write(buf, size, offset);
    } catch (tihmstar::exception &e) {
        e.dump();
        return -EIO;
    }
}

static const struct fuse_operations orbisDiskFuse_ops = {
    .getattr = fs_getattr,
    .open    = fs_open,
    .read    = fs_read,
    .write   = fs_write,
    .readdir = fs_readdir,
};
#endif


#pragma mark OrbisDiskFuse
OrbisDiskFuse::OrbisDiskFuse(std::shared_ptr<OrbisInternalDisk> disk, const char *mountPath)
: _disk(disk)
, _fuse(NULL), _ch(NULL)
{
#ifndef HAVE_FUSE
    reterror("Built without FUSE support!");
#else
    retassure(mountPath, "Error no mount point specified!");
    _mountpoint = mountPath;

    int vers = fuse_version();
    if (vers < FUSE_USE_VERSION) {
        reterror("Fuse version too low, expected %d but got %d",FUSE_USE_VERSION,vers);
    }
    info("Got FUSE version %d",vers);

    struct fuse_args args = {};
    cleanup([&]{
        fuse_opt_free_args(&args);
    });

    args = FUSE_ARGS_INIT(0, nullptr);
    assure(!fuse_opt_add_arg(&args, "FIRST_ARG_IS_IGNORED"));

    if (!disk->isWriteable()){
        assure(!fuse_opt_add_arg(&args, "-r"));
    }

    {
        std::string imgNameOpt = "fsname=OrbisDiskFuse";
        assure(!fuse_opt_add_arg(&args, "-o"));
        assure(!fuse_opt_add_arg(&args, imgNameOpt.c_str()));
    }

#if !defined(__linux__)
    {
        std::string imgNameOpt = "volname=OrbisDiskFuse";
        assure(!fuse_opt_add_arg(&args, "-o"));
        assure(!fuse_opt_add_arg(&args, imgNameOpt.c_str()));
    }
#endif //!defined(__linux__)

#ifdef __APPLE__
    assure(!fuse_opt_add_arg(&args, "-o"));
    if (!disk->isWriteable()){
        assure(!fuse_opt_add_arg(&args, "rdonly,local"));
    }else{
        assure(!fuse_opt_add_arg(&args, "local"));
    }
#endif

    {
        debug("Trying to mount at %s",_mountpoint.c_str());
        retassure(_ch = fuse_mount(_mountpoint.c_str(), &args), "Failed to mount");
        retassure(_fuse = fuse_new(_ch, &args, &orbisDiskFuse_ops, sizeof(orbisDiskFuse_ops), disk.get()), "Failed to create FUSE session");
    }
    info("Mounted at %s",_mountpoint.c_str());
#endif
}

OrbisDiskFuse::~OrbisDiskFuse(){
#ifdef HAVE_FUSE
    if (_ch) {
        fuse_unmount(_mountpoint.c_str(), _ch); _ch = NULL;
    }
    safeFreeCustom(_fuse, fuse_destroy);
#endif
}

#pragma mark OrbisDiskFuse private

#pragma mark OrbisDiskFuse public
void OrbisDiskFuse::loopSession(){
#ifndef HAVE_FUSE
    reterror("Built without FUSE support!");
#else
    struct fuse_session *se = NULL;
    cleanup([&]{
        safeFreeCustom(se, fuse_remove_signal_handlers);
    });
    if ((se = fuse_get_session(_fuse))) {
        if (fuse_set_signal_handlers(se)){
            se = NULL;
            error("Failed to set FUSE sighandlers");
        }
    }
    fuse_loop_mt(_fuse);
#endif
}

void OrbisDiskFuse::stopSession(){
#ifndef HAVE_FUSE
    reterror("Built without FUSE support!");
#else
    fuse_exit(_fuse);
#endif
}
