//
//  main.cpp
//  orbisDiskTool
//
//  Created by tihmstar on 11.12.25.
//

#include "OrbisInternalDisk.hpp"
#include "OrbisDiskFuse.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Mem.hpp>

#include <memory>

#include <getopt.h>

using namespace orbisDiskTool;

static struct option longopts[] = {
    { "help",               no_argument,        NULL, 'h' },
    { "decrypt",            required_argument,  NULL, 'd' },
    { "exteranl",           no_argument,        NULL, 'h' },
    { "input",              required_argument,  NULL, 'i' },
    { "threads",            required_argument,  NULL, 'j' },
    { "data-keygen-key",    required_argument,  NULL, 'k' },
    { "metadata-data-key",  required_argument,  NULL, 'm' },
    { "metadata-tweak-key", required_argument,  NULL, 't' },
    { "writeable",          no_argument,        NULL, 'w' },

    { "mount",              required_argument,  NULL,  0  },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf(
           "Usage: orbisDiskTool [OPTIONS]\n"
           "Encrypt/Decrypt/Mount orbis disk images\n\n"
           "  -h, --help\t\t\t\tprints usage information\n"
           "  -d, --decrypt <outpath>\t\toutput path for image decryption\n"
           "  -E, --external\t\t\t\tswitch to using extHDD ENV vars\n"
           "  -i, --input <path>\t\t\tinput file (or blockdevice)\n"
           "  -j, --thread <cnt>\t\t\tnumber of threads (for decryption)\n"
           "  -k, --data-keygen-key <key>\t\tdata-keygen-key in hexbytes (env: DATA_KEYGEN_KEY)\n"
           "  -m, --metadata-data-key <key>\t\tmetadata-data-key in hexbytes (env: METADATA_DATA_KEY  / EXT_METADATA_DATA_KEY)\n"
           "  -t, --metadata-tweak-key <key>\tmetadata-tweak-key in hexbytes (env: METADATA_TWEAK_KEY / EXT_METADATA_TWEAK_KEY)\n"
           "  -w, --writeable\t\t\topen image in write mode\n"
           "      --mount <path>\t\t\tpath to mount\n"
           "\n"
           );
}

tihmstar::Mem parseHex(const char *hexbytes){
    tihmstar::Mem ret;
    size_t len = strlen(hexbytes);
    retassure((len & 1) == 0, "hexstring is odd (%s)",hexbytes);

    while (len) {
        unsigned int t;
        retassure(sscanf(hexbytes,"%02x",&t) == 1, "Failed to parse hexstring (%s)",hexbytes);
        ret.append(&t, 1);
        len-=2;
        hexbytes+=2;
    }
    return ret;
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",VERSION_STRING);
    
    int optindex = 0;
    int opt = 0;
    
    const char *infile = NULL;
    const char *decryptOutPath = NULL;
    const char *mountPath = NULL;

    tihmstar::Mem dataKeygenKey;
    tihmstar::Mem metaDataKey;
    tihmstar::Mem metaTweakKey;

    uint16_t threads = 0;
    bool writeable = false;
    bool extHDDEnvVars = false;
    
    while ((opt = getopt_long(argc, (char* const *)argv, "hd:Ei:j:k:m:t:w", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;

                if (curopt == "mount") {
                    mountPath = optarg;
                } else {
                    reterror("unexpected lonopt=%s",curopt.c_str());
                }
                break;
            }
                
            case 'h':
                cmd_help();
                return 0;

            case 'E':
                extHDDEnvVars = true;
                break;
                
            case 'd':
                decryptOutPath = optarg;
                break;
                
            case 'i':
                infile = optarg;
                break;

            case 'j':
                threads = atoi(optarg);
                info("Setting threads to %d",threads);
                break;

            case 'k':
                dataKeygenKey = parseHex(optarg);
                break;

            case 'm':
                metaDataKey = parseHex(optarg);
                break;

            case 't':
                metaTweakKey = parseHex(optarg);
                break;
                
            case 'w':
                writeable = true;
                info("Enable writeable mode");
                break;
                
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (!infile){
        error("No inputfile specified");
        cmd_help();
        return -1;
    }
    
    std::shared_ptr<OrbisInternalDisk> disk = std::make_shared<OrbisInternalDisk>(infile,writeable);

    if (!metaDataKey.size()){
        if (const char *val = getenv(extHDDEnvVars ? "EXT_METADATA_DATA_KEY" : "METADATA_DATA_KEY")){
            metaDataKey = parseHex(val);
        }
    }

    if (!metaTweakKey.size()){
        if (const char *val = getenv(extHDDEnvVars ? "EXT_METADATA_TWEAK_KEY" : "METADATA_TWEAK_KEY")){
            metaTweakKey = parseHex(val);
        }
    }
    
    if (!dataKeygenKey.size()){
        if (const char *val = getenv("DATA_KEYGEN_KEY")){
            if (!extHDDEnvVars) dataKeygenKey = parseHex(val);
        }
    }

    retassure(metaDataKey.size(), "Metadata key not set!");
    disk->setMetaDataKey(metaDataKey.data(), metaDataKey.size());
    
    retassure(metaTweakKey.size(), "Metadata tweak not set!");
    disk->setMetaTweakKey(metaTweakKey.data(), metaTweakKey.size());

    //must happen after setting metadata keys
    disk->initCrypto(dataKeygenKey.data(), dataKeygenKey.size());

    if (decryptOutPath) {
        disk->decryptImage(decryptOutPath, threads);
    }
    
    if (mountPath) {
        info("Mounting disk");
        OrbisDiskFuse odf(disk, mountPath);
        odf.loopSession();
    }
    
    info("Done");
    return 0;
}
