AM_CFLAGS = $(GLOBAL_CFLAGS) $(libfuse_CFLAGS) $(libgeneral_CFLAGS) $(openssl_CFLAGS) 
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libfuse_LIBS) $(libgeneral_LIBS) $(openssl_LIBS)

bin_PROGRAMS = orbisDiskTool

orbisDiskTool_CFLAGS = $(AM_CFLAGS)
orbisDiskTool_CXXFLAGS = $(AM_CXXFLAGS)
orbisDiskTool_LDFLAGS = $(AM_LDFLAGS)
orbisDiskTool_SOURCES = main.cpp \
                        OrbisInternalDisk.cpp \
                        OrbisDiskFuse.cpp