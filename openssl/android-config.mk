#
# These flags represent the build-time configuration of openssl for android
#
# They were pruned from the "Makefile" generated by running ./Configure from import_openssl.sh
#

# From CLFAG=	
#LOCAL_CFLAGS += -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DL_ENDIAN #-DTERMIO
LOCAL_CFLAGS += -DOPENSSL_THREADS -D_REENTRANT  -DL_ENDIAN #-DTERMIO

# From DEPFLAG=
LOCAL_CFLAGS += -DOPENSSL_NO_CAMELLIA -DOPENSSL_NO_CAPIENG -DOPENSSL_NO_CAST -DOPENSSL_NO_CMS -DOPENSSL_NO_GMP -DOPENSSL_NO_IDEA -DOPENSSL_NO_JPAKE -DOPENSSL_NO_MD2 -DOPENSSL_NO_MDC2 -DOPENSSL_NO_RC5 -DOPENSSL_NO_SHA0 -DOPENSSL_NO_RFC3779 -DOPENSSL_NO_SEED -DOPENSSL_NO_STORE -DOPENSSL_NO_WHIRLPOOL

# Extra
LOCAL_CFLAGS += -DOPENSSL_NO_HW -DOPENSSL_NO_ENGINE -DZLIB

# Debug
# LOCAL_CFLAGS += -DCIPHER_DEBUG
