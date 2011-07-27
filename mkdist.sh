#!/bin/bash


cd "`dirname \"$0\"`"
BASEDIR="`pwd`"

. ../repo-scripts/mkdist_funcs.sh

setup_hg
get_version_hg
check_mod_hg
[ -z "${NOBUILD}" ] && {
	make -C src
	( cd ucm ; LD_LIBRARY_PATH=../src/.libs ./generate_ltc.sh -r )
}
build_all
[ -z "${NOBUILD}" ] && { make -C doc clean ; make -C doc all ; }
get_sources_hg
make_tmpdir
copy_sources ${SOURCES} ${GENSOURCES} ${AUXSOURCES}
copy_dist_files
copy_files doc/API doc/motivation.txt
create_configure

if [[ "${VERSION}" =~ [0-9]{8} ]] ; then
	VERSION_BIN=0
else
	VERSION_BIN="$(printf "0x%02x%02x%02x" $(echo ${VERSION} | tr '.' ' '))"
fi

sed -i "s/<VERSION>/${VERSION}/g" `find ${TOPDIR} -type f`
sed -i "/#define TRANSCRIPT_VERSION/c #define TRANSCRIPT_VERSION ${VERSION_BIN}" ${TOPDIR}/src/transcript.h

OBJECTS_LIBTRANSCRIPT="`echo \"${SOURCES} ${GENSOURCES} ${AUXSOURCES}\" | tr ' ' '\n' | sed -r 's%\.objects/%%' | egrep '^src/[^/]*\.c$' | sed -r 's/\.c\>/.lo/g' | tr '\n' ' '`"
TABLES="`echo \"${SOURCES} ${GENSOURCES} ${AUXSOURCES}\" | tr ' ' '\n' | sed -r 's%\.objects/%%' | egrep '^src/tables/.*\.c$' | sed -r 's/\.c\>/.la/g' | tr '\n' ' '`"
OBJECTS_LINKLTC="`echo \"${SOURCES} ${GENSOURCES} ${AUXSOURCES}\" | tr ' ' '\n' | sed -r 's%\.objects/%%' | egrep '^src\.util/linkltc/.*\.c$' | sed -r 's/\.c\>/.o/g' | tr '\n' ' '`"
OBJECTS_UCM2LTC="`echo \"${SOURCES} ${GENSOURCES} ${AUXSOURCES}\" | tr ' ' '\n' | sed -r 's%\.objects/%%' | egrep '^src\.util/ucm2ltc/.*\.cc?$' | sed -r 's/\.cc?\>/.o/g' | tr '\n' ' '`"

make -C src -p -n > ${TMPDIR}/rules.txt
MODULES="`egrep '^MODULES\>' ${TMPDIR}/rules.txt | head -n1 | sed -r 's/.*=//'`"
MODULETARGETS="`echo \"${MODULES}\" | sed -r 's%(\<[^ \t]+\>)%src/modules/\1.la%g'`"

#FIXME: somehow verify binary compatibility, and print an error if not compatible
VERSIONINFO="0:0:0"
LIBVERSION="${VERSIONINFO%%:*}"

sed -r -i "s%<OBJECTS_LIBTRANSCRIPT>%${OBJECTS_LIBTRANSCRIPT}%g;\
s%<TABLES>%${TABLES}%g;s%<MODULES>%${MODULETARGETS}%g;\
s%<VERSIONINFO>%${VERSIONINFO}%g" ${TOPDIR}/mk/libtranscript.in
sed -r -i "s%<OBJECTS_LINKLTC>%${OBJECTS_LINKLTC}%g" ${TOPDIR}/mk/linkltc.in
sed -r -i "s%<OBJECTS_UCM2LTC>%${OBJECTS_UCM2LTC}%g" ${TOPDIR}/mk/ucm2ltc.in
sed -r -i "s%<LIBVERSION>%${LIBVERSION}%g" ${TOPDIR}/Makefile.in ${TOPDIR}/mk/libtranscript.in

for MODULE in ${MODULES} ; do
	MODULEOBJECTS="`egrep \"^modules/${MODULE}.la\" ${TMPDIR}/rules.txt | head -n1 | sed -r 's%modules/%src/modules/%g;s%\.objects/%%g;s/\|.*//;s/.*://'`"
	echo "src/modules/${MODULE}.la: ${MODULEOBJECTS} src/libtranscript.la"
	echo "	\$(SILENTLDLT) \$(LIBTOOL) \$(SILENCELT) --mode=link --tag=CC \$(CC) -shared -module -avoid-version -shrext .ltc \$(CFLAGS) \$(LDFLAGS) -o \$@ ${MODULEOBJECTS} \$(LDLIBS) -rpath \$(libdir)/transcript${LIBVERSION}"
done >> ${TOPDIR}/mk/libtranscript.in

# Modify parser output to look for files in current directory iso .objects
sed -r -i 's%\.objects/%%g' ${TOPDIR}/src.util/ucm2ltc/ucmparser.cc

( cd ${TOPDIR}/src ; ln -s . transcript )

create_tar
