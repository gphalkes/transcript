#!/bin/bash


cd "`dirname \"$0\"`"
BASEDIR="`pwd`"

. ../repo-scripts/mkdist_funcs.sh

setup_hg
get_version_hg
#check_mod_hg
#~ build_all
get_sources_hg
make_tmpdir
copy_sources ${SOURCES} ${GENSOURCES} ${AUXSOURCES}
copy_dist_files
copy_files doc/API doc/motivation.txt
#copy_files ${AUXFILES}

if [[ "${VERSION}" =~ [0-9]{8} ]] ; then
	VERSION_BIN=0
else
	VERSION_BIN="$(printf \"%02x%02x%02x\" $(echo ${VERSION} | tr '.' ' '))"
fi

sed -i "s/<VERSION>/${VERSION}/g" `find ${TOPDIR} -type f | egrep -v '^src'`
sed -i "/#define TRANSCRIPT_VERSION/c #define TRANSCRIPT_VERSION ${VERSION_BIN}" ${TOPDIR}/src/transcript.h
( cd ${TOPDIR} ; "${BASEDIR}/../config/merge_config" )

for SRC in ${SOURCES} ${GENSOURCES} ${AUXSOURCES} ; do
	[[ "${SRC}" =~ \.h$ ]] && continue
	[[ "${SRC}" =~ \.objects/ ]] && SRC="`echo \"${SRC}\" | sed -r 's%\.objects/%%'`"

	if [[ "${SRC}" =~ ^src/[^/]*\.c ]] ; then
		LIBTRANSCRIPT_OBJECTS="${LIBTRANSCRIPT_OBJECTS} ${SRC%.c}.lo"
	elif [[ "${SRC}" =~ src/tables/.*\.c ]] ; then
		TABLES="${TABLES} ${SRC%.c}.la"
	elif [[ "${SRC}" =~ ^src.util/linkltc/ ]] ; then
		LINKLTC_OBJECTS="${LINKLTC_OBJECTS} ${SRC%.c}.o"
	elif [[ "${SRC}" =~ ^src.util/ucm2ltc/[^/]*\.cc? ]] ; then
		UCM2LTC_OBJECTS="${UCM2LTC_OBJECTS} ${SRC%.c*}.o"
	else
		echo "Don't know what to do with source ${SRC}"
	fi
done

sed -r -i "s%<OBJECTS_LIBTRANSCRIPT>%${LIBTRANSCRIPT_OBJECTS}%g;\
s%<OBJECTS_LINKLTC>%${LINKLTC_OBJECTS}%g;\
s%<OBJECTS_UCM2LTC>%${UCM2LTC_OBJECTS}%g;\
s%<TABLES>%${TABLES}%g" ${TOPDIR}/Makefile.in
sed -r -i 's%\.objects/%%g' ${TOPDIR}/src.util/ucm2ltc/ucmparser.cc

( cd ${TOPDIR}/src ; ln -s . transcript )

create_tar
