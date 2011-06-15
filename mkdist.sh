#!/bin/bash


cd "`dirname \"$0\"`"
BASEDIR="`pwd`"

. ../repo-scripts/mkdist_funcs.sh

PACKAGE=libtranscript

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

	if [[ "${SRC}" =~ ^src/[^/]*\.c ]] ; then
		LIBTRANSCRIPT_SOURCES="${LIBTRANSCRIPT_SOURCES} ${SRC}"
	elif [[ "${SRC}" =~ ^src.util/linkltc/ ]] ; then
		LINKLTC_SOURCES="${LINKLTC_SOURCES} ${SRC}"
	elif [[ "${SRC}" =~ ^src.util/ucm2ltc/ ]] ; then
		UCM2LTC_SOURCES="${UCM2LTC_SOURCES} ${SRC}"
	else
		echo "Don't know what to do with source ${SRC}"
	fi
done

sed -r -i "s%<SOURCES_LIBTRANSCRIPT>%${LIBTRANSCRIPT_SOURCES}%g" ${TOPDIR}/Makefile.in

create_tar
