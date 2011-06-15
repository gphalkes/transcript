#!/bin/bash

cd "`dirname \"$0\"`"

. ../repo-scripts/mkdist_funcs.sh

setup_hg
get_version_hg
#check_mod_hg
build_all
get_sources_hg
make_tmpdir
copy_sources ${SOURCES} ${GENSOURCES} ${AUXSOURCES}
copy_dist_files
copy_files doc/API doc/motivation.txt
#copy_files ${AUXFILES}


if [ "${VERSION}" =~ [0-9]{8} ] ; then
	VERSION_BIN=0
else
	VERSION_BIN="$(printf \"%02x%02x%02x\" $(echo ${VERSION} | tr '.' ' '))"
fi

sed -i "s/<VERSION>/${VERSION}/g" `find ${TOPDIR} -type f | egrep -v '^src'`
sed -i "/#define TRANSCRIPT_VERSION/c #define TRANSCRIPT_VERSION ${VERSION_BIN}" ${TOPDIR}/src/transcript.h

create_tar
