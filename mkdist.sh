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
#copy_files ${AUXFILES}
create_tar
