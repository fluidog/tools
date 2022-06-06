#! /bin/bash

CVES_DATA=data/CVEs.txt

IN_CHECK_CVES=check-CVEs.txt
OUT_PATCH_DIR=out-CVEs-patch
OUT_CVES_INFO=out-CVEs-info.txt
OUT_CVES_APPLIED_INFO=out-CVEs-applied_info.txt
PATCH_URL=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=


LINUX_KERNEL_DIR=/root/workspace/kernel/klinux4.19-zyj/
BRANCH=origin/kylinos-zyj


function make_cves_info()
{
	sed -e '/^$/d' | # 去除空行
		while read cve ; do
			grep -e $cve $CVES_DATA || echo "!$cve"
		done
}


function make_cves_patch()
{
	sed -e '/^$/d' | # 去除空行
		awk "{if(\$4~/[0-9]+/) print \"-o $OUT_PATCH_DIR/\"\$1 \" $PATCH_URL\"\$4 }" |
		xargs -d "\n" -n 1 echo curl -sS -L --create-dirs |
		xargs -d "\n" -n 1 -P 8 bash -c
}

function make_cves_applied_info()
{
	for patch in $OUT_PATCH_DIR/* ; do
		cmg=$(sed -n -e '4s/^Subject: //p' $patch)
		search=$(git -C "$LINUX_KERNEL_DIR" log --grep "$cmg" $BRANCH -- )
		[ -n "$search" ] && echo -n "[1]"  || echo -n "[0]" 
		echo "  ${patch##*/} $cmg"
	done
}


function is_patch_applied()
{
	local patch=$1
	local cmg=$(sed -n -e '4s/^Subject: //p' $patch)
	local search=$(git -C "$LINUX_KERNEL_DIR" log --grep "$cmg" $BRANCH -- )
	[ -n "$search" ] && echo -n "[1]"  || echo -n "[0]" 
		echo "  ${patch##*/} $cmg"
}
[ $# -eq 1 ] && {
	is_patch_applied $1
	exit 0
}
# multi thread
function make_cves_applied_info2()
{
	echo $OUT_PATCH_DIR/* | xargs -n 1 -P 8 $0 
}



make_cves_info < $IN_CHECK_CVES > $OUT_CVES_INFO

make_cves_patch < $OUT_CVES_INFO

# make_cves_applied_info2 > $OUT_CVES_APPLIED_INFO
