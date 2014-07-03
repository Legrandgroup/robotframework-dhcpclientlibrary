#!/bin/bash

set -e

PROGNAME=`basename "$0"`
DEFAULT_INSTALL_DIR='/opt/python-local'
INIT_CWD=`pwd`


install_python_package() {

  if [ $# -ne 2 ]; then
    echo "install_python_package() Error: Missing argument" >&2
    exit 2
  fi
  
  PACKAGE="$1"
  INSTALL_DIR="$2"
  
  WORK_DIR=`mktemp -t -d`

  if test -z "${WORK_DIR}"; then
    echo "Failed creating temporary directory" >&2
    exit 1
  fi

	NBZIP=`ls -1 "${PROGDIR}/${PACKAGE}/${PACKAGE}"*.zip | wc -l`

	if test -n "${NBZIP}"; then
	  if [ "${NBZIP}" -eq 1 ]; then
	    :
	  else
	    echo "Could not find which source zip archive to use in ${PROGDIR}/${PACKAGE}" >&2
	    exit 1
	  fi
	else
	  echo "Could not find which source zip archive to use in ${PROGDIR}/${PACKAGE}" >&2
	  exit 1
	fi

	PACKAGEZIP=`ls -1rt "${PROGDIR}/${PACKAGE}"/*.zip | tail -n 1`

	(cd "${WORK_DIR}" && unzip -x "${PACKAGEZIP}")

	ls "${PROGDIR}/${PACKAGE}"/*.patch | while read onepatchfile
	do
	  (cd "${WORK_DIR}" && patch -p0 < "${onepatchfile}")
	done

	cd "${WORK_DIR}/${PACKAGE}"*
	echo "Installing library in ${INSTALL_DIR}"

	sudo mkdir -p "${INSTALL_DIR}"
	sudo python ./setup.py install --prefix="${INSTALL_DIR}"

	echo "Installation done. In order to use this library, add the following to your PYTHONPATH:"
  echo ${INSTALL_DIR}/lib/python*/site-packages/
}

if [ -z "${INSTALL_DIR}" ]; then
  INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
  echo "Using default install target dir ${INSTALL_DIR}"
fi

# Get the diretory where this script is located
SOURCE="${BASH_SOURCE[0]}"
while [ -h "${SOURCE}" ]; do # resolve $SOURCE until the file is no longer a symlink
  PROGDIR=`cd -P "$( dirname "${SOURCE}" )" && pwd`
  SOURCE=`readlink "${SOURCE}"`
  [[ "${SOURCE}" != /* ]] && SOURCE="${PROGDIR}/${SOURCE}" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
PROGDIR=`cd -P "$( dirname "${SOURCE}" )" && pwd`

if ! type -p unzip 2>/dev/null; then
  echo "Could not find unzip command" >&2
  exit 1
fi

if ! type -p mktemp 2>/dev/null; then
  echo "Could not find mktemp command" >&2
  exit 1
fi

if ! type -p patch 2>/dev/null; then
  echo "Could not find patch command" >&2
  exit 1
fi

if ! type -p python 2>/dev/null; then
  echo "Could not find python command" >&2
  exit 1
fi

for package in pydhcplib
do
  install_python_package "${package}" "${INSTALL_DIR}"
done

cd "${INIT_CWD}"