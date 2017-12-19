#!/usr/bin/env bash

main() {
  if [ $# -ne 2 ] ; then
    printf "Usage:\n\ttravis.sh <linux|osx> <initialize|build>\n"
    return 1
  fi

  local platform_name="$1"
  local operation_type="$2"

  if [[ "${platform_name}" != "osx" && "${platform_name}" != "linux" ]] ; then
    printf "Invalid platform: ${platform_name}\n"
    return 1
  fi

  if [[ "${operation_type}" == "initialize" ]] ; then
    "${platform_name}_initialize"
    return $?

  elif [[ "$operation_type" == "build" ]] ; then
    "${platform_name}_build"
    return $?
  
  else
    printf "Invalid operation\n"
    return 1
  fi
}

get_processor_count() {
  which nproc > /dev/null
  if [ $? -eq 0 ] ; then
    nproc
    return 0
  fi

  which sysctl > /dev/null
  if [ $? -eq 0 ] ; then
    sysctl -n hw.ncpu
    return 0
  fi

  return 1
}

linux_initialize() {
  printf "Initializing platform: linux\n"
  local log_file=`mktemp`

  printf " > Updating the package database..\n"
  sudo apt-get -qq update > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n\n\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Installing the required packages...\n"
  sudo apt-get install -qqy cmake python2.7 python-dev build-essential realpath > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Could not install the required dependencies\n\n\n"
    cat "${log_file}"
    return 1
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

osx_initialize() {
  printf "Initializing platform: macOS\n"
  local log_file=`mktemp`

  printf " > Updating the package database..\n"
  brew update > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n\n\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Installing CMake...\n"
  brew install cmake  > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to install CMake\n\n\n"
    cat "${log_file}"
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

common_build() {
  printf "Gathering system information...\n"

  which cmake > /dev/null
  printf " > CMake version: "
  if [ $? -eq 0 ] ; then
    cmake --version | head -n 1
  else
    printf "not found\n"
  fi

  which gcc > /dev/null
  printf " > GCC version: "
  if [ $? -eq 0 ] ; then
    gcc --version | head -n 1
  else
    printf "not found\n"
  fi

  which clang > /dev/null
  printf " > Clang version: "
  if [ $? -eq 0 ] ; then
    clang --version | head -n 1
  else
    printf "not found\n"
  fi

  printf "\n"

  printf "Library\n"
  if [ ! -d "build" ] ; then
    printf " > Creating the build directory...\n"
    mkdir "build"
    if [ $? -ne 0 ] ; then
      printf " x Failed to create the build directory\n"
      return 1
    fi
  fi

  local log_file=`mktemp`
  local processor_count=`get_processor_count`

  printf " > Configuring...\n"
  ( cd "build" && cmake .. ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Configure failed; CMake returned an error.\n\n\n"
    cat "$log_file"
    return 1
  fi

  printf " > Building...\n"
  ( cd "build" && make -j "${processor_count}" ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The build has failed.\n\n\n"
    cat "$log_file"
    return 1
  fi

  printf " > Installing...\n"
  sudo touch /usr/lib/test_file > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Access denied to /usr/lib; the 'install' step will be skipped\n"

  else
    ( cd "build" && sudo make install ) > "$log_file" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to install the library.\n\n\n"
      cat "$log_file"
      return 1
    fi
  fi

  printf "\n"

  printf "pepy\n"

  printf " > Building...\n"
  ( cd python && python2 ./setup.py build ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
      printf " x Build failed.\n\n\n"
      cat "$log_file"
      return 1
  fi

  return 0
}

linux_build() {
  printf "Building platform: linux\n"

  source /etc/*-release
  printf "Distribution: ${DISTRIB_DESCRIPTION}\n\n"

  common_build
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

osx_build() {
  printf "Building platform: macOS\n\n"

  printf "macOS version: "
  sw_vers -productVersion

  common_build
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

main $@
exit $?
