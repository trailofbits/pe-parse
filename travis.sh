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

linux_initialize() {
  printf "Initializing platform: linux\n"

  printf " > Updating the package database..\n"
  sudo apt-get -qq update
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n"
    return 1
  fi

  printf " > Installing the required packages...\n"
  sudo apt-get install -qqy cmake python2.7 python-dev build-essential realpath
  if [ $? -ne 0 ] ; then
    printf " x Could not install the required dependencies\n"
    return 1
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

osx_initialize() {
  printf "Initializing platform: osx\n"

  printf " > Updating the package database..\n"
  brew update
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n"
    return 1
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

linux_build() {
  printf "Building platform: linux\n\n"
  local log_file=`mktemp`

  printf "Library\n"
  if [ ! -d "build" ] ; then
    printf " > Creating the build directory...\n"
    mkdir "build"
    if [ $? -ne 0 ] ; then
      printf " x Failed to create the build directory\n"
      return 1
    fi
  fi

  printf " > Configuring...\n"
  ( cd "build" && cmake .. ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Configure failed; CMake returned an error.\n\n\n"
    cat "$log_file"
    return 1
  fi

  printf " > Building...\n"
  ( cd "build" && make -j `nproc` ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The build has failed.\n\n\n"
    cat "$log_file"
    return 1
  fi

  printf " > Installing...\n"
  ( cd "build" && sudo make install ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to install the library.\n"\n\n
    cat "$log_file"
    return 1
  fi

  printf "\n\n"

  printf "Examples\n"
  if [ ! -d "examples_build" ] ; then
    printf " > Creating the build directory...\n"
    mkdir "examples_build"
    if [ $? -ne 0 ] ; then
      printf " x Failed to create the build directory\n\n\n"
      cat "$log_file"
      return 1
    fi
  fi

  printf " > Configuring...\n"
  ( cd "examples_build" && cmake "../examples/peaddrconv" ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Configure failed; CMake returned an error.\n\n\n"
    cat "$log_file"
    return 1
  fi

  printf " > Building...\n"
  ( cd "examples_build" && make -j `nproc` ) > "$log_file" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The build has failed.\n\n\n"
    cat "$log_file"
    return 1
  fi

  return 0
}

osx_build() {
  printf "Building for platform: osx\n\n"

  printf " x This platform is not yet supported\n"
  return 1
}

main $@
exit $?
