# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jarvis/PHE/sgx_version

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jarvis/PHE/sgx_version/build

# Utility rule file for sign.

# Include the progress variables for this target.
include CMakeFiles/sign.dir/progress.make

CMakeFiles/sign: enclave.signed


enclave.signed: enclave
enclave.signed: ../enclave.conf
enclave.signed: private.pem
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/jarvis/PHE/sgx_version/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating enclave.signed"
	/opt/edgelessrt/bin/oesign sign -e /home/jarvis/PHE/sgx_version/build/enclave -c /home/jarvis/PHE/sgx_version/enclave.conf -k private.pem

private.pem:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/jarvis/PHE/sgx_version/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Generating private.pem, public.pem"
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem

public.pem: private.pem
	@$(CMAKE_COMMAND) -E touch_nocreate public.pem

sign: CMakeFiles/sign
sign: enclave.signed
sign: private.pem
sign: public.pem
sign: CMakeFiles/sign.dir/build.make

.PHONY : sign

# Rule to build all files generated by this target.
CMakeFiles/sign.dir/build: sign

.PHONY : CMakeFiles/sign.dir/build

CMakeFiles/sign.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sign.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sign.dir/clean

CMakeFiles/sign.dir/depend:
	cd /home/jarvis/PHE/sgx_version/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jarvis/PHE/sgx_version /home/jarvis/PHE/sgx_version /home/jarvis/PHE/sgx_version/build /home/jarvis/PHE/sgx_version/build /home/jarvis/PHE/sgx_version/build/CMakeFiles/sign.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sign.dir/depend

