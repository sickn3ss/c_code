# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

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
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/sickness/CLionProjects/CLion_cross_compiling

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/CLion_cross_compiling.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/CLion_cross_compiling.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/CLion_cross_compiling.dir/flags.make

CMakeFiles/CLion_cross_compiling.dir/main.c.o: CMakeFiles/CLion_cross_compiling.dir/flags.make
CMakeFiles/CLion_cross_compiling.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/CLion_cross_compiling.dir/main.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/CLion_cross_compiling.dir/main.c.o   -c /Users/sickness/CLionProjects/CLion_cross_compiling/main.c

CMakeFiles/CLion_cross_compiling.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/CLion_cross_compiling.dir/main.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/sickness/CLionProjects/CLion_cross_compiling/main.c > CMakeFiles/CLion_cross_compiling.dir/main.c.i

CMakeFiles/CLion_cross_compiling.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/CLion_cross_compiling.dir/main.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/sickness/CLionProjects/CLion_cross_compiling/main.c -o CMakeFiles/CLion_cross_compiling.dir/main.c.s

CMakeFiles/CLion_cross_compiling.dir/main.c.o.requires:

.PHONY : CMakeFiles/CLion_cross_compiling.dir/main.c.o.requires

CMakeFiles/CLion_cross_compiling.dir/main.c.o.provides: CMakeFiles/CLion_cross_compiling.dir/main.c.o.requires
	$(MAKE) -f CMakeFiles/CLion_cross_compiling.dir/build.make CMakeFiles/CLion_cross_compiling.dir/main.c.o.provides.build
.PHONY : CMakeFiles/CLion_cross_compiling.dir/main.c.o.provides

CMakeFiles/CLion_cross_compiling.dir/main.c.o.provides.build: CMakeFiles/CLion_cross_compiling.dir/main.c.o


# Object files for target CLion_cross_compiling
CLion_cross_compiling_OBJECTS = \
"CMakeFiles/CLion_cross_compiling.dir/main.c.o"

# External object files for target CLion_cross_compiling
CLion_cross_compiling_EXTERNAL_OBJECTS =

CLion_cross_compiling: CMakeFiles/CLion_cross_compiling.dir/main.c.o
CLion_cross_compiling: CMakeFiles/CLion_cross_compiling.dir/build.make
CLion_cross_compiling: CMakeFiles/CLion_cross_compiling.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable CLion_cross_compiling"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CLion_cross_compiling.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/CLion_cross_compiling.dir/build: CLion_cross_compiling

.PHONY : CMakeFiles/CLion_cross_compiling.dir/build

CMakeFiles/CLion_cross_compiling.dir/requires: CMakeFiles/CLion_cross_compiling.dir/main.c.o.requires

.PHONY : CMakeFiles/CLion_cross_compiling.dir/requires

CMakeFiles/CLion_cross_compiling.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/CLion_cross_compiling.dir/cmake_clean.cmake
.PHONY : CMakeFiles/CLion_cross_compiling.dir/clean

CMakeFiles/CLion_cross_compiling.dir/depend:
	cd /Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/sickness/CLionProjects/CLion_cross_compiling /Users/sickness/CLionProjects/CLion_cross_compiling /Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug /Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug /Users/sickness/CLionProjects/CLion_cross_compiling/cmake-build-debug/CMakeFiles/CLion_cross_compiling.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/CLion_cross_compiling.dir/depend

