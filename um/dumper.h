#pragma once

#include <cstdint>

// dump a running driver to a file
bool dump_driver(char const* name, char const* path = nullptr);

// get the image base and image size of a loaded driver (from kernel module list)
bool find_loaded_driver(char const* name, void*& imagebase, uint32_t& imagesize);

