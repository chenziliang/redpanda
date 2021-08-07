#pragma once

// TP starts : internal roaring
#ifndef TP_BUILD 
#include <roaring/roaring.hh>
#else
#include <roaring.hh>
using namespace roaring;
#endif
// TP ends
