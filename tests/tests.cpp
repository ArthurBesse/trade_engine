#include <gtest/gtest.h>
#include <libengine/Engine.h>
#include "basic_functionality_tests.h"
#include "invalid_api_usage_tests.h"
#include "cuncurrent_tests.h"


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}