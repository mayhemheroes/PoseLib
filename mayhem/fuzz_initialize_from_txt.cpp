#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "PoseLib/misc/colmap_models.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    poselib::Camera cam;
    cam.initialize_from_txt(str);
    return 0;
}
