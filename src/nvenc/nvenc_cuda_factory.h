/**
 * @file src/nvenc/nvenc_cuda_factory.h
 * @brief SDK-neutral factory for Linux CUDA NVENC encoders.
 */
#pragma once

#include <cstdint>
#include <memory>

#include "nvenc_encoder.h"

namespace nvenc {

  struct nvenc_cuda_input {
    void *context = nullptr;
    std::uintptr_t device_pointer = 0;
    std::uint32_t pitch = 0;
  };

  std::unique_ptr<nvenc_encoder> make_nvenc_cuda_encoder(nvenc_cuda_input input);

}  // namespace nvenc
