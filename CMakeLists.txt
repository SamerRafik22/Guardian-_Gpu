cmake_minimum_required(VERSION 3.18)
project(Guardian_Gpu LANGUAGES CXX)

# C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find CUDA Toolkit
find_package(CUDAToolkit QUIET)

if(CUDAToolkit_FOUND)
    set(CUDA_TOOLKIT_ROOT_DIR ${CUDAToolkit_TARGET_DIR})
else()
    if(EXISTS "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v10.2")
        set(CUDA_TOOLKIT_ROOT_DIR "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v10.2")
    elseif(EXISTS "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.0")
        set(CUDA_TOOLKIT_ROOT_DIR "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.0")
    else()
        message(FATAL_ERROR "CUDA Toolkit not found.")
    endif()
endif()

# Paths
set(NVML_INCLUDE_DIR "${CUDA_TOOLKIT_ROOT_DIR}/include")
set(NVML_LIBRARY "${CUDA_TOOLKIT_ROOT_DIR}/lib/x64/nvml.lib")

if(EXISTS "${CUDA_TOOLKIT_ROOT_DIR}/extras/CUPTI")
    set(CUPTI_INCLUDE_DIR "${CUDA_TOOLKIT_ROOT_DIR}/extras/CUPTI/include")
    if(WIN32)
        set(CUPTI_LIBRARY "${CUDA_TOOLKIT_ROOT_DIR}/extras/CUPTI/lib64/cupti.lib")
    endif()
else()
    set(CUPTI_INCLUDE_DIR "${CUDA_TOOLKIT_ROOT_DIR}/include")
    set(CUPTI_LIBRARY "${CUDA_TOOLKIT_ROOT_DIR}/lib/x64/cupti.lib")
endif()

# Global Includes
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NVML_INCLUDE_DIR}
    ${CUPTI_INCLUDE_DIR}
    ${CUDAToolkit_INCLUDE_DIRS}
)

# Manually link CUDART STATIC to avoid dependency on cudart64_xx.dll
set(CUDART_STATIC_LIBRARY "${CUDA_TOOLKIT_ROOT_DIR}/lib/x64/cudart_static.lib")

# --- TARGET 2: GuardianMonitor (The Host) ---
add_executable(GuardianMonitor
    monitor_main.cpp
    Gpu_mon.cpp
    etw_monitor.cpp
)

target_link_libraries(GuardianMonitor PRIVATE
    ${CUDA_LIBRARIES}
    ${NVML_LIBRARY}
    tdh
    advapi32
)

# --- TARGET 3: SleepyApp (Pure C++ Test Target) ---
add_executable(SleepyApp 
    sleepy.cpp
)

# --- TARGET 4: CudaWorkload (Verification Tool) ---
# We compile this manually with NVCC if CMake fails, or just include cpp version
add_executable(CudaWorkload cuda_workload.cpp)
target_link_libraries(CudaWorkload PRIVATE ${CUDART_STATIC_LIBRARY})
