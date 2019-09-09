/*******************************************************************************
Vendor: Xilinx
Associated Filename: vadd.cpp
Purpose: SDAccel vector addition

*******************************************************************************
Copyright (C) 2017 XILINX, Inc.

This file contains confidential and proprietary information of Xilinx, Inc. and
is protected under U.S. and international copyright and other intellectual
property laws.

DISCLAIMER
This disclaimer is not a license and does not grant any rights to the materials
distributed herewith. Except as otherwise provided in a valid license issued to
you by Xilinx, and to the maximum extent permitted by applicable law:
(1) THESE MATERIALS ARE MADE AVAILABLE "AS IS" AND WITH ALL FAULTS, AND XILINX
HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS, EXPRESS, IMPLIED, OR STATUTORY,
INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, NON-INFRINGEMENT, OR
FITNESS FOR ANY PARTICULAR PURPOSE; and (2) Xilinx shall not be liable (whether
in contract or tort, including negligence, or under any other theory of
liability) for any loss or damage of any kind or nature related to, arising under
or in connection with these materials, including for any direct, or any indirect,
special, incidental, or consequential loss or damage (including loss of data,
profits, goodwill, or any type of loss or damage suffered as a result of any
action brought by a third party) even if such damage or loss was reasonably
foreseeable or Xilinx had been advised of the possibility of the same.

CRITICAL APPLICATIONS
Xilinx products are not designed or intended to be fail-safe, or for use in any
application requiring fail-safe performance, such as life-support or safety
devices or systems, Class III medical devices, nuclear facilities, applications
related to the deployment of airbags, or any other applications that could lead
to death, personal injury, or severe property or environmental damage
(individually and collectively, "Critical Applications"). Customer assumes the
sole risk and liability of any use of Xilinx products in Critical Applications,
subject only to applicable laws and regulations governing limitations on product
liability.

THIS COPYRIGHT NOTICE AND DISCLAIMER MUST BE RETAINED AS PART OF THIS FILE AT
ALL TIMES.

*******************************************************************************/
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include "pow.h"

static const int DATA_SIZE = 4096;

static const std::string error_message =
    "Error: Result mismatch:\n"
    "i = %d CPU result = %d Device result = %d\n";

static char nibbleToChar(unsigned nibble)
{
	return (char) ((nibble >= 10 ? 'a'-10 : '0') + nibble);
}

static uint8_t charToNibble(char chr)
{
	if (chr >= '0' && chr <= '9')
	{
		return (uint8_t) (chr - '0');
	}
	if (chr >= 'a' && chr <= 'z')
	{
		return (uint8_t) (chr - 'a' + 10);
	}
	if (chr >= 'A' && chr <= 'Z')
	{
		return (uint8_t) (chr - 'A' + 10);
	}
	return 0;
}

static std::vector<uint8_t> hexStringToBytes(char const* str)
{
	std::vector<uint8_t> bytes(strlen(str) >> 1);
	for (unsigned i = 0; i != bytes.size(); ++i)
	{
		bytes[i] = charToNibble(str[i*2 | 0]) << 4;
		bytes[i] |= charToNibble(str[i*2 | 1]);
	}
	return bytes;
}

static std::string bytesToHexString(uint8_t const* bytes, unsigned size)
{
	std::string str;
	for (unsigned i = 0; i != size; ++i)
	{
		str += nibbleToChar(bytes[i] >> 4);
		str += nibbleToChar(bytes[i] & 0xf);
	}
	return str;
}

int main(int argc, char* argv[]) {

    //TARGET_DEVICE macro needs to be passed from gcc command line
    if(argc != 2) {
		std::cout << "Usage: " << argv[0] <<" <xclbin>" << std::endl;
		return EXIT_FAILURE;
	}

    char* xclbinFilename = argv[1];
    
    size_t size_dag = 1073739904U;
    size_t size_hsh = 32U;
    
    // Creates a vector of DATA_SIZE elements with an initial value of 10 and 32
    // using customized allocator for getting buffer alignment to 4k boundary
    
    std::vector<cl::Device> devices;
    cl::Device device;
    std::vector<cl::Platform> platforms;
    bool found_device = false;

    //traversing all Platforms To find Xilinx Platform and targeted
    //Device in Xilinx Platform
    cl::Platform::get(&platforms);
    for(size_t i = 0; (i < platforms.size() ) & (found_device == false) ;i++){
        cl::Platform platform = platforms[i];
        std::string platformName = platform.getInfo<CL_PLATFORM_NAME>();
        if ( platformName == "Xilinx"){
            devices.clear();
            platform.getDevices(CL_DEVICE_TYPE_ACCELERATOR, &devices);
	    if (devices.size()){
		    device = devices[0];
		    found_device = true;
		    break;
	    }
        }
    }
    if (found_device == false){
       std::cout << "Error: Unable to find Target Device " 
           << device.getInfo<CL_DEVICE_NAME>() << std::endl;
       return EXIT_FAILURE; 
    }

    // Creating Context and Command Queue for selected device
    cl::Context context(device);
    cl::CommandQueue q(context, device, CL_QUEUE_PROFILING_ENABLE);

    // Load xclbin 
    std::cout << "Loading: '" << xclbinFilename << "'\n";
    std::ifstream bin_file(xclbinFilename, std::ifstream::binary);
    bin_file.seekg (0, bin_file.end);
    unsigned nb = bin_file.tellg();
    bin_file.seekg (0, bin_file.beg);
    char *buf = new char [nb];
    bin_file.read(buf, nb);
    
    // Creating Program from Binary File
    cl::Program::Binaries bins;
    bins.push_back({buf,nb});
    devices.resize(1);
    cl::Program program(context, devices, bins);
    
    // This call will get the kernel object from program. A kernel is an 
    // OpenCL function that is executed on the FPGA. 
    cl::Kernel krnl_pow(program,"krnl_ethash");
    
    // These commands will allocate memory on the Device. The cl::Buffer objects can
    // be used to reference the memory locations on the device. 
    cl::Buffer buf_res_mix(context, CL_MEM_WRITE_ONLY, size_hsh);
    cl::Buffer buf_res_hsh(context, CL_MEM_WRITE_ONLY, size_hsh);
    cl::Buffer buf_dag(context, CL_MEM_READ_ONLY, size_dag);
    cl::Buffer buf_hdr(context, CL_MEM_READ_ONLY, size_hsh);
    
    //set the kernel Arguments
    int narg=0;
    krnl_pow.setArg(narg++, buf_res_mix);
    krnl_pow.setArg(narg++, buf_res_hsh);
    krnl_pow.setArg(narg++, buf_dag);
    krnl_pow.setArg(narg++, buf_hdr);
    krnl_pow.setArg(narg++, 0); //nonce=0

    //We then need to map our OpenCL buffers to get the pointers
    char *p_res_mix = (char *) q.enqueueMapBuffer (buf_res_mix , CL_TRUE , CL_MAP_WRITE , 0, size_hsh);
    char *p_res_hsh = (char *) q.enqueueMapBuffer (buf_res_hsh , CL_TRUE , CL_MAP_WRITE , 0, size_hsh);
    char *p_dag = (char *) q.enqueueMapBuffer (buf_dag , CL_TRUE , CL_MAP_READ , 0, size_dag);
    char *p_hdr = (char *) q.enqueueMapBuffer (buf_hdr , CL_TRUE , CL_MAP_READ , 0, size_hsh);

    // init dag
	std::ifstream file("../dataset", std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	if (file.read(p_dag, size))
	{
		std::cout << "dag loaded\n";
	} else {
		std::cout << "failed to load dag\n";
		std::cout << "error: only " << file.gcount() << " could be read\n";
		std::cout << "eof: " << file.eof() << "\n";
		std::cout << "fail: " << file.fail() << "\n";
		std::cout << "bad: " << file.bad() << "\n";
	}
	// init header hash
	memcpy(p_hdr, hexStringToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").data(), 32);

    // Data will be migrated to kernel space
    q.enqueueMigrateMemObjects({buf_dag,buf_hdr},0/* 0 means from host*/);

    //Launch the Kernel
    q.enqueueTask(krnl_pow);

    // The result of the previous kernel execution will need to be retrieved in
    // order to view the results. This call will transfer the data from FPGA to
    // source_results vector
    q.enqueueMigrateMemObjects({buf_res_mix,buf_res_hsh},CL_MIGRATE_MEM_OBJECT_HOST);

    q.finish();

    //Print the result
    std::cout << "mix: " << bytesToHexString((const uint8_t*)p_res_mix, 32).c_str() << std::endl;
    std::cout << "hsh: " << bytesToHexString((const uint8_t*)p_res_hsh, 32).c_str() << std::endl;

    q.enqueueUnmapMemObject(buf_res_mix , p_res_mix);
    q.enqueueUnmapMemObject(buf_res_hsh , p_res_hsh);
    q.enqueueUnmapMemObject(buf_dag , p_dag);
    q.enqueueUnmapMemObject(buf_hdr , p_hdr);
    q.finish();

    return 0;
}
