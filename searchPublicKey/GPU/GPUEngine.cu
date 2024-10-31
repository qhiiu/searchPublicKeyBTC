#include "./../SECP256k1.h"

#include "GPUEngine.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <stdint.h>
#include "../hash/sha256.h" 
#include "../hash/ripemd160.h"
#include "../Timer.h"

#include "GPUMath.h"
#include "GPUHash.h"
#include "GPUBase58.h"

#include <device_atomic_functions.h>
#include <cuda_runtime.h>
#include <iostream>
using namespace std;

__device__ uint64_t* _2Gnx = NULL;
__device__ uint64_t* _2Gny = NULL;

__device__ uint64_t* Gx = NULL;
__device__ uint64_t* Gy = NULL;

// ---------------------------------------------------------------------------------------

__device__ __noinline__ void Check__Hash(uint64_t* px, uint64_t* py, int32_t incr, uint32_t* out_found, uint64_t* arr_targetPubkey)
{	 
	// compare pubkey
	if (px[0] == arr_targetPubkey[0] &&
		px[1] == arr_targetPubkey[1] &&
		px[2] == arr_targetPubkey[2] &&
		px[3] == arr_targetPubkey[3]
	){
		// generate hash160 if pubkey is true 
		uint8_t isOdd = py[0] & 1; // 
		uint32_t hash160[5];  

		_GetHash160Comp(px, isOdd, (uint8_t*)hash160);  //

		uint32_t tid = (blockIdx.x * blockDim.x) + threadIdx.x;

			out_found[1] = tid;
			out_found[2] = (uint32_t)(incr << 16);
			out_found[3] = hash160[0];
			out_found[4] = hash160[1];
			out_found[5] = hash160[2];
			out_found[6] = hash160[3]; 
			out_found[7] = hash160[4];
	}
}
#define CHECK__HASH(incr) Check__Hash(px, py, incr, out_found, arr_targetPubkey)

//============================================================
//============================================================
//============================================================
//============================================================
// ---------------------------------------------------------------------------------------
#define CudaSafeCall( err ) __cudaSafeCall( err, __FILE__, __LINE__ )

inline void __cudaSafeCall(cudaError err, const char* file, const int line)
{
	if (cudaSuccess != err){
		fprintf(stderr, "cudaSafeCall() failed at %s:%i : %s\n", file, line, cudaGetErrorString(err));
		exit(-1);
	}
	return;
} 
// ---------------------------------------------------------------------------------------

__global__ void compute_keys_comp_mode_sa( uint64_t* __inputKey, uint32_t* out_found, uint64_t* arr_targetPubkey)
{
			// blockDim.x = 128  // blockIdx.x = 48 
			// xPtr-yPtr : 0    - 512    // xPtr-yPtr : 1024 - 1536

	int xPtr = (blockIdx.x * blockDim.x) * 8;  
	int yPtr = xPtr + 4 * blockDim.x;

	uint64_t* startx = __inputKey + xPtr;  
	uint64_t* starty = __inputKey + yPtr;

	uint64_t dx[GRP_SIZE / 2 + 1][4];  //mảng để lưu giá trị delta x.
	uint64_t px[4]; 
	uint64_t py[4];
	uint64_t pyn[4];
	uint64_t sx[4];
	uint64_t sy[4];
	uint64_t dy[4];
	uint64_t _s[4];
	uint64_t _p[4]; //mảng để lưu các giá trị tạm thời.

	// Load starting key
	__syncthreads();    //Đồng bộ hóa các luồng trong block hiện tại. // __syncthreads() là một hàm đồng bộ hóa trong CUDA, để đồng bộ hóa tất cả các luồng trong một block. Khi gọi hàm này, tất cả các luồng trong block đó sẽ dừng lại cho đến khi tất cả các luồng đã đến điểm gọi hàm. Điều này đảm bảo rằng mọi phép toán trước đó trong block đã hoàn thành trước khi bất kỳ luồng nào tiếp tục thực hiện các phép toán tiếp theo.
	Load256A(sx, startx);
	Load256A(sy, starty);
	Load256(px, sx);
	Load256(py, sy);   // Tải các giá trị bắt đầu vào các mảng sx, sy, px, py


	// Fill group with delta x
	uint32_t i;
	for (i = 0; i < HSIZE; i++){ //HSIZE = (GRP_SIZE / 2 - 1) = 1023
		ModSub256(dx[i], Gx + 4 * i, sx);  
		}    // Tính toán các giá trị delta x cho nhóm điểm.
	ModSub256(dx[i], Gx + 4 * i, sx);   // For the first point
	ModSub256(dx[i + 1], _2Gnx, sx); // For the next center point

	_ModInvGrouped(dx);  // Compute modular inverse // Tính toán nghịch đảo modulo cho các giá trị delta x.

	// We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
	// We compute key in the positive and negative way from the center of the group

	// Check starting point
	CHECK__HASH(GRP_SIZE / 2); //GRP_SIZE = 1024*2  //  điểm khởi đầu.
	
	ModNeg256(pyn, py);  // Tính giá trị âm của py

	
	//tính toán các giá trị x và y cho từng điểm 
	for (i = 0; i < HSIZE; i++) {   // HSIZE (GRP_SIZE / 2 - 1) = 1023 

		// P = StartPoint + i*G  //--- thay p2 = G // thay _p2 = _p
		Load256(px, sx);
		Load256(py, sy);
		ModSub256(dy, Gy + 4 * i, py);
				//--------------- hiiu... Secp256K1::NextKey  -------------------- 
		_ModMult(_s, dy, dx[i]);    //  s = (G.y-p1.y)*inverse(G.x-p1.x)
		_ModSqr(_p, _s);           // _p = pow2(s)

		ModSub256(px, _p, px);
		ModSub256(px, Gx + 4 * i);  // px = pow2(s) - p1.x - G.x; 

		ModSub256(py, Gx + 4 * i, px);
		_ModMult(py, _s);            // py = - s*(ret.x-G.x)
		ModSub256(py, Gy + 4 * i);   // py = - G.y - s*(ret.x-G.x);
				//-----------------------------------
 
		CHECK__HASH(GRP_SIZE / 2 + (i + 1));    

		// P = StartPoint - i*G, if (x,y) = i*G then (x,-y) = -i*G
		Load256(px, sx);   
		ModSub256(dy, pyn, Gy + 4 * i);
				//--------------- hiiu... Secp256K1::NextKey --------------------
		_ModMult(_s, dy, dx[i]);            //  s = (G.y-p1.y)*inverse(G.x-p1.x)
		_ModSqr(_p, _s);                   // _p = pow2(s)

		ModSub256(px, _p, px);
		ModSub256(px, Gx + 4 * i);          // px = pow2(s) - p1.x - G.x;

		ModSub256(py, px, Gx + 4 * i);
		_ModMult(py, _s);                   // py = s*(ret.x-G.x)
		ModSub256(py, Gy + 4 * i, py);      // py = - G.y - s*(ret.x-G.x);
				//-----------------------------------

		CHECK__HASH(GRP_SIZE / 2 - (i + 1));   
	}

	// First point (startP - (GRP_SZIE/2)*G)
	Load256(px, sx);
	Load256(py, sy);
	ModNeg256(dy, Gy + 4 * i);
	ModSub256(dy, py);

	_ModMult(_s, dy, dx[i]);              //  s = (G.y-p1.y)*inverse(G.x-p1.x)
	_ModSqr(_p, _s);                     // _p = pow2(s)

	ModSub256(px, _p, px);
	ModSub256(px, Gx + 4 * i);            // px = pow2(s) - p1.x - G.x;

	ModSub256(py, px, Gx + 4 * i);
	_ModMult(py, _s);                     // py = s*(ret.x-G.x)
	ModSub256(py, Gy + 4 * i, py);        // py = - G.y - s*(ret.x-G.x);

	
	CHECK__HASH(0);   //Kiểm tra hash cho điểm cuối cùng.
	i++;

	// Next start point (startP +  *G) m //Cuối cùng, các giá trị x và y mới được lưu trở lại startx và starty
	Load256(px, sx);
	Load256(py, sy);
	ModSub256(dy, _2Gny, py);

	_ModMult(_s, dy, dx[i]);             //  s = (G.y-p1.y)*inverse(G.x-p1.x)
	_ModSqr(_p, _s);                    // _p = pow2(s)

	ModSub256(px, _p, px);
	ModSub256(px, _2Gnx);                // px = pow2(s) - p1.x - G.x;

	ModSub256(py, _2Gnx, px);
	_ModMult(py, _s);                    // py = - s*(ret.x-G.x)
	ModSub256(py, _2Gny);                // py = - G.y - s*(ret.x-G.x);

	// Update starting point
	__syncthreads();
	Store256A(startx, px);
	Store256A(starty, py);
}

// ---------------------------------------------------------------------------------------

using namespace std;

int _ConvertSMVer2Cores(int major, int minor)
{
	// Defines for GPU Architecture types (using the SM version to determine the # of cores per SM
	typedef struct {
		int SM;  // 0xMm (hexidecimal notation), M = SM Major version, 	// and m = SM minor version
		int Cores;
	} sSMtoCores;

	sSMtoCores nGpuArchCoresPerSM[] = {
		{0x20, 32}, // Fermi Generation (SM 2.0) GF100 class
		{0x21, 48}, // Fermi Generation (SM 2.1) GF10x class
		{0x30, 192},
		{0x32, 192},
		{0x35, 192},
		{0x37, 192},
		{0x50, 128},
		{0x52, 128},
		{0x53, 128},
		{0x60,  64},
		{0x61, 128},
		{0x62, 128},
		{0x70,  64},
		{0x72,  64},
		{0x75,  64},
		{0x80,  64},
		{0x86, 128},
		{-1, -1}
	};

	int index = 0;

	while (nGpuArchCoresPerSM[index].SM != -1) {
		if (nGpuArchCoresPerSM[index].SM == ((major << 4) + minor)) {return nGpuArchCoresPerSM[index].Cores;	}
		index++;
	}
	return 0;
}

// ----------------------------------------------------------------------------

GPUEngine::GPUEngine(Secp256K1* secp, int nbThreadGroup, int nbThreadPerGroup, int gpuId, char* pubkey )
{
	// Initialise CUDA
	this->nbThreadPerGroup = nbThreadPerGroup;

	initialised = false;

	int deviceCount = 0;
	CudaSafeCall(cudaGetDeviceCount(&deviceCount));

	CudaSafeCall(cudaSetDevice(gpuId));

	cudaDeviceProp deviceProp;
	CudaSafeCall(cudaGetDeviceProperties(&deviceProp, gpuId));

	if (nbThreadGroup == -1)
		nbThreadGroup = deviceProp.multiProcessorCount * 8;

	this->nbThread = nbThreadGroup * nbThreadPerGroup;
	this->outputSize = (1 * ITEM_SIZE_A + 4);

	char tmp[512];
	sprintf(tmp, "GPU #%d %s (%dx%d cores) Grid(%dx%d) \n",
		gpuId, deviceProp.name, deviceProp.multiProcessorCount,
		_ConvertSMVer2Cores(deviceProp.major, deviceProp.minor),
		nbThread / nbThreadPerGroup,
		nbThreadPerGroup);
	
	deviceName = std::string(tmp);

	// Prefer L1 (We do not use __shared__ at all)
	CudaSafeCall(cudaDeviceSetCacheConfig(cudaFuncCachePreferL1));

	size_t stackSize = 49152; 
	CudaSafeCall(cudaDeviceSetLimit(cudaLimitStackSize, stackSize));

	// Allocate memory
	CudaSafeCall(cudaMalloc((void**)&inputKey, nbThread * 32 * 2));
	CudaSafeCall(cudaHostAlloc(&inputKeyPinned, nbThread * 32 * 2, cudaHostAllocWriteCombined | cudaHostAllocMapped));

	CudaSafeCall(cudaMalloc((void**)&outputBuffer, outputSize));
	CudaSafeCall(cudaHostAlloc(&outputBufferPinned, outputSize, cudaHostAllocWriteCombined | cudaHostAllocMapped));

	//---------------------------------------------------------kpubkey :
	// targetPubkey --> arr_targetPubkey --> input into Cuda 

			Point targetPubkey;

					// char* pubkey = "4EE2BE2D4E9F92D2F5A4A03058617DC45BEFE22938FEED5B7A6B7282DD74CBDD";
					// targetPubkey.x.SetBase16("21e215ff6ab474d5b7e82436a518d5849c6bb665c36a014ad4387d0ec541ded7") ;
			targetPubkey.x.SetBase16(pubkey) ;
			
			CudaSafeCall(cudaHostAlloc(&arr_targetPubkey_pinned, 4 * sizeof(uint64_t), cudaHostAllocWriteCombined | cudaHostAllocMapped));

			arr_targetPubkey_pinned[0] = targetPubkey.x.bits64[0];
			arr_targetPubkey_pinned[1] = targetPubkey.x.bits64[1];
			arr_targetPubkey_pinned[2] = targetPubkey.x.bits64[2];
			arr_targetPubkey_pinned[3] = targetPubkey.x.bits64[3];

			// create arr_targetPubkey in cuda
			CudaSafeCall(cudaMalloc((void**)&arr_targetPubkey, 4 * sizeof(uint64_t)));
			//copy host to cuda
			CudaSafeCall(cudaMemcpy(arr_targetPubkey, arr_targetPubkey_pinned, 4 * sizeof(uint64_t), cudaMemcpyHostToDevice));
			//free 
			CudaSafeCall(cudaFreeHost(arr_targetPubkey_pinned));
			arr_targetPubkey_pinned = NULL;

	//----------------------------------------------end - kpubkey 

	// generator table
	InitGenratorTable(secp);

	CudaSafeCall(cudaGetLastError());

	initialised = true;

}

// ----------------------------------------------------------------------------

void GPUEngine::InitGenratorTable(Secp256K1* secp)
{
	// generator table
	uint64_t* _2GnxPinned;
	uint64_t* _2GnyPinned;

	uint64_t* GxPinned;
	uint64_t* GyPinned;

	uint64_t size = (uint64_t)GRP_SIZE;

	CudaSafeCall(cudaMalloc((void**)&__2Gnx, 4 * sizeof(uint64_t)));
	CudaSafeCall(cudaHostAlloc(&_2GnxPinned, 4 * sizeof(uint64_t), cudaHostAllocWriteCombined | cudaHostAllocMapped));

	CudaSafeCall(cudaMalloc((void**)&__2Gny, 4 * sizeof(uint64_t)));
	CudaSafeCall(cudaHostAlloc(&_2GnyPinned, 4 * sizeof(uint64_t), cudaHostAllocWriteCombined | cudaHostAllocMapped));

	size_t TSIZE = (size / 2) * 4 * sizeof(uint64_t);
	CudaSafeCall(cudaMalloc((void**)&_Gx, TSIZE));
	CudaSafeCall(cudaHostAlloc(&GxPinned, TSIZE, cudaHostAllocWriteCombined | cudaHostAllocMapped));

	CudaSafeCall(cudaMalloc((void**)&_Gy, TSIZE));
	CudaSafeCall(cudaHostAlloc(&GyPinned, TSIZE, cudaHostAllocWriteCombined | cudaHostAllocMapped));


	Point* Gn = new Point[size];
	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g); 
	Gn[1] = g;
	for (int i = 2; i < size; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G   
	Point _2Gn = secp->DoubleDirect(Gn[size / 2 - 1]);

	int nbDigit = 4;
	for (int i = 0; i < nbDigit; i++) {
		_2GnxPinned[i] = _2Gn.x.bits64[i];
		_2GnyPinned[i] = _2Gn.y.bits64[i];
	}
	for (int i = 0; i < size / 2; i++) {
		for (int j = 0; j < nbDigit; j++) {
			GxPinned[i * nbDigit + j] = Gn[i].x.bits64[j];
			GyPinned[i * nbDigit + j] = Gn[i].y.bits64[j];
		}
	}

	delete[] Gn;

	CudaSafeCall(cudaMemcpy(__2Gnx, _2GnxPinned, 4 * sizeof(uint64_t), cudaMemcpyHostToDevice));
	CudaSafeCall(cudaFreeHost(_2GnxPinned));
	_2GnxPinned = NULL;

	CudaSafeCall(cudaMemcpy(__2Gny, _2GnyPinned, 4 * sizeof(uint64_t), cudaMemcpyHostToDevice));
	CudaSafeCall(cudaFreeHost(_2GnyPinned));
	_2GnyPinned = NULL;

	CudaSafeCall(cudaMemcpy(_Gx, GxPinned, TSIZE, cudaMemcpyHostToDevice));
	CudaSafeCall(cudaFreeHost(GxPinned));
	GxPinned = NULL;

	CudaSafeCall(cudaMemcpy(_Gy, GyPinned, TSIZE, cudaMemcpyHostToDevice));
	CudaSafeCall(cudaFreeHost(GyPinned));
	GyPinned = NULL;

	//cudaMemcpyToSymbol : để sao chép dữ liệu từ bộ nhớ của máy chủ (host) vào bộ nhớ của thiết bị (device) cho các biến toàn cục (global variables)
	CudaSafeCall(cudaMemcpyToSymbol(_2Gnx, &__2Gnx, sizeof(uint64_t*)));
	CudaSafeCall(cudaMemcpyToSymbol(_2Gny, &__2Gny, sizeof(uint64_t*)));
	CudaSafeCall(cudaMemcpyToSymbol(Gx, &_Gx, sizeof(uint64_t*)));
	CudaSafeCall(cudaMemcpyToSymbol(Gy, &_Gy, sizeof(uint64_t*)));

}

// ----------------------------------------------------------------------------

int GPUEngine::GetGroupSize()
{	
	return GRP_SIZE; //GRP_SIZE = 1024*2
}

// ----------------------------------------------------------------------------

void GPUEngine::PrintCudaInfo()
{
	printf("GPUEngine::PrintCudaInfo() : ");
	const char* sComputeMode[] = {
		"Multiple host threads",
		"Only one host thread",
		"No host thread",
		"Multiple process threads",
		"Unknown",
		NULL
	};

	int deviceCount = 0;
	CudaSafeCall(cudaGetDeviceCount(&deviceCount));

	for (int i = 0; i < deviceCount; i++) {
		CudaSafeCall(cudaSetDevice(i));
		cudaDeviceProp deviceProp;
		CudaSafeCall(cudaGetDeviceProperties(&deviceProp, i));
		printf("GPU #%d %s (%dx%d cores) (Cap %d.%d) (%.1f MB) (%s)\n",
			i, deviceProp.name, deviceProp.multiProcessorCount,
			_ConvertSMVer2Cores(deviceProp.major, deviceProp.minor),
			deviceProp.major, deviceProp.minor, (double)deviceProp.totalGlobalMem / 1048576.0,
			sComputeMode[deviceProp.computeMode]);
	}
}

// ----------------------------------------------------------------------------

GPUEngine::~GPUEngine()
{
	CudaSafeCall(cudaFree(inputKey));
	// CudaSafeCall(cudaFree(inputHashORxpoint));
	CudaSafeCall(cudaFree(arr_targetPubkey));
	CudaSafeCall(cudaFreeHost(outputBufferPinned));
	CudaSafeCall(cudaFree(outputBuffer));
	CudaSafeCall(cudaFree(__2Gnx));
	CudaSafeCall(cudaFree(__2Gny));
	CudaSafeCall(cudaFree(_Gx));
	CudaSafeCall(cudaFree(_Gy));
}

// ----------------------------------------------------------------------------

int GPUEngine::GetNbThread() 
{	
	return nbThread; 
}

// ----------------------------------------------------------------------------

bool GPUEngine::SetKeys(Point* p) //p ở đây có dạng (x=, y= , z=1)
{
	for (int i = 0; i < nbThread; i += nbThreadPerGroup) { //nbThread = 6144 -- nbThreadPerGroup = 128 

		for (int j = 0; j < nbThreadPerGroup; j++) {

			inputKeyPinned[8 * i + j + 0 * nbThreadPerGroup] = p[i + j].x.bits64[0];
			inputKeyPinned[8 * i + j + 1 * nbThreadPerGroup] = p[i + j].x.bits64[1];
			inputKeyPinned[8 * i + j + 2 * nbThreadPerGroup] = p[i + j].x.bits64[2];
			inputKeyPinned[8 * i + j + 3 * nbThreadPerGroup] = p[i + j].x.bits64[3];

			inputKeyPinned[8 * i + j + 4 * nbThreadPerGroup] = p[i + j].y.bits64[0];
			inputKeyPinned[8 * i + j + 5 * nbThreadPerGroup] = p[i + j].y.bits64[1];
			inputKeyPinned[8 * i + j + 6 * nbThreadPerGroup] = p[i + j].y.bits64[2];
			inputKeyPinned[8 * i + j + 7 * nbThreadPerGroup] = p[i + j].y.bits64[3];
		}
	}

	// Fill device memory
	CudaSafeCall(cudaMemcpy(inputKey, inputKeyPinned, nbThread * 32 * 2, cudaMemcpyHostToDevice));

	CudaSafeCall(cudaFreeHost(inputKeyPinned));
	inputKeyPinned = NULL;

	CudaSafeCall(cudaMemset(outputBuffer, 0, 4));

	compute_keys_comp_mode_sa <<< nbThread / nbThreadPerGroup, nbThreadPerGroup >>>(inputKey, outputBuffer, arr_targetPubkey);
	return true;
}

// ----------------------------------------------------------------------------

bool GPUEngine::LaunchSEARCH_MODE_SA(std::vector<ITEM>& dataFound) 
{
	dataFound.clear();

	// Get the result
	cudaEvent_t evt;
	CudaSafeCall(cudaEventCreate(&evt));
	CudaSafeCall(cudaMemcpyAsync(outputBufferPinned, outputBuffer, 4, cudaMemcpyDeviceToHost, 0));
	CudaSafeCall(cudaEventRecord(evt, 0));

	//The function enters a loop where it checks if the event has completed. //If not, it sleeps for 1 millisecond to avoid busy-waiting.
	while (cudaEventQuery(evt) == cudaErrorNotReady) {  	
		Timer::SleepMillis(1);// Sleep 1 ms to free the CPU 
	}
	
	CudaSafeCall(cudaEventDestroy(evt));

	// Look for data found
	uint32_t nbFound = outputBufferPinned[0];

	// When can perform a standard copy, the kernel is eneded 
	CudaSafeCall(cudaMemcpy(outputBufferPinned, outputBuffer, nbFound * ITEM_SIZE_A + 4, cudaMemcpyDeviceToHost)); // ITEM_SIZE_A = 28

	for (uint32_t i = 0; i < nbFound; i++) { 
		// printf("\n  ---------- nếu đúng mới chạy    for -> launch() -------- A_2 \n");

		uint32_t* itemPtr = outputBufferPinned + (i * ITEM_SIZE_A32 + 1); //ITEM_SIZE_A32 = 7
		ITEM it;
		it.thId = itemPtr[0];
		int16_t* ptr = (int16_t*)&(itemPtr[1]);
		it.incr = ptr[1];  
		it.hash = (uint8_t*)(itemPtr + 2);
		dataFound.push_back(it);
	}
	   
	CudaSafeCall(cudaMemset(outputBuffer, 0, 4));

	compute_keys_comp_mode_sa <<< nbThread / nbThreadPerGroup, nbThreadPerGroup >>>(inputKey, outputBuffer, arr_targetPubkey);

	return true;
}


