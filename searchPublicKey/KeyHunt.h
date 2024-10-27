#ifndef KEYHUNTH
#define KEYHUNTH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "GPU/GPUEngine.h"
#ifdef WIN64
#include <Windows.h>
#endif

#define CPU_GRP_SIZE (1024*2)
// #define CPU_GRP_SIZE (1024*2*2)


class KeyHunt;

typedef struct {
	KeyHunt* obj;
	int  threadId;
	bool isRunning;
	bool hasStarted;

	int  gridSizeX;
	int  gridSizeY;
	int  gpuId;

	Int rangeStart;
	Int rangeEnd;
} TH_PARAM;


class KeyHunt
{

public:
	KeyHunt(bool useGpu, const std::string& outputFile, uint32_t maxFound, 
		const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit, char* pubkey);

	~KeyHunt();

	void Search(std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit);
	void FindKeyGPU(TH_PARAM* p);

private:

	void InitGenratorTable();

	bool checkPrivKey(std::string addr, Int& key, int32_t incr);

	void output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey);
	bool isAlive(TH_PARAM* p);

	bool hasStarted(TH_PARAM* p);
	uint64_t getGPUCount();

	void SetupRanges(uint32_t totalThreads);

	void getGPUStartingKeys(Int& tRangeStart, Int& tRangeEnd, int groupSize, int nbThread, Int* keys, Point* p);

	std::string formatThousands(uint64_t x);
	char* toTimeStr(int sec, char* timeStr);

	Secp256K1* secp; 

	uint64_t counters[256];
	double startTime;

	bool useGpu;
	bool endOfSearch;
	int nbGPUThread;
	int nbFoundKey;
	uint64_t targetCounter;

	std::string outputFile;

	Int rangeStart;
	Int rangeEnd;
	Int rangeDiff;
	Int rangeDiff2;

	uint32_t maxFound;
	char* pubkey;



	pthread_mutex_t  ghMutex;
};

#endif // KEYHUNTH
