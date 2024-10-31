#include "KeyHunt.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "hash/sha256.h"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>

using namespace std;

  
Point Gn[CPU_GRP_SIZE / 2];  //CPU_GRP_SIZE = 1024*2 
Point _2Gn;

// ----------------------------------------------------------------------------

KeyHunt::KeyHunt(bool useGpu, const std::string& outputFile, const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit, char* pubkey)
{
	this->pubkey = pubkey;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->nbGPUThread = 0;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());

	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);   // số keys cần quét 

	secp = new Secp256K1();
	secp->Init();

	InitGenratorTable();
	}

// ----------------------------------------------------------------------------

void KeyHunt::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G 
	Point GPU_Engine = secp->G;
	Gn[0] = GPU_Engine;
	GPU_Engine = secp->DoubleDirect(GPU_Engine);
	Gn[1] = GPU_Engine;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		GPU_Engine = secp->AddDirect(GPU_Engine, secp->G);
		Gn[i] = GPU_Engine;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("Start Time   : %s", ctimeBuff);

	printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
	printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
	printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());
}

// ----------------------------------------------------------------------------

#include <fstream>
KeyHunt::~KeyHunt()
{	
	std::cout<< std::endl;
	// save data

	// print end_time 
	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	std::cout << std::endl << "END TIME : " << ctimeBuff << std::endl;
	std::cout <<"======================================================" << std::endl << std::endl;
	
	delete secp;
	exit(-1);
}

// ----------------------------------------------------------------------------

void KeyHunt::output(std::string addr, std::string priv_wif, std::string priv_hex, std::string public_key)
{
	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}	else {	needToClose = true;	}
	}

	if (!needToClose)
		printf("\n");

	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n=================================================================================\n");
	fprintf(stdout, "PubAddress: %s\n", addr.c_str());
	fprintf(f, "Priv_wif : p2pkh:%s\n", priv_wif.c_str());
	fprintf(stdout, "Priv_wif : p2pkh:%s\n", priv_wif.c_str());
	fprintf(f, "Priv_hex : %s\n", priv_hex.c_str());
	fprintf(stdout, "Priv_hex : %s\n", priv_hex.c_str());
	fprintf(f, "Public_key : %s\n", public_key.c_str());
	fprintf(stdout, "Public_key : %s\n", public_key.c_str());
	fprintf(f, "=================================================================================\n");
	fprintf(stdout, "=================================================================================\n");
	printf("\n.\n.\n.\n.\n.\n.\n.\n.\n.\n.\n.\n.\n.\n");
	if (needToClose)
		fclose(f);
}

// ----------------------------------------------------------------------------

bool KeyHunt::checkPrivKey(std::string addr, Int& key, int32_t incr)  
{
	Int k(&key);         //std::cout<<std::endl <<"1 - 1_priv_hex : "<< k.GetBase16().c_str(); 
	k.Add((uint64_t)incr);

	Point p = secp->ComputePublicKey(&k); //
	std::string chkAddr = secp->GetAddress(1, p); // 
	
	output(addr, secp->GetPrivAddress(1, k), k.GetBase16(), secp->GetPublicKeyHex(1, p)); 

	return true;
}
   

// ----------------------------------------------------------------------------

void* _FindKeyGPU(void* lpParam)
{
	TH_PARAM* p = (TH_PARAM*)lpParam; //TH_PARAM  là 1 structer 
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------
void KeyHunt::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{
	Int tRangeDiff(tRangeEnd);
	Int tRangeStart2(tRangeStart);
	Int tRangeEnd2(tRangeStart);

	Int tThreads;
	tThreads.SetInt32(nbThread);
	tRangeDiff.Set(&tRangeEnd);
	tRangeDiff.Sub(&tRangeStart);
	tRangeDiff.Div(&tThreads);

	for (int i = 0; i < nbThread; i++) { //nbThread = 6144

		tRangeEnd2.Set(&tRangeStart2);  
		tRangeEnd2.Add(&tRangeDiff); 
		keys[i].Set(&tRangeStart2);  // set keys[i] tổng thể cho từng thread
		tRangeStart2.Add(&tRangeDiff);

		// k sẽ đc lấy giả trị của vị trí keys+i , sau đó cộng thêm 1024 để về giữa groupSize
		// sau đó từ k tạo được p_middle_start là điểm publicKey_middle_start 
		// tương đương 6144 keys_start có 6144 k_middle_start => 6144 p_middel_start  
		Int k(keys + i);     
		k.Add((uint64_t)(groupSize / 2));	// Starting key is at the middle of the group 
											// groupSize =  GRP_SIZE (1024*2)	= 1024
		p[i] = secp->ComputePublicKey(&k);  //hiiu.......
	}
	// printf("\n.\n.\n.\n.\n.\n.\n.\n.\n");

}

void KeyHunt::FindKeyGPU(TH_PARAM * ph)
{
	bool ok = true;

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* GPU_Engine;
	GPU_Engine = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, pubkey );  
	printf("GPU info      : %s ", GPU_Engine->deviceName.c_str());

	int nbThread = GPU_Engine->GetNbThread(); //6144
	printf("nbThread : %d \n\n", nbThread);

	Point* p = new Point[nbThread]; // p này để lưu giá trị của public_key  --- trong hàm getGPUStartingKey_s 
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;
	counters[thId] = 0;
	ph->hasStarted = true;
	

	getGPUStartingKeys(tRangeStart, tRangeEnd, GPU_Engine->GetGroupSize(), nbThread, keys, p);
	ok = GPU_Engine->SetKeys(p);    //-------> chạy 1 lần compute <<<>>>

	// GPU_Engine Thread
	while (ok && !endOfSearch) {
		ok = GPU_Engine->LaunchSEARCH_MODE_SA(found); //-------> chạy xN lần compute <<<>>> 

		// nếu đúng --> chạy for()
		for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
			// std::cout<<std::endl <<"===== nếu đúng in ra đấy ====== A_3 \n";
			ITEM it = found[i];
			std::string addr = secp->GetAddress(1, it.hash);
			if (checkPrivKey(addr, keys[it.thId], it.incr)) {
				nbFoundKey++;
			}
		}
 
		if (ok) {
			// update keys[i]_start  cho từng lần quét     
			for (int i = 0; i < nbThread; i++) { // nbThread = 6144  //STEP_SIZE (1024*2)
				keys[i].Add((uint64_t)STEP_SIZE); //hiiu......// set keys[i] chi tiết cho từng lần quét - dựa trên gốc là keys[i] tổng thể
			}
			
			counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // 12582912 = 1024x2 * 6144   // thId = 128 
			// printf("\n --- counters : %lu -----",counters[thId] );
		}
	}

	delete[] keys;
	delete[] p;
	delete GPU_Engine;

	ph->isRunning = false;
}

// ----------------------------------------------------------------------------

bool KeyHunt::isAlive(TH_PARAM * p)
{
	bool check_isAlive = true;
	int total = nbGPUThread;
	for (int i = 0; i < total; i++)
		check_isAlive = check_isAlive && p[i].isRunning;

	return check_isAlive;
}

// ----------------------------------------------------------------------------

bool KeyHunt::hasStarted(TH_PARAM * p)
{
	bool hasStarted = true;
	int total = nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;

	return hasStarted;

}

// ----------------------------------------------------------------------------
uint64_t KeyHunt::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;

}
// ----------------------------------------------------------------------------

void KeyHunt::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

// ----------------------------------------------------------------------------
void KeyHunt::Search(std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	double t0;
	double t1;
	endOfSearch = false;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	// setup ranges
	SetupRanges(nbGPUThread);

	memset(counters, 0, sizeof(counters));

	if (!useGpu){printf("\n");}		

	TH_PARAM* params = (TH_PARAM*)malloc((nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbGPUThread) * sizeof(TH_PARAM));

	// Launch GPU threads  //nbGPUThread là số card đồ họa có trong máy
	for (int i = 0; i < nbGPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = 0x80L + i;
		params[i].isRunning = true;
		params[i].gpuId = gpuId[i];
		params[i].gridSizeX = gridSize[2 * i];
		params[i].gridSizeY = gridSize[2 * i + 1];

		params[i].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[i].rangeEnd.Set(&rangeStart);

		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (i))); //----------------> móc nối -- chuyển qua FindKeyGPU 
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount;
	p100.SetInt32(100);
	double completedPerc = 0;

	while (isAlive(params)) {

		int delay = 1000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(1000);
			delay -= 1000;
		}

		// set completedPerc % hoàn thành 
		gpuCount = getGPUCount();
		uint64_t count = gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();
		completedPerc = CalcPercantage(ICount, rangeStart, rangeDiff2);

		// set ? avgGpuKeyRate
		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// KeyRate smoothing  // set ? avgGpuKeyRate
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);

		if (isAlive(params)) {
			memset(timeStr, '\0', 256);
			// printf("		[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %lf %%] [T: %s (%d bit)] [F: %d]  \n",
			printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %lf %%] [T: %s (%d bit)] [F: %d]  ",

				toTimeStr(t1, timeStr),
				avgKeyRate / 1000000.0,
				avgGpuKeyRate / 1000000.0,
				completedPerc,
				formatThousands(count).c_str(),
				completedBits, 
				nbFoundKey);
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		if (should_exit || nbFoundKey >= 1 || completedPerc > 100.5){
			endOfSearch = true;
		}	
	}

	free(params);
	}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------


std::string KeyHunt::formatThousands(uint64_t x)
{
	// printf("\n::::::K::::::: KeyHunt::formatThousands ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

	char buf[32] = "";
	sprintf(buf, "%lu", x);

	std::string s(buf);
	int len = (int)s.length();
	int numCommas = (len - 1) / 3;
	if (numCommas == 0) {		return s;	}

	std::string result = "";
	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));
	for (int i = 0; i < len; i++) {
		result += s[i];
		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}

// ----------------------------------------------------------------------------

char* KeyHunt::toTimeStr(int sec, char* timeStr)
{
	// printf("\n::::::K::::::: KeyHunt::toTimeStr ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60)); 
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}
