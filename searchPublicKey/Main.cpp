#include "Timer.h"
#include "KeyHunt.h"
#include "Base58.h"
#include "CmdParse.h"
#include <string>
#include <string.h>
#include <stdexcept>
#include <cassert>
#include <algorithm>
#include <signal.h>
#include <unistd.h>
#include <iostream>

#include <sstream>

using namespace std;
bool should_exit = false;

// ----------------------------------------------------------------------------

bool parseRange(const std::string& s, Int& start, Int& end)
{
	size_t pos = s.find(':');

	if (pos == std::string::npos) {
		start.SetBase16(s.c_str());
		end.Set(&start);
		end.Add(0xFFFFFFFFFFFFULL);
	}
	else {
		std::string left = s.substr(0, pos);

		if (left.length() == 0) {	start.SetInt32(1);	}
		else {	start.SetBase16(left.c_str());	}

		std::string right = s.substr(pos + 1);

		if (right[0] == '+') {
			Int t;
			t.SetBase16(right.substr(1).c_str());
			end.Set(&start);
			end.Add(&t);
		}
		else {	end.SetBase16(right.c_str());	}
	}

	return true;
}

void CtrlHandler(int signum) {
	printf("\nBYE");
	printf("\nBYE");
	printf("\nBYE");
	printf("\nBYE");
	exit(signum);
}

void run(){

	// Global Init
	Timer::Init();
	rseed(Timer::getSeed32());

	bool gpuEnable = true;
	bool gpuAutoGrid = true;
	vector<int> gpuId = { 0 };
	vector<int> gridSize;

	string outputFile = "$.txt";
	// string address = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9";	
	// string rangee = "51c11111111a11111:7b8c88a8888188888";

	string address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so";	
	string rangee = "2832ed74f00000000:2832ed74f50000000"; //2832ed74f2b5e35ee
	char* pubkey = "4EE2BE2D4E9F92D2F5A4A03058617DC45BEFE22938FEED5B7A6B7282DD74CBDD";

	uint32_t maxFound = 1;

	Int rangeStart;
	Int rangeEnd;
	rangeStart.SetInt32(0); 
	rangeEnd.SetInt32(0);

	std::cout<< "===================================================" << std::endl;   

	parseRange(rangee, rangeStart, rangeEnd);

	if (gridSize.size() == 0) {
		for (int i = 0; i < gpuId.size(); i++) {
			gridSize.push_back(-1);
			gridSize.push_back(128);
		}
	}

	printf("\n\n");
	printf("MAX FOUND    : %d\n", maxFound);
	printf("BTC ADDRESS  : %s\n", address.c_str());
	std::cout<<"PUBKEY 	     : "<< pubkey << std::endl<< std::endl;
	printf("OUTPUT FILE  : %s\n", outputFile.c_str());

	signal(SIGINT, CtrlHandler);

	KeyHunt* v;
	v = new KeyHunt(gpuEnable, outputFile,	maxFound, rangeStart.GetBase16(), rangeEnd.GetBase16(), should_exit, pubkey);

	v->Search(gpuId, gridSize, should_exit);

	printf("\n\n delete v; \n");
	printf("\n delete v; \n");
	printf("\n delete v; \n");
	printf("\n delete v; \n");

	delete v;

};

int main(){
	run();
	return 0;
};