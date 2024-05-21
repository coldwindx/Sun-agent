#include <fstream>
#include <vector>
#include <iostream>
#include <algorithm>
#include "json/json.h"
#include "agent/process.h"

using namespace std;

void Cache::insert(std::shared_ptr<Process> p)
{
    procCache[p->pid] = p;
}
static unordered_map<std::string, int> str2id = {
    {"ProcessStart", 1},
    {"ProcessEnd", 2},
    {"ThreadStart", 3},
    {"ThreadEnd", 4},
    {"ImageLoad", 5},
    {"FileIOWrite", 6},
    {"FileIORead", 7},
    {"FileIOFileCreate", 8},
    {"FileIORename", 8},
    {"FileIOCreate", 10},
    {"FileIOCleanup", 11},
    {"FileIOClose", 12},
    {"FileIODelete", 13},
    {"FileIOFileDelete", 14},
    {"RegistryCreate", 15},
    {"RegistrySetValue", 16},
    {"RegistryOpen", 17},
    {"RegistryDelete", 18},
    {"RegistrySetInformation", 19},
    {"RegistryQuery", 20},
    {"RegistryQueryValue", 21},
    {"CallStack", 22},
};
void Cache::add(const Event &event)
{
    if (!procCache.count(event.pid))
    {
        procCache[event.pid] = make_shared<Process>(0L, event.pid, event.pname, event.pcmd, event.ppid);
        procCache[event.pid]->index = event.index;
    }

    if (!procChannel.count(event.pid))
        procChannel[event.pid] = vector<int>(22, 0);

    if (procChannel[event.pid].size() == 0)
        procChannel[event.pid].resize(22, 0);
    procChannel[event.pid][str2id[event.eventname] - 1]++;
}
void Cache::remove(int pid)
{
    if (procCache.count(pid))
    {
        procCache.erase(pid);
        procChannel.erase(pid);
    }
}

void Cache::clear()
{
    procCache.clear();
    procChannel.clear();
}

bool Cache::have(int pid) const
{
    return procCache.count(pid);
}

shared_ptr<Process> Cache::getProcess(int pid)
{
    return procCache[pid];
}

void Cache::setFilename(std::string &filename)
{
    this->filename = filename;
}

void Cache::save()
{
    ofstream fout("X.txt", ios::out | ios::app);
    ofstream lout("L.txt", ios::out | ios::app);
    for (auto &[pid, p] : procCache)
    {
        if (procChannel.count(pid))
        {
            auto &vc = procChannel[pid];
            if (0 < vc.size())
            {
                fout << vc[0];
                for (int i = 1; i < 22; ++i)
                    fout << "," << vc[i];
                fout << endl;
                procChannel.erase(pid);

                lout << p->label << endl;
            }
        }
    }
    fout.close();
    lout.close();
}
