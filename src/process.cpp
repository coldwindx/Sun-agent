#include <fstream>
#include <vector>
#include <iostream>
#include "agent/process.h"
using namespace std;

void Cache::insert(std::shared_ptr<Process> p)
{
    procCache[p->pid] = p;
}
void Cache::add(const Event &event, int cid)
{
    if (!procCache.count(event.pid))
        return; // 不在记录内的进程
    // procCache[event.pid] = make_shared<Process>(event.pid, event.pid, event.pname, event.pcmd, event.ppid);

    auto &channel = procChannel[event.pid];
    channel[cid].push_back(move(event.eventname));
    channel[cid].push_back(move(event.oname));

    shared_ptr<Process> p = procCache[event.pid];

    if (++(p->cntevents) < 10)
        return;
    save(event.pid);
    p->cntevents %= 10;
}
void Cache::remove(int pid)
{
    if (procCache.count(pid))
    {
        save(pid);
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

void Cache::save(int pid)
{
    auto p = procCache[pid];
    auto &channel = procChannel[pid];
    ofstream fout(this->filename, ios::app);
    fout << p->index << "\t" << p->uniqueKey << "\t" << p->pid << "\t" << p->label << "\n";
    for (int i = 0; i < 1; ++i)
    {
        for (auto &x : channel[i])
            fout << '\t' << x; // 命令行中存在空格，不能使用空格划分
        fout << "\n";
        channel[i].clear();
    }
    fout.close();
}
