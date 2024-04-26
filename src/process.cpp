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
void Cache::add(const Event &event, int cid)
{
    if (!procCache.count(event.pid))
    {
        procCache[event.pid] = make_shared<Process>(0L, event.pid, event.pname, event.pcmd, event.ppid);
        procCache[event.pid]->index = event.index;
    }

    auto &channel = procChannel[event.pid];
    channel[cid] += " " + event.eventname + " " + event.oname;

    shared_ptr<Process> p = procCache[event.pid];

    if (++(p->cntevents) < 8)
        return;
    save(event.pid);
    p->cntevents %= 8;
}
void Cache::remove(int pid)
{
    if (procCache.count(pid))
    {
        if (0 < procCache[pid]->cntevents)
            save(pid);
        procCache.erase(pid);
        procChannel.erase(pid);
    }
}

void Cache::clear()
{
    for (auto &[pid, p] : procCache)
        if (0 < p->cntevents)
            save(pid);
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

    Json::Value json;
    json["index"] = p->index;
    json["unique_key"] = static_cast<Json::Int64>(p->uniqueKey);
    json["pid"] = p->pid;
    json["label"] = p->label;
    json["channel"] = channel[0];
    channel[0].clear();

    // if (p->label == 1)
    // {
    //     ofstream fout(this->filename, ios::out | ios::app);
    //     if (!fout.is_open())
    //         throw runtime_error("error：can not find or create the file which named \"" + this->filename + "\".");
    //     Json::FastWriter sw; // 单行输出，效率更高
    //     fout << sw.write(json);
    //     fout.close();
    // }
}
