#include <fstream>
#include <vector>
#include <iostream>
#include <algorithm>
#include "json/json.h"
#include "agent/process.h"
#include "agent/parser.h"

using namespace std;

void Cache::insert(std::shared_ptr<Process> p)
{
    procCache[p->pid] = p;
}
void Cache::add(const Event &event)
{
    if (!procCache.count(event.pid))
    {
        procCache[event.pid] = make_shared<Process>(0L, event.pid, event.pname, event.pcmd, event.ppid);
        procCache[event.pid]->index = event.index;
        procCache[event.pid]->label = Label::label(event);
    }

    auto &channel = procChannel[event.pid];
    channel[event.cid] += " " + event.eventname + " " + event.oname;

    shared_ptr<Process> p = procCache[event.pid];

    p->total++;
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

void Cache::setSaver(Saver *saver)
{
    this->saver = saver;
}
void Cache::clear()
{
    for (auto &[pid, p] : procCache)
    {
        if (0 < p->cntevents)
            save(pid);
    }
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

void Cache::save(int pid)
{
    auto p = procCache[pid];
    auto &channel = procChannel[pid];

    if (p->index.size() == 0)
        throw runtime_error("error：No index!\n");

    Json::Value json;
    json["index"] = p->index;
    json["unique_key"] = static_cast<Json::Int64>(p->uniqueKey);
    json["pid"] = p->pid;
    json["pname"] = p->name;
    json["label"] = p->label;
    // json["pchannel"] = channel[0];
    // json["fchannel"] = channel[1];
    // json["rchannel"] = channel[2];
    // json["achannel"] = channel[3];
    json["total"] = p->total;
    json["cnt_event"] = p->cntevents;

    Json::FastWriter sw; // 单行输出，效率更高
    saver->write(sw.write(json));

    for (auto &v : channel)
        v.clear();
}
