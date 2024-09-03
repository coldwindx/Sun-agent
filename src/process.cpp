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
        // auto p = procCache[pid];
        // if (procCache.count(p->ppid))
        //     cout << p->ppid << "(" << procCache[p->ppid]->label << ")"
        //          << ":" << procCache[p->ppid]->name << "--->" << p->pid << "(" << p->label << ")" << (p->cmd == "" ? p->name : p->cmd) << endl;
        // else
        //     cout << p->ppid << "--->" << p->pid << "(" << p->label << ")" << (p->cmd == "" ? p->name : p->cmd) << endl;
        procCache.erase(pid);
        procChannel.erase(pid);
    }
}

void Cache::clear()
{
    for (auto &[pid, p] : procCache)
    {
        // if (procCache.count(p->ppid))
        //     cout << p->ppid << "(" << procCache[p->ppid]->label << ")"
        //          << ":" << procCache[p->ppid]->name << "--->" << p->pid << "(" << p->label << ")" << (p->cmd == "" ? p->name : p->cmd) << endl;
        // else
        //     cout << p->ppid << "--->" << p->pid << "(" << p->label << ")" << (p->cmd == "" ? p->name : p->cmd) << endl;
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

void Cache::setFilename(std::string &filename)
{
    this->filename = filename;
    this->fp = fopen(filename.c_str(), "w+");
    // fprintf(this->fp, "index,unique_key,pid,pname,label,pchannel,fchannel,rchannel,achannel\n");
    fprintf(this->fp, "index,unique_key,pid,pname,label,channel\n");
}

void Cache::save(int pid)
{
    auto p = procCache[pid];
    auto &channel = procChannel[pid];

    if (p->index.size() == 0)
        throw runtime_error("error：No index!\n");

    for (auto &v : channel)
        std::replace(v.begin(), v.end(), ',', ' ');
    // fprintf(this->fp, "%s,%ld,%d,%s,%d,%s,%s,%s,%s\n",
    //         p->index.c_str(), static_cast<Json::Int64>(p->uniqueKey), p->pid, p->name.c_str(), p->label,
    //         channel[0].c_str(), channel[1].c_str(), channel[2].c_str(), channel[3].c_str());

    fprintf(this->fp, "%s,%ld,%d,%s,%d,%s\n",
            p->index.c_str(), static_cast<Json::Int64>(p->uniqueKey), p->pid, p->name.c_str(), p->label, channel[0].c_str());

    for (auto &v : channel)
        v.clear();
}
