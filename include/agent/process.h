#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include "tools.h"
#include "event.h"

struct Process
{
    std::string index;
    long long uniqueKey;
    int pid;
    int ppid;
    std::string name;
    std::string cmd;
    int label = 0;
    int sign;
    int cntevents = 0;

    Process() {}
    Process(long long uniqueKey, int pid, const std::string &name, const std::string &cmd, int ppid) : uniqueKey(uniqueKey), pid(pid), name(name), cmd(cmd), ppid(ppid) {}
};

class Cache : public Singleton<Cache>
{
    std::unordered_map<int, std::shared_ptr<Process>> procCache;
    std::unordered_map<int, std::string[4]> procChannel;
    std::string filename;

public:
    void insert(std::shared_ptr<Process> p);
    void add(const Event &event);
    void remove(int pid);
    void clear();
    bool have(int pid) const;
    std::shared_ptr<Process> getProcess(int pid);
    void setFilename(std::string &filename);
    void save(int pid);
};
