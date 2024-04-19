#include "agent/parser.h"
#include "agent/event.h"
#include "agent/process.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include "agent/parser.h"

using namespace std;
// Windows NT 时间起点，转换为Unix时间戳表示
static const uint64_t EPOCH_AS_FILETIME = ((uint64_t)11644473600LL * (uint64_t)10000000);
static unordered_map<std::string, int> str2etype = {
    {"ProcessStart", 0x1},
    {"ProcessEnd", 0x2},
    {"ThreadStart", 0x4},
    {"ThreadEnd", 0x8},
    {"ImageLoad", 0x10},
    {"FileIOWrite", 0x20},
    {"FileIORead", 0x40},
    {"FileIOFileCreate", 0x80},
    {"FileIORename", 0x100},
    {"FileIOCreate", 0x200},
    {"FileIOCleanup", 0x400},
    {"FileIOClose", 0x800},
    {"FileIODelete", 0x1000},
    {"FileIOFileDelete", 0x2000},
    {"RegistryCreate", 0x4000},
    {"RegistrySetValue", 0x8000},
    {"RegistryOpen", 0x10000},
    {"RegistryDelete", 0x20000},
    {"RegistrySetInformation", 0x40000},
    {"RegistryQuery", 0x80000},
    {"RegistryQueryValue", 0x100000},
    {"CallStack", 0x200000},
};

Event LogParser::parse(const Json::Value &json)
{
    Event event;
    uint64_t ts = json["_source"]["TimeStamp"].asInt64();
    event.timestamp = (ts - EPOCH_AS_FILETIME) / 10000;
    event.eventname = json["_source"]["Event"].asString();
    event.eventid = str2etype[event.eventname];
    event.pid = json["_source"]["PID"].asInt();
    event.pname = json["_source"]["PName"].asString();
    event.pcmd = json["_source"]["args"]["CommandLine"].asString();
    event.ppid = json["_source"]["PPID"].asInt();
    event.ppname = json["_source"]["PPName"].asString();
    event.tid = json["_source"]["TID"].asInt();
    event.index = json["_index"].asString();

    Cache &cache = Singleton<Cache>::getInstance();

    if (event.eventid == 0x1)
    {
        long long uniqueKey = json["_source"]["args"]["UniqueProcessKey"].asInt64();
        event.oid = event.pid;
        event.oname = json["_source"]["args"]["CommandLine"].asString();

        shared_ptr<Process> p = make_shared<Process>(uniqueKey, event.pid, event.pname, event.oname, event.ppid);
        // 获取进程标签
        p->label = getLabel(p, event);
        p->index = event.index;

        // Json::FastWriter writer;
        // // if (p->label)
        // cout << writer.write(json) << endl;

        cache.insert(p);
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid == 0x2)
    {
        Cache &cache = Singleton<Cache>::getInstance();
        // 加入通道
        cache.add(event, 0);
        // 需要先加入通道，再删除进程信息，否则获取不到进程的标签
        cache.remove(event.pid);
    }
    if (event.eventid & 0xC)
    {

        event.oname = json["_source"]["args"]["TThreadId"].asString();
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x10)
    {

        event.oname = json["_source"]["args"]["FileName"].asString();
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x3fe0) // 文件操作
    {

        event.oid = json["_source"]["args"]["FileKey"].asInt64();
        event.oname = json["_source"]["args"]["FileName"].asString();
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x1FC000) // 注册表操作
    {
        event.oname = json["_source"]["args"]["KeyName"].asString();
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x200000)
    {

        // API序列
        stringstream ss;
        string line;
        ss << json["_source"]["args"]["stackInfo"].asString();
        while (getline(ss, line, ','))
        {
            event.oname += line.substr(1 + line.find_last_of(':')) + " ";
        }
        // 加入通道
        cache.add(event, 0);
    }

    return event;
}

int LogParser::getLabel(std::shared_ptr<Process> p, const Event &event)
{

    if (event.index == "k8c64c2ff302f64cf326897af8176d68e" && string::npos != p->name.find("wscript.exe"))
        return 1;
    if (event.index == "kd2ae2596560a8a7591194f7c737bc802" && string::npos != p->name.find("123.exe"))
        return 1;
    if (string::npos != event.pname.find(event.index.substr(1)))
        return 1;
    Cache &cache = Singleton<Cache>::getInstance();
    if (cache.have(event.ppid))
    {
        auto p = cache.getProcess(event.ppid);
        return p->label;
    }
    return 0;
}
Event LabelParser::parse(const Json::Value &json)
{
    Event event;
    uint64_t ts = json["_source"]["TimeStamp"].asInt64();
    event.timestamp = (ts - EPOCH_AS_FILETIME) / 10000;
    event.eventname = json["_source"]["Event"].asString();
    event.eventid = str2etype[event.eventname];
    event.pid = json["_source"]["PID"].asInt();
    event.pname = json["_source"]["PName"].asString();
    event.pcmd = json["_source"]["args"]["CommandLine"].asString();
    event.ppid = json["_source"]["PPID"].asInt();
    event.ppname = json["_source"]["PPName"].asString();
    event.tid = json["_source"]["TID"].asInt();

    if (event.eventid == 0x1)
    {
        int label = 0;
        string index = json["_index"].asString().substr(1);
        if (string::npos != event.pname.find(index))
        {
            label = 1;
        }
        else
        {
            Cache &cache = Singleton<Cache>::getInstance();
            if (cache.have(event.ppid))
            {
                auto p = cache.getProcess(event.ppid);
                label = p->label;
            }
        }
        long long uniqueKey = json["_source"]["args"]["UniqueProcessKey"].asInt64();
        event.oid = event.pid;
        event.oname = json["_source"]["args"]["CommandLine"].asString();
        shared_ptr<Process> p = make_shared<Process>(uniqueKey, event.pid, event.pname, event.oname, event.ppid);
        p->label = label;
        Cache &cache = Singleton<Cache>::getInstance();
        cache.insert(p);
        if (1 == label)
        {
            ofstream fout("/mnt/sdd1/data/sun/labels.txt", ios::app);
            fout << json["_index"].asString() << " " << uniqueKey << " " << event.pid << "\n";
            fout.close();
            // cout << json["_index"].asString() << " " << uniqueKey << " " << event.pid << " " << event.pname << "\n";
        }

        // printf("%lld, %d, %d, %d, %s\n", uniqueKey, event.pid, event.ppid, label, event.oname.c_str());
        return event;
    }
    if (event.eventid == 0x2)
    {
        Cache &cache = Singleton<Cache>::getInstance();
        cache.remove(event.pid);
        return event;
    }
    return event;
}
