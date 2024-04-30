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

static std::string subreplace(const std::string &resource_str, const std::string &sub_str, const std::string &new_str)
{
    std::string dst_str = resource_str;
    std::string::size_type pos = 0;
    while ((pos = dst_str.find(sub_str)) != std::string::npos) // 替换所有指定子串
    {
        dst_str.replace(pos, sub_str.length(), new_str);
    }
    return dst_str;
}

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
        event.oname = subreplace(json["_source"]["args"]["CommandLine"].asString(), "\n", " ");

        shared_ptr<Process> p = make_shared<Process>(uniqueKey, event.pid, event.pname, event.oname, event.ppid);
        // 获取进程标签
        p->label = getLabel(p, event);
        p->index = event.index;
        // cout << p->ppid << "-->" << p->pid << "(" << p->label << ")"
        //      << ":" << p->cmd << endl;
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
        event.oname = subreplace(json["_source"]["args"]["TThreadId"].asString(), "\n", " ");
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x10)
    {
        event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x3fe0) // 文件操作
    {

        event.oid = json["_source"]["args"]["FileKey"].asInt64();
        event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
        // 加入通道
        cache.add(event, 0);
    }
    if (event.eventid & 0x1FC000) // 注册表操作
    {
        event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
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
        event.oname = subreplace(event.oname, "\n", " ");
        // 加入通道
        cache.add(event, 0);
    }
    return event;
}

static unordered_set<string> white = {
    "360se.exe",
    "aitagent.exe",
    "conhost.exe",
    "cscript.exe",
    "explorer.exe",
    "fastpdf.exe",
    "fphelper.exe",
    "icacls.exe",
    "iisreset.exe",
    "iisrstas.exe",
    "lsass.exe",
    "MicrosoftEdgeUpdate.exe",
    "mshta.exe",
    "mtstocom.exe",
    "net.exe",
    "netsh.exe",
    "ngentask.exe",
    "olgywe.exe",
    "osk.exe",
    "p1q135no.exe",
    "PING.EXE",
    "QQBrowser.exe",
    "schtasks.exe",
    "SearchFilterHost.exe",
    "SearchIndexer.exe",
    "SearchProtocolHost.exe",
    "SECOH-QAD.exe",
    "ServiceModelReg.exe",
    "services.exe",
    "setupsqm.exe",
    "sevnz.exe",
    "sftp-server.exe",
    "SkyDrive.exe",
    "SMSvcHost.exe",
    "SppExtComObj.Exe",
    "sppsvc.exe",
    "sshd.exe",
    "StellarPlayer.exe",
    "svchost.exe",
    "systems.exe",
    "takeown.exe",
    "taskdl.exe",
    "taskeng.exe",
    "taskhostex.exe",
    "timeout.exe",
    "Updater.exe",
    "w32tm.exe",
    "WerFault.exe",
    "wermgr.exe",
    "WinRAR.exe",
    "wpscloudsvr.exe",
    "wpsupdate.exe"};
static unordered_set<string> black = {
    "C:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe -secured -Embedding",
    "C:\\Windows\\system32\\svchost.exe -k netsvcs",
    "C:\\Windows\\system32\\svchost.exe -k NetworkService",
    "C:\\Windows\\system32\\SearchIndexer.exe /Embedding",
    "C:\\Windows\\System32\\svchost.exe -k swprv",
    "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
    "\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff",
    "C:\\Windows\\system32\\vssvc.exe",
    "C:\\Windows\\System32\\vdsldr.exe -Embedding",
    "C:\\Windows\\SysWOW64\\DllHost.exe /Processid:{45BA127D-10A8-46EA-8AB7-56EA9078943C}",
    "C:\\Windows\\system32\\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
    "C:\\Windows\\System32\\svchost.exe -k swprv",
};

int LogParser::getLabel(std::shared_ptr<Process> p, const Event &event)
{
    // 来自良性样本的全部为正常
    if (event.index == "kcyw-2024_01_11-000001")
        return 0;
    // 根据勒索软件的派生关系，确定性的恶意标签
    if (event.index == "k0dc058b5d67fee098b9e7b7babc48fa1" && p->name == "Abandon.exe")
        return 1;
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
    if (string::npos != event.ppname.find(event.index.substr(1)))
        return 1;
    // 根据命令行确定恶意标签
    if (black.count(p->cmd))
        return 1;
    // 系统进程设置为良性
    if (white.count(p->name))
        return 0;
    // 默认为恶意
    return 1;
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
