#include <stdio.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <functional>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include "agent/event.h"
#include "agent/process.h"
#include "agent/parser.h"

using namespace std;
// Windows NT 时间起点，转换为Unix时间戳表示
static const uint64_t EPOCH_AS_FILETIME = ((uint64_t)11644473600LL * (uint64_t)10000000);
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

static unordered_map<std::string, std::function<void(Event &event, const Json::Value &json)>> handlermanager = {
    {"ProcessStart", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x1;
         event.uKey = json["_source"]["args"]["UniqueProcessKey"].asInt64();
         event.oid = event.pid;
         event.oname = subreplace(json["_source"]["args"]["CommandLine"].asString(), "\n", " ");
     }},
    {"ProcessEnd", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x2;
     }},
    {"ThreadStart", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x4;
         event.oname = subreplace(json["_source"]["args"]["TThreadId"].asString(), "\n", " ");
     }},
    {"ThreadEnd", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x8;
         event.oname = subreplace(json["_source"]["args"]["TThreadId"].asString(), "\n", " ");
     }},
    {"ImageLoad", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x10;
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIOWrite", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x20;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIORead", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x40;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIOFileCreate", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x80;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIORename", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x100;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIOCreate", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x200;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["OpenPath"].asString(), "\n", " ");
     }},
    {"FileIOCleanup", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x400;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIOClose", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x800;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIODelete", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x1000;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"FileIOFileDelete", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x2000;
         event.oid = json["_source"]["args"]["FileKey"].asInt64();
         event.oname = subreplace(json["_source"]["args"]["FileName"].asString(), "\n", " ");
     }},
    {"RegistryCreate", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x4000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistrySetValue", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x8000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistryOpen", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x10000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistryDelete", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x20000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistrySetInformation", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x40000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistryQuery", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x40000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"RegistryQueryValue", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x100000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }},
    {"CallStack", [](Event &event, const Json::Value &json)
     {
         event.cid = 0;
         event.eventid = 0x200000;
         event.oname = subreplace(json["_source"]["args"]["KeyName"].asString(), "\n", " ");
     }}};

Event LogParser::parse(const Json::Value &json)
{
    Event event;
    uint64_t ts = json["_source"]["TimeStamp"].asInt64();
    event.timestamp = (ts - EPOCH_AS_FILETIME) / 10000;
    event.eventname = json["_source"]["Event"].asString();
    event.pid = json["_source"]["PID"].asInt();
    event.pname = json["_source"]["PName"].asString();
    event.pcmd = json["_source"]["args"]["CommandLine"].asString();
    event.ppid = json["_source"]["PPID"].asInt();
    event.ppname = json["_source"]["PPName"].asString();
    event.tid = json["_source"]["TID"].asInt();
    event.index = json["_index"].asString();

    auto handle = handlermanager[event.eventname];
    handle(event, json);
    return event;
}

unordered_set<string> Label::white = {
    "360se.exe",
    "aitagent.exe",
    "conhost.exe",
    "cscript.exe",
    "chrome.exe",
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
    "wpsupdate.exe",
    "msedge.exe",
    "Unknown",
    "wps.exe",
    "csrss.exe",
    "fpprotect.exe",
    "TsService.exe",
    "dwm.exe",
    "QiyiService.exe",
    "wpscenter.exe",
    "ChsIME.exe",
    "winlogon.exe",
    "Feishu.exe",
    "igfxEM.exe",
    "CatLink.exe",
    "logioptionsplus_agent.exe",
    "MsMpEng.exe",
    "OneApp.IGCC.WinService.exe",
    "WeChatAppEx.exe",
};
unordered_set<string> Label::black = {
    "C:\\Windows\\System32\\vds.exe",
    "C:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe -secured -Embedding",
    "C:\\Windows\\system32\\svchost.exe -k iissvcs",
    "C:\\Windows\\System32\\inetsrv\\iisrstas.exe -Embedding",
    "C:\\Windows\\System32\\iisreset.exe /start /fail=1",
    "C:\\Windows\\system32\\svchost.exe -k netsvcs",
    "C:\\Windows\\system32\\svchost.exe -k NetworkService",
    "C:\\Windows\\system32\\SearchIndexer.exe /Embedding",
    "C:\\Windows\\System32\\svchost.exe -k swprv",
    "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding", // *
    "C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding",          // *
    "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff",
    "C:\\Windows\\system32\\vssvc.exe",
    "C:\\Windows\\System32\\vds.exe",
    "C:\\Windows\\System32\\vdsldr.exe -Embedding",
    "C:\\Windows\\SysWOW64\\DllHost.exe /Processid:{45BA127D-10A8-46EA-8AB7-56EA9078943C}",
    "C:\\Windows\\system32\\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
    "C:\\Windows\\System32\\svchost.exe -k swprv",
    "C:\\Windows\\system32\\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask",
    "C:\\Windows\\system32\\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState",
    "C:\\Windows\\system32\\wbem\\unsecapp.exe -Embedding",
    "C:\\Windows\\System32\\sdiagnhost.exe -Embedding",
    "C:\\Windows\\System32\\skydrive.exe -Embedding",
    "C:\\Windows\\system32\\sc.exe start w32time task_started",
    "netsh  advfirewall set currentprofile state off",
    "netsh  firewall set opmode mode=disable",
    "C:\\Windows\\system32\\wbengine.exe",
    "C:\\Windows\\system32\\aitagent.EXE /increment",
    "timeout  -c 5",
    "C:\\Windows\\system32\\WerFault.exe -k -rq",
    "taskhost.exe /RuntimeWide",
    "taskhostex.exe Regular",
    "taskhost.exe SYSTEM",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2576",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2604",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2328",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2580",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2604",
    "C:\\Windows\\system32\\WerFault.exe -u -p 2868 -s 5672",
    "C:\\Windows\\system32\\WerFault.exe -u -p 3188 -s 2116",
    "C:\\Windows\\System32\\svchost.exe -k WerSvcGroup",
    "C:\\Windows\\system32\\vssadmin.exe Delete Shadows /Quiet /All",
    "taskkill  -f -im pg_ctl.exe",
    "taskkill  -f -im fdlauncher.exe",
    "net  stop MSSQL$MSFW",
};

int Label::label(const Event &event)
{
    // 来自良性样本的全部为正常
    if (event.index == "kcyw-2024_01_11-000001")
        return 0;
    if (event.index[0] == 'z')
        return 0;
    // 勒索软件启动进程
    if (event.index == "k0dc058b5d67fee098b9e7b7babc48fa1" && event.pname == "Abandon.exe")
        return 1;
    if (event.index == "k8c64c2ff302f64cf326897af8176d68e" && string::npos != event.pname.find("wscript.exe"))
        return 1;
    if (event.index == "kd2ae2596560a8a7591194f7c737bc802" && string::npos != event.pname.find("123.exe"))
        return 1;
    if (string::npos != event.pname.find(event.index.substr(1)))
        return 1;
    // 断链的恶意进程
    if (event.index == "" && event.pname == "Locator.exe")
        return 1;
    // 黑名单
    if (black.count(event.pcmd))
        return 1;
    // 基于派生关系
    Cache &cache = Singleton<Cache>::getInstance();
    if (cache.have(event.ppid))
        return cache.getProcess(event.ppid)->label;
    // 白名单
    if (white.count(event.pname))
        return 0;
    // 默认为恶意
    return 1;
}