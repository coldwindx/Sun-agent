#pragma once
#include <string>
#include <json/json.h>

struct Event
{
    std::string index;     // 索引
    long long timestamp;   // 时间戳
    int eventid;           // 事件ID
    std::string eventname; // 事件名
    int pid;               // 进程ID
    std::string pname;     // 进程名
    std::string pcmd;      // 进程命令行
    int ppid;              // 父进程ID
    std::string ppname;    // 父进程名
    int tid;               // 线程ID
    long long oid;         // 事件对象ID
    std::string oname;     // 事件对象名
};