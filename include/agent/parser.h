#pragma once
#include "event.h"
#include <unordered_set>
#include <unordered_map>
#include <json/json.h>
#include "process.h"

class LogParser
{
public:
    static int getLabel(std::shared_ptr<Process> p, const Event &event);
    Event parse(const Json::Value &json);
};

class LabelParser
{
public:
    static Event parse(const Json::Value &json);
};
