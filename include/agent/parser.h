#pragma once
#include "event.h"
#include <unordered_set>
#include <unordered_map>
#include <json/json.h>
#include "process.h"

using namespace std;

class LogParser
{
public:
    // static int getLabel(const Event &event);
    Event parse(const Json::Value &json);
};

class Label
{

    static unordered_set<string> white;
    static unordered_set<string> black;

public:
    static int label(const Event &event);
};