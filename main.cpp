#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <queue>
#include <json/json.h>
#include "elasticlient/client.h"
#include "elasticlient/scroll.h"
#include "agent/process.h"
#include "agent/tools.h"
#include "agent/parser.h"

using namespace std;
// ./main --sql ../conf/search.sql --samples ../conf/train.sample --output cdatasets.train.json
int main(int argc, char **argv)
{
    if (argc < 7)
    {
        printf("Must input filename!\n");
        exit(0);
    }
    printf("%s %s\n", argv[0], argv[1]);
    // Prepare Client for nodes of one Elasticsearch cluster
    std::shared_ptr<elasticlient::Client> client = std::make_shared<elasticlient::Client>(
        std::vector<std::string>({"http://elastic:bupthtles@10.101.169.215:9200/"})); // last / is mandatory
    elasticlient::Scroll scrollInstance(client);

    ifstream in;
    in.open(argv[2], ios::in);
    string sql;
    for (string s; getline(in, s);)
        sql += s;
    in.close();

    in.open(argv[4], ios::in);
    vector<string> samples;
    for (string s; getline(in, s);)
        samples.push_back(move(s));
    in.close();

    string filename = string(argv[6]);
    Saver saver(filename);

    Cache &cache = Singleton<Cache>::getInstance();
    cache.setSaver(&saver);

    for (string &sample : samples)
    {
        cout << "Start to preprocess " << sample << endl;
        // // Scroll all documents of type: docType from testindex which corresponding searchQuery
        scrollInstance.init(sample, "_doc", sql);

        Json::Value res;
        bool isSuccessful = true;

        LogParser parser;
        // 同时发生的数据可能不是有序的，将ProcessEnd后置
        Cache &cache = Singleton<Cache>::getInstance();
        queue<Event> cq;
        // Will scroll for all suitable documents
        while ((isSuccessful = scrollInstance.next(res)))
        {
            if (res["hits"].empty())
                break;

            for (auto &hit : res["hits"])
            {
                Event event = parser.parse(hit);
                long long ts = event.timestamp;

                while (!cq.empty() && cq.front().timestamp < ts)
                {
                    auto e = cq.front();
                    cache.add(e);
                    cache.remove(e.pid);
                    cq.pop();
                }

                if (event.eventid == 0x2)
                {
                    cq.push(event);
                    continue;
                }
                if (event.eventid == 0x1 || !cache.have(event.pid))
                {
                    shared_ptr<Process> p = make_shared<Process>(event.uKey, event.pid, event.pname, event.pcmd, event.ppid);
                    p->label = Label::label(event);
                    p->index = event.index;
                    cache.insert(p);
                }
                cache.add(event);
            }
        }
        scrollInstance.clear();
        cache.clear();
    }

    cout << "End preprocess " << endl;
}
