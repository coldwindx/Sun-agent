#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <queue>
#include <json/json.h>
#include <elasticlient/client.h>
#include <elasticlient/scroll.h>
#include <agent/event.h>
#include "agent/parser.h"

// export LD_LIBRARY_PATH=/home/zhulin/workspace/Sun-agent/lib:$LD_LIBRARY_PATH:
// g++ main.cpp ./src/*.cpp -o main -I ./include/ -L ./lib/ -lelasticlient -ljsoncpp -lcpr -lcurl -std=c++17
using namespace std;

int main(int argc, char **argv)
{
    // Prepare Client for nodes of one Elasticsearch cluster
    std::shared_ptr<elasticlient::Client> client = std::make_shared<elasticlient::Client>(
        std::vector<std::string>({"http://elastic:bupthtles@10.101.169.215:9200/"})); // last / is mandatory
    elasticlient::Scroll scrollInstance(client);

    // std::string searchQuery{"{\"query\":{\"terms\":{\"Event.keyword\":[\"ProcessStart\",\"ProcessEnd\",\"ThreadStart\",\"ThreadEnd\",\"ImageLoad\",\"FileIOWrite\",\"FileIORead\",\"FileIOFileCreate\",\"FileIORename\",\"FileIOCreate\",\"FileIOCleanup\",\"FileIOClose\",\"FileIODelete\",\"FileIOFileDelete\",\"RegistryCreate\",\"RegistrySetValue\",\"RegistryOpen\",\"RegistryDelete\",\"RegistrySetInformation\",\"RegistryQuery\",\"RegistryQueryValue\",\"CallStack\"]}},\"sort\":[{\"TimeStamp\":{\"order\":\"asc\",\"unmapped_type\":\"keyword\"}}],\"size\":10000}"};
    // std::string searchQuery{"{\"query\":{\"terms\":{\"Event.keyword\":[\"ProcessStart\",\"ProcessEnd\"]}},\"sort\":[{\"TimeStamp\":{\"order\":\"asc\",\"unmapped_type\":\"keyword\"}}],\"size\":10000}"};
    std::string searchQuery{"{\"query\":{\"terms\":{\"Event.keyword\":[\"ProcessStart\",\"FileIOWrite\",\"FileIORead\",\"FileIOFileCreate\",\"FileIORename\",\"FileIOCreate\",\"FileIOCleanup\",\"FileIOClose\",\"FileIODelete\",\"FileIOFileDelete\",\"TcpIpSendIPV4\", \"TcpIpRecvIPV4\"]}},\"sort\":[{\"TimeStamp\":{\"order\":\"asc\",\"unmapped_type\":\"keyword\"}}],\"size\":10000}"};

    // test
    vector<string> test_samples = {"kad29f77ee86ed9827158347befa8998d", "k2218db42c1b69db72d7432c8d6fcab9d", "kcc378f899d56f8d3c76b9905b47a84a6", "k74d9610a72fa9ed105c927e3b1897c5b", "kba67dd5ab7d6061704f2903573cec303", "k5e271dbfb5803f600b30f7d9945024fd", "kc64eb31c168a78c8b17198b15ba7e638", "k38393408898e353857a18f481cf15935", "kc9ec0d9ff44f445ce5614cc87398b38d", "k21a563f958b73d453ad91e251b11855c", "k643c8c25fbe8c3cc7576bc8e7bcd8a68", "k81fc90c9f339042edc419e0a62a03e17", "k80d2cfccef17caa46226147c1b0648e6", "kdeebbea18401e8b5e83c410c6d3a8b4e", "k732a229132d455b98038e5a23432385d", "kdffd2b26085eddb88743ae3fc7be9eee", "k6992dd450b7581d7c2a040d15610a8c5", "k0c4502d6655264a9aa420274a0ddeaeb", "k209a288c68207d57e0ce6e60ebf60729", "k6e080aa085293bb9fbdcc9015337d309", "k58b70be83f9735f4e626054de966cc94", "keba85b706259f4dc0aec06a6a024609a", "kc24f6144e905b717a372c529d969611e", "k0a47084d98bed02037035d8e3120c241", "k087f42dd5c17b7c42723dfc150a8da42", "ke3dd1eb73e602ea95ad3e325d846d37c", "k33a7c3fe6c663032798a6780bb21599c", "k4edfdc708fb7cb3606ca68b6c288f979", "k77d0a95415ef989128805252cba93dc2", "k168447d837fc71deeee9f6c15e22d4f4", "k6c660f960daac148be75427c712d0134", "k84c82835a5d21bbcf75a61706d8ab549", "kb65b194c6cc134d56ba3acdcc7bd3051", "kd5fee0c6f1d0d730de259c64e6373a0c", "k1de48555aafd904f53e8b19f99658ce8", "k64497a0fa912f0e190359684de92be2d", "k2bbb2d9be1a993a8dfef0dd719c589a0", "ke4e439fc5ade188ba2c69367ba6731b6", "kc24f6144e905b717a372c529d969611e", "ke1e41506da591e55cee1825494ac8f42", "k2bbff2111232d73a93cd435300d0a07e", "k8c64c2ff302f64cf326897af8176d68e", "k00e3b3952d6cfe18aba4554a034f8e55", "kb7be2da288647b28c1697615e8d07b17", "kb572a0486274ee9c0ba816c1b91b87c7", "k25a54e24e9126fba91ccb92143136e9f", "ke3f6878bcafe2463f6028956f44a6e74", "k0880430c257ce49d7490099d2a8dd01a", "k5c7fb0927db37372da25f270708103a2", "k9ce01dfbf25dfea778e57d8274675d6f"};
    vector<string> test_samples_z = {"z_360software", "z_bilibili", "z_baiduwangpan", "z_aiqiyi", "z_hengxingbofangqi", "z_wps_ppt", "z_pdf", "z_pdf_zhuanhuan", "z_dayuchixiaoyu", "z_wangyi_youdaofanyi", "z_readpaper_installer", "z_kuaijianji", "z_douyin", "z_office_installer", "z_leidianmoniqi"};
    // val
    vector<string> val_samples = {"k4a6e3d45e11bae69b64fc879400fcdb6", "kf00aded4c16c0e8c3b5adfc23d19c609", "kb99c2748e46c0f8ed8da08fd933e0d9f", "kcd6590f4d46f4a2b0c9888d030d01447", "k44c185fc8210cff1dabc94c1755f6f23", "k49eb4afe5b817ed56eacf504c80106d1", "k4a5c9e93e3cbb0ad7c7083bf09925abc", "k3981aa980e34be2f97b9f29bd5e98bdd", "k6660b6386c3a860f05da7199d78d2b2f", "k67d32736c5e1300c21329f956da836ab", "k4ab8f1d7af4652b8e70c9e036644ec75", "k05a9d84adb552bfe6590b4f3d6f9a970", "k5ef5cf7dd67af3650824cbc49ffa9999", "kbfe12a8e2169231a3825951ba63f11c9", "k90e6ea15ed18005b431e135186d57abf", "k27e65e2ed2b8c532d2fdafbf923b9a68", "ke60e767e33acf49c02568a79d9cbdadd", "k8203a583c5eef23e5fa7fa9d1506d430", "kc8757716d8d48419fc0568a644f4e704", "kb9a6cce789af6ca22c445d22039dd44a", "kcfd8653d544f79ccd26fb180107eb788", "k9b02b542834573f9502ca83719a73a01", "ke068ee33b5e9cb317c1af7cecc1bacb5", "k23501259ba490cf6fc8e2e7d82a7c22e", "k27b8f8ddde8f8a8a89215f81bf64c1d5", "k8b6bc16fd137c09a08b02bbe1bb7d670", "kd2e194259106bca3b42dc8690d340b59", "k2ca016fa98dd5227625befe9edfaba98", "kf9afb31bc17811e5ab4fa406f105b1fe", "k117c3707f4d8db004a0e7ef86350612b", "kfbb12ff00c62ef58b38385d06abb4f43", "kc7974a145daeb02865fe839b6faf44d6", "kf6f120d1262b88f79debb5d848ac7db9", "k024382eef9abab8edd804548f94b78fc", "kc8132050d594b4554db527e7ed1a061b", "ka0dd1dfbac4b2aaed94b2065a9c9f30c", "k10dcf1d147c4197fba20c86f3d59b777", "k21c2b2d0bfc15b3d4bc72263f9db5547", "k33228a20a7e985f02e2ddd73cccde729", "k1fff77fb1958e7f730bb4de627a24d57", "kf9fc1a1a95d5723c140c2a8effc93722", "ka57ea2a7451b3a071617031c19bebcf5", "kaf2379cc4d607a45ac44d62135fb7015", "k3ef478a7c898e91f09385da44555d986", "kfe1bc60a95b2c2d77cd5d232296a7fa4", "kfc4f9b77b3b2bcc7baed9a4184a51656", "k650c360fc17f15d0cb72a18e9a3499c2", "kd1126f717a1d42450772f63d5a371e44"};
    vector<string> train_samples = {"kcyw-2024_01_11-000001", "kfd7ede21ac7e65ee920e9b437c819f86", "kc99e32fb49a2671a6136535c6537c4d7", "k44ebe5670496f7aa3d5bae72e938670d", "k66f56e58b1726fe7c87d72a45e1aef38", "k5ea93735e0239cf95fb1aaf3ac6317ee", "k04c8bb7931e16af4c3d5269362d07544", "k2e7378639f635aac8dca22a9a6a6e2cc", "kc2767cbb246f2981a0274905cac01ac6", "kb76b5e04ee1c34a706e3b456382e551e", "kef2697aa224266b204127722771bc209", "k8c54bbe3f191a8627bfeeb4cb02634a9", "k0d9aefd8da622cae66f03607b71e67e1", "k6f2e52ac25369f0f8f8edd6584ec0279", "k04ad1d87185dddc361183349a1422bb9", "k65fb5232fcb9c3236f26a89774d767b1", "kd15e1690428a87583b8059dd4d44ca1e", "k987336d00fdbec3bcdb95b078f7de46f", "k59e8d02c3818ad4e4ce74975e9154bc1", "k4663a364837b94824bf804dd54f9f91d", "k2f956b5649ae55091e478be5f3d33913", "kf83fb9ce6a83da58b20685c1d7e1e546", "k0dc058b5d67fee098b9e7b7babc48fa1", "k6b897a5a99499166fa91419bdf783bd4", "k5a1437bc040ebabb2b588200831f5981", "k7939864db15c97bc6ec5c595b59b85f2", "k85b2a7f42dff2d06d9b80acbde26de71", "k5a91f712fd144ea66bfc7c43dce3ffba", "kc3ccde9c3fab53d5c749b2186e997bdc", "k13067ecf3b17d7a6543e368db7f9e5a5", "k35fe9d41aa9c31a1191ae2e7a3f442aa", "k49973e9179195c665b4e55102ac13eb2", "ke3b3e285390c0e2f7d04bd040bec790d", "ke9a4afb843412da3b151ebb412c2fd07", "k7994ec400d2bdc1e18484821650b71fb", "kd002a9d651890fb355b06f1b98ec9172", "kb80103a60fa68e425a4fd200ca223915", "k0f77484639b1193ad66e313040c92571", "k5ef1fdd422951c153db8c39b87e84e5d", "ka89a89474158a2659dfca1627c96e43d", "ke29f7f907c96782adbf18d790086ec08", "k979692cd7fc638beea6e9d68c752f360", "k123bfb167c50be9e360f3b55a04f3a35", "ka31a3b951ad919557deae4d4d8f7b8a0", "k31de54d2714627b215cb8f114c31256f", "k815f827cbedec5631f73178fd1ac9aa8", "k74d200bcb1fae1e6dabdaa115c051099", "ke3b7d39be5e821b59636d0fe7c2944cc", "ka3474f8a6e675b30dcf3e612390c614e", "k447977fa3657facc24006c33dcb97384", "kfb0e8cdaae96f5da8f73b3e30af023fb", "kf75ba194742c978239da2892061ba1b4", "kd2ae2596560a8a7591194f7c737bc802", "kf7186597308adb3a78d356e159ce18b0", "kb83084409598344335bb313288a7034c", "k0bbb5eafade47a9d212a23fc886646b7", "kba375d0625001102fc1f2ccb6f582d91", "k0889138a3894284e97b61f9a310e3e7d", "k63ce67f6aee7b492478468561e8ef17c", "k26b06bf6f0d74ce2fb490bc637381228", "k0ed51a595631e9b4d60896ab5573332f", "kb7a45c21c29d0c3b09cee7b974d03241", "k35487602107011c85a802a006f5a590a", "k2f121145ea11b36f9ade0cb8f319e40a", "k891671a3dbedc9f31325acd29ec912bf"};
    vector<string> train_samples_z = {"z_plantvszombies", "z_kuwoyinyue", "z_kugouyinyue", "z_tencent_qq", "z_tencent_weixin", "z_360_qudongdashi", "z_360_liulanqi", "z_baidu_fanyi", "z_tencent_liulanqi", "z_baidu_liulanqi", "z_feishu", "z_google_liulanqi", "z_sougou_shurufa", "z_shouxinshurufa", "z_360_yasuo", "z_7z", "z_winrar", "z_xunlei", "z_visualstudio_installer", "z_dingding", "z_xiangrikui", "z_360_bizhi", "z_tencent_huiyi", "z_360_bangongzhushou", "z_yueshupdf", "z_todesk", "z_steam", "z_saolei", "z_wangyi_youxiang", "z_baidu_wenku", "z_codeblocks_installer", "z_codeblocks", "z_readpaper", "z_xmind", "z_sketchbook", "z_xiangrikui_yuanchengkongzhi", "z_tuguaishou", "z_ludashi", "z_bandicam", "z_mubu", "z_rainmeter", "z_dism"};
    vector<string> train_sampes_kzl = {"kzl-2024.01.11-000001"};

    vector<string> samples;
    for (auto &s : train_samples_z)
        samples.push_back(move(s));
    for (auto &s : train_sampes_kzl)
        samples.push_back(move(s));

    // string filename = "threatrace.json";
    // Cache &cache = Singleton<Cache>::getInstance();
    // cache.setFilename(filename);

    // unordered_set<string> vis;
    for (string &sample : samples)
    {
        cout << "Start to preprocess " << sample << endl;
        // // Scroll all documents of type: docType from testindex which corresponding searchQuery
        scrollInstance.init(sample, "_doc", searchQuery);

        string scene = "./threatrace/threatrace.json." + sample;
        Json::Value res;
        bool isSuccessful = true;

        LogParser parser;

        long long sts = 0L, ets = 1000L;
        // Will scroll for all suitable documents
        while ((isSuccessful = scrollInstance.next(res)))
        {
            if (res["hits"].empty())
            {
                // last scroll, no more results
                break;
            }
            vector<Event> cq;
            for (auto &hit : res["hits"])
            {
                Event event = parser.parse(hit);
                cq.push_back(move(event));
            }
            ofstream fout(scene, ios::out | ios::app);
            for (auto &ev : cq)
            {
                fout << ev.msg;
            }
            fout.close();
        }
        scrollInstance.clear();
    }

    cout << "End preprocess " << endl;
}
