{
	"query": {
		"terms": {
			"Event.keyword": ["ProcessStart", "ProcessEnd", "ThreadStart", "ThreadEnd", "ImageLoad", "FileIOWrite", "FileIORead", "FileIOFileCreate", "FileIORename", "FileIOCreate", "FileIOCleanup", "FileIOClose", "FileIODelete", "FileIOFileDelete", "RegistryCreate", "RegistrySetValue", "RegistryOpen", "RegistryDelete", "RegistrySetInformation", "RegistryQuery", "RegistryQueryValue", "CallStack"]
		}
	},
	"sort": [{
		"TimeStamp": {
			"order": "asc",
			"unmapped_type": "keyword"
		}
	}],
	"size": 10000
}