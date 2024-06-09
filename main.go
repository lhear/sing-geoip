package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

type RuleUrl struct {
	v4 string
	v6 string
}

var (
	RULE_URL = &RuleUrl{
		v4: "https://raw.githubusercontent.com/lhear/china-ip-list/master/cn_ipv4.txt",
		v6: "https://raw.githubusercontent.com/lhear/china-ip-list/master/cn_ipv6.txt",
	}
)

func main() {
	v4, err := GetUrlContent(RULE_URL.v4)
	if err != nil {
		log.Fatalln(err.Error())
	}
	v6, err := GetUrlContent(RULE_URL.v6)
	if err != nil {
		log.Fatalln(err.Error())
	}
	d, err := ConvertToJSON(strings.Split(strings.Trim(string(v4)+string(v6), "\n"), "\n"))
	if err != nil {
		log.Fatalln(err.Error())
	}
	os.MkdirAll("rule-set", os.ModePerm)
	CompileRuleSet(d, "rule-set/cn.srs")
}

func GetUrlContent(url string) ([]byte, error) {
	var data []byte
	var err error

	if strings.HasPrefix(url, "https://") {
		response, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch data: %v", err)
		}
		defer response.Body.Close()

		data, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read data: %v", err)
		}
	} else {
		data, err = os.ReadFile(url)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %v", err)
		}
	}
	return data, nil
}

func ConvertToJSON(ips []string) ([]byte, error) {
	jsonData := map[string]interface{}{
		"version": 1,
		"rules": []map[string]interface{}{
			{
				"ip_cidr": ips,
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("failed to generate JSON data: %v", err)
	}

	return jsonBytes, nil
}

func CompileRuleSet(sourceJson []byte, outputPath string) error {
	var err error
	content := sourceJson
	plainRuleSet, err := sjson.UnmarshalExtended[option.PlainRuleSetCompat](content)
	if err != nil {
		return err
	}
	ruleSet := plainRuleSet.Upgrade()
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	err = srs.Write(outputFile, ruleSet)
	if err != nil {
		outputFile.Close()
		os.Remove(outputPath)
		return err
	}
	outputFile.Close()
	return nil
}
