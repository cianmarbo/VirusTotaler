package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type AnalysisResults struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineVersion string `json:"engine_version"`
	Result        string `json:"result"`
	Method        string `json:"method"`
	EngineUpdate  string `json:"engine_update"`
}

type TotalVotesResponse struct {
	Harmless  string `json:"harmless"`
	Malicious string `json:"malicious"`
}

type ScanResponseAttributes struct {
	TypeDescription      string                        `json:"type_description"`
	Tlsh                 string                        `json:"tlsh"`
	VHash                string                        `json:"vhash"`
	TypeTags             [3]string                     `json:"type_tags"`
	Names                [3]string                     `json:"names"`
	LastModificationDate int                           `json:"last_modification_date"`
	TypeTag              string                        `json:"type_tag"`
	TimesSubmitted       int                           `json:"times_submitted"`
	TotalVotes           map[string]TotalVotesResponse `json:"total_votes"`
	Size                 int                           `json:"size"`
	TypeExtension        string                        `json:"type_extension"`
	LastSubmissionDate   int                           `json:"last_submission_date"`
	MeaningfulName       string                        `json:"meaningful_name"`
	LastAnalysisResults  map[string]AnalysisResults    `json:"last_analysis_results"`
}

type Response struct {
	Data map[string]ScanResponseAttributes `json:"data"`
}

func main() {

	// resp, err := http.Get("https://www.virustotal.com/api/v3/files/01d0ed4638e7490380b2dac5db0a87b31b9d605d6bae489bc3f7ae5023dad1e8")

	var TestItem string = os.Args[1]
	var ApiKey string = os.Args[2]
	var Url string = "https://www.virustotal.com/api/v3/files/" + TestItem

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, Url, nil)
	req.Header.Add("x-apikey", ApiKey)
	resp, err := client.Do(req)

	if err != nil {
		fmt.Errorf("GET request failed")
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		fmt.Errorf("Failed to read HTTP response body")
	}

	var data Response
	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Errorf("Failed to decode HTTP response")
	}

	// lmao, err := json.Marshal(data)
	// fmt.Println(string(lmao))

	// json_body := string(body)
	// log.Println(json_body)

}
