package main

import (
	"os"
	"fmt"
	"math"
	"time"
	"os/exec"
	"runtime"
	"reflect"
	"strconv"
	"strings"
	"net/http"
	"math/rand"
	"html/template"
	"path/filepath"	
)


// PageVariables struct to hold data for rendering HTML templates
type PageVariables struct {
	ImageInfo   			map[string]int
	HideImages  			bool
	SessionName 			string
	SelectedImages 			map[string]int
	RandomImageURL 			string
	TestClicked    			bool
	ThreatMitigated 		bool
	Opportunities  			[]string
	OpportunityImages 		map[string]int
    AssetImages       		map[string]int
    ActiveThreats       	map[string]int
    Capital					int
    InterestCharged			int
    Reputation				int
    Turn					int
    EnableTempSoC			bool

}

// Using this for opportunity cards and asset cards with partial functionality 
type Card struct {
	// Asset - Fully Functional
	// Opportunity - Baseline
	Requires  []string
	// Asset - 1 = Only 1 attack mitigated / 50 = 50% mitigated (impacts)
	// Opportunity - Rep, capital
	Bonus     []int
	// Asset - Threat it mitigates
	// Opportunity - Fail condition / trigger, rep cost, capital cost, lose contract
	ThreatImpact []string
}

var (
	setupFinished bool = false
	state = make(map[string]map[string]int)
	startingAssetImages = map[string]int{
		"Assets/IDS_Card.png": 15000,
		"Assets/IPS_Card.png": 20000,
		"Assets/Firewall_Card.png": 5000,
		"Assets/Sec_Analyst_Card.png": 40000,	
	}
	assetCardMapping = map[string][]string{
		"Assets/IDS_Card.png": {"Network_Scan", "Network_Intrusion"},
		"Assets/IPS_Card.png": {"Network_Scan", "Network_Intrusion"},
		"Assets/Firewall_Card.png": {"Data_Exfil", "Vulnerability", "Phishing_Attack"},
		"Assets/SoC_Card.png": {"Network_Scan", "Network_Intrusion", "Data_Exfil", "Insider_Threat", "Phishing_Attack"},
		"Assets/Sec_Analyst_Card.png": {"Phishing_Attack", "Sec_Misconfig", "Reg_Audit"},
		"Assets/Data_Backups_Card.png": {"Ransomware"},
		"Assets/Pen_Test_Card.png": {"Network_Intrusion", "Vulnerability", "Sec_Misconfig", "Reg_Audit"},
		"Assets/SIEM_Card.png": {"Insider_Threat", "Phishing_Attack"},
		"Assets/Sec_Governance_Card.png": {"Reg_Audit"},
	}
	threatCardMapping = map[string][]string{
	// rep, capitial, Linked threats (for next turn), Persistant
		"Threats/Network_Scan_Card.png": {"1", "10000", "", "False"},
		"Threats/Network_Intrusion_Card.png": {"0", "0", "Data_Exfil;Vulnerability", "True"},
		"Threats/Data_Exfil_Card.png": {"3", "30000", "", "False"},
		"Threats/Insider_Threat_Card.png": {"0", "0", "Data_Exfil;Sec_Misconfig", "True"},
		"Threats/Phishing_Attack_Card.png": {"0", "0", "Insider_Threat", "False"},
		"Threats/Ransomware_Card.png": {"2", "50000", "", "False"},
		"Threats/Vulnerability_Card.png": {"2", "20000", "Data_Exfil;Ransomware", "False"},
		"Threats/Sec_Misconfig_Card.png": {"0", "0", "Vulnerability", "False"},
		"Threats/Reg_Audit_Card.png": {"1", "10000", "", "False"},
	}
	
	requireSoCSIEM = []string{"Assets/IDS_Card.png", "Assets/IPS_Card.png", "Assets/Firewall_Card.png"}
	
	IDS = Card{
		Requires:  []string{"Assets/SIEM_Card.png", "Assets/SoC_Card.png"},
		Bonus:     []int{50},
		ThreatImpact: []string{"Network_Scan", "Network_Intrusion"},
	}
	IPS = Card{
		Requires:  []string{"Assets/SIEM_Card.png", "Assets/SoC_Card.png"},
		Bonus:     []int{1},
		ThreatImpact: []string{"Network_Scan", "Network_Intrusion"},
	}
	Firewall = Card{
		Requires:  []string{"Assets/SIEM_Card.png", "Assets/SoC_Card.png"},
		Bonus:     []int{50},
		ThreatImpact: []string{"Data_Exfil", "Vulnerability", "Phishing_Attack"},
	}
	
	
	MoD = Card{
		Requires:  []string{"Assets/Sec_Governance_Card.png", "Assets/Pen_Test_Card.png", "Assets/Data_Backups_Card.png"},
		Bonus:     []int{2, 20000},
		ThreatImpact: []string{"Reg_Audit", "4", "30000", "True"},
	}
	FinTech = Card{
		Requires:  []string{"Assets/Sec_Governance_Card.png", "Assets/Pen_Test_Card.png", "Assets/SIEM_Card.png"},
		Bonus:     []int{1, 40000},
		ThreatImpact: []string{"Reg_Audit;Vulnerability", "0", "0.5;Cost", "False"},
	}
	TeleComs = Card{
		Requires:  []string{"Assets/IPS_Card.png", "Assets/Firewall_Card.png", "Assets/Data_Backups_Card.png"},
		Bonus:     []int{1, 20000},
		ThreatImpact: []string{"Network_Scan;Network_Intrusion", "0", "0.1;Capital", "False"},
	}
	Gov = Card{
		Requires:  []string{"Assets/Sec_Governance_Card.png", "Assets/Pen_Test_Card.png", "Assets/Sec_Analyst_Card.png"},
		Bonus:     []int{2, 15000},
		ThreatImpact: []string{"Reg_Audit;Data_Exfil", "4", "0", "True"},
	}
	Transport = Card{
		Requires:  []string{"Assets/Sec_Analyst_Card.png", "Assets/Data_Backups_Card.png"},
		Bonus:     []int{1, 30000},
		ThreatImpact: []string{"Sec_Misconfig;Vulnerability;Ranswomware", "0", "0.05;Capital", "True;Ransomware"},
	}
	Multimedia = Card{
		Requires:  []string{"Assets/Firewall_Card.png", "Assets/IDS_Card.png", "Assets/IPS_Card.png"},
		Bonus:     []int{1, 25000},
		ThreatImpact: []string{"Data_Exfil", "1", "30000", "True"},
	}
	Healthcare = Card{
		Requires:  []string{"Assets/Sec_Governance_Card.png", "Assets/Sec_Analyst_Card.png", "Assets/Data_Backups_Card.png"},
		Bonus:     []int{1, 15000},
		ThreatImpact: []string{"Vulnerability;Ransomware", "2", "15000", "False"},
	}
	Energy = Card{
		Requires:  []string{"Assets/Sec_Governance_Card.png", "Assets/SoC_Card"},
		Bonus:     []int{1, 40000},
		ThreatImpact: []string{"Vulnerability;Ransomware", "0", "0.5;Cost", "False"},
	}
	
	opportunityCardMapping = map[string]Card{
		"MoD":MoD,
		"FinTech":FinTech,
		"TeleComs":TeleComs,
		"Gov":Gov,
		"Transport":Transport,
		"Multimedia":Multimedia,
		"Healthcare":Healthcare,
		"Energy":Energy,
	}
)


func renderTemplate(w http.ResponseWriter, tmplFile string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/" + tmplFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}


func getFilesInDirectory(directory, extension string) ([]string, error) {
	var files []string

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), extension) {
			files = append(files, info.Name())
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}


func getSharedKeys(map1, map2 interface{}) []string {
	var sharedKeys []string

	if reflect.TypeOf(map1).Kind() != reflect.Map || reflect.TypeOf(map2).Kind() != reflect.Map {
		return sharedKeys
	}

	for _, key := range reflect.ValueOf(map1).MapKeys() {
		if reflect.ValueOf(map2).MapIndex(key).IsValid() {
			sharedKeys = append(sharedKeys, fmt.Sprint(key.Interface()))
		}
	}

	return sharedKeys
}


func containsSubstring(value string, substring string) bool {
	return strings.Contains(value, substring)
}


func compareStringSlices(slice1, slice2 []string) bool {
	presenceMap := make(map[string]bool)

	for _, element := range slice2 {
		presenceMap[element] = true
	}

	for _, element := range slice1 {
		if !presenceMap[element] {
			return false
		}
	}
	return true
}


func getKeys(inputMap interface{}) ([]string, error) {
	mapValue := reflect.ValueOf(inputMap)

	if mapValue.Kind() != reflect.Map {
		return nil, fmt.Errorf("input is not a map")
	}

	keys := make([]string, 0, mapValue.Len())
	mapKeys := mapValue.MapKeys()

	for _, key := range mapKeys {
		keys = append(keys, fmt.Sprintf("%v", key.Interface()))
	}

	return keys, nil
}


func removeItem(slice []string, itemToRemove string) []string {
	for i, item := range slice {
		if item == itemToRemove {
			// Found the item, remove it by slicing the slice
			// [0:i] is everything before the item, [i+1:] is everything after the item
			slice = append(slice[:i], slice[i+1:]...)
			break
		}
	}
	return slice
}


func isValuePresent(slice []string, value string) bool {
    for _, element := range slice {
        if element == value {
            return true
        }
    }
    return false
}

func uniqueValues(input []string) []string {
    uniqueMap := make(map[string]bool)
    uniqueSlice := make([]string, 0)

    for _, element := range input {
        if _, found := uniqueMap[element]; !found {
            uniqueMap[element] = true
            uniqueSlice = append(uniqueSlice, element)
        }
    }

    return uniqueSlice
}


func removeSubstrings(input []string, delimiter string) []string {
	var result []string

	for _, str := range input {
		splitStr := strings.Split(str, delimiter)

		result = append(result, splitStr[0])
	}

	return result
}


func openBrowser(uri string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", uri)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", uri)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}


func checkOddEven(num int) int {
	if num%2 == 0 {
		return 2 // Even
	}
	return 1 // Odd
}


func main() {
	http.HandleFunc("/", HomePage)
	http.HandleFunc("/submit", HandleSubmit)
	http.HandleFunc("/home", SelectedImagesPage)
	http.HandleFunc("/turn", HandleTurn)
	http.HandleFunc("/opportunities", HandleOpportunities)
	http.HandleFunc("/assets", HandleAssets)
	http.HandleFunc("/manage", HandleThreats)
	
	// Launch the default web browser
	err := openBrowser("http://localhost:8080")
	if err != nil {
		fmt.Println("Error opening browser:", err)
		os.Exit(1)
	}

	http.Handle("/Cards/", http.StripPrefix("/Cards/", http.FileServer(http.Dir("Cards"))))

	http.ListenAndServe(":8080", nil)
}


func HomePage(w http.ResponseWriter, r *http.Request) {
	
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hideImages := r.URL.Query().Get("noImages") == "true"

	pageVariables := PageVariables{
		ImageInfo:   	startingAssetImages,
		HideImages:  	hideImages,
		SessionName: 	r.URL.Query().Get("session"),
	}
	
	if setupFinished {
		sessionName := r.URL.Query().Get("session")
		redirectURL := "/home?session=" + sessionName
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	err = tmpl.Execute(w, pageVariables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}


func HandleSubmit(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    totalValueStr := r.FormValue("totalValue")
	totalValueFloat, err := strconv.ParseFloat(totalValueStr, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	totalValue := int(math.Round(totalValueFloat))

    selectedOpportunityImages := make(map[string]int)
    selectedAssetImages := make(map[string]int)
    capitalValue := map[string]int{
    	"capitalValue": totalValue,
    }
    
    repValue := map[string]int{
    	"repValue": 0,
    }
    
    turnValue := map[string]int{
    	"turn": 0,
    }
    
    soCEnabledTurn := map[string]int{
    	"soCEnabledTurn": 0,
    }
    
    disableSecAnalyst := map[string]int{
    	"disableSecAnalyst": 0,
    }
    
    insidertLinkedTurn := map[string]int{
    	"linkedTurn": 0,
    }
    
    intrustionLinkedTurn := map[string]int{
    	"linkedTurn": 0,
    }
    
    for key, values := range r.Form {
        if strings.HasPrefix(key, "selectedImages") && len(values) > 0 {
            imageName := values[0]
            costKey := "cost_" + imageName
            cost, err := strconv.Atoi(r.FormValue(costKey))
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            if containsSubstring(imageName, "Opportunities") {
                selectedOpportunityImages[imageName] = cost
            } else {
                selectedAssetImages[imageName] = cost
            }
        }
    }

    sessionName := r.URL.Query().Get("session")
    state[sessionName+"-opportunities"] = selectedOpportunityImages
    state[sessionName+"-assets"] = selectedAssetImages
    state[sessionName+"-capital"] = capitalValue
    state[sessionName+"-reputation"] = repValue
    state[sessionName+"-turn"] = turnValue
    state[sessionName+"-tempSoCTurn"] = soCEnabledTurn
    state[sessionName+"-disableSecAnalyst"] = disableSecAnalyst
    state[sessionName+"-insidertLinkedTurn"] = insidertLinkedTurn
    state[sessionName+"-intrustionLinkedTurn"] = intrustionLinkedTurn

    redirectURL := "/home?session=" + sessionName
    setupFinished = true
    http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}


func SelectedImagesPage(w http.ResponseWriter, r *http.Request) {
    sessionName := r.URL.Query().Get("session")

    selectedOpportunityImages, okOpportunity := state[sessionName+"-opportunities"]
    selectedAssetImages, okAsset := state[sessionName+"-assets"]
    capitalValue, _ := state[sessionName+"-capital"]
    repValue, _ := state[sessionName+"-reputation"]

    if !okOpportunity {
        selectedOpportunityImages = make(map[string]int)
    }

    if !okAsset {
        selectedAssetImages = make(map[string]int)
    }

    tmpl, err := template.ParseFiles("templates/home.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    pageVariables := PageVariables{
        OpportunityImages: 	selectedOpportunityImages,
        AssetImages:       	selectedAssetImages,
        Capital:			capitalValue["capitalValue"],
        Reputation:			repValue["repValue"],
    }

    err = tmpl.Execute(w, pageVariables)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}


//TODO - Add in fail condition triggers for contracts
func HandleTurn(w http.ResponseWriter, r *http.Request) {
	interest := 0.0
	enableTempSoC := false
    
	testClicked := false
    if cookie, err := r.Cookie("testClicked"); err == nil && cookie.Value == "true" {
        testClicked = true
    }

    http.SetCookie(w, &http.Cookie{Name: "testClicked", Value: "", MaxAge: -1, Path: "/"})

	sessionName := r.URL.Query().Get("session")
    selectedOpportunityImages, _ := state[sessionName+"-opportunities"]
    selectedAssetImages, _ := state[sessionName+"-assets"]
    activeThreats, okActiveThreats := state[sessionName+"-threats"]
	capitalValue, _ := state[sessionName+"-capital"]
	repValue, _ := state[sessionName+"-reputation"]
	turnValue,_ := state[sessionName+"-turn"]
	soCEnabledTurn, _ := state[sessionName+"-tempSoCTurn"]
	disableSecAnalyst, _ := state[sessionName+"-disableSecAnalyst"]
	
	if disableSecAnalyst["disableSecAnalyst"] == 1{
		selectedAssetImages["Assets/Sec_Analyst_Card.png"] = 40000
		disableSecAnalyst["disableSecAnalyst"] = 0
	}
	
	turnValue["turnValue"] ++
	
	if !okActiveThreats {
		activeThreats = make(map[string]int)
	}
    
	assetDetails := r.FormValue("assetDetails")

	selectedAsset := strings.Fields(assetDetails)
	
	assetToSellDetails := r.FormValue("assetToSell")

	rawSoldAsset := strings.Fields(assetToSellDetails)
	
	if len(rawSoldAsset) > 0{
		soldAssetDetails := strings.Split(rawSoldAsset[0], ";")
		
		cost, err := strconv.Atoi(soldAssetDetails[1])
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
		asset := soldAssetDetails[0]

		delete(selectedAssetImages, asset)
		
		capitalValue["capitalValue"] += cost
	}
	
	for _, rawAssetDetails := range selectedAsset {
	
		assetDetails := strings.Split(rawAssetDetails, ";")
		
		cost, err := strconv.Atoi(assetDetails[1])
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
		asset := assetDetails[0]

		selectedAssetImages[asset] = cost
		
		capitalValue["capitalValue"] -= cost
		
		if asset == "Assets/Sec_Governance_Card.png"{
			disableSecAnalyst["disableSecAnalyst"] = 1
			delete(selectedAssetImages, "Assets/Sec_Analyst_Card.png")
		}
	}

	threatsDir := "Cards/Threats"
	threats, err := getFilesInDirectory(threatsDir, ".png")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rand.Seed(time.Now().UnixNano())
	randomIndex := rand.Intn(len(threats))

	randomThreat := threats[randomIndex]

	threatMitigated := false
	penTestCheck := false
	
	activeAssets := getSharedKeys(selectedAssetImages, assetCardMapping)
	
	if isValuePresent(activeAssets, "Assets/Pen_Test_Card.png"){
		activeAssets = removeItem(activeAssets, "Assets/Pen_Test_Card.png")
		penTestCheck = true
	}
	
	for _, asset := range activeAssets {
		for _, v := range assetCardMapping[asset] {
			if containsSubstring(randomThreat, v) {
				if isValuePresent(requireSoCSIEM, asset){
					if isValuePresent(activeAssets, "Assets/SoC_Card.png") && isValuePresent(activeAssets, "Assets/SIEM_Card.png") {
						threatMitigated = true
					}
				} else {
					threatMitigated = true
				}
			}
		}
	}
	
	if threatMitigated && containsSubstring(randomThreat, "Ransomware"){
		turnValue["turnValue"] ++
		repValue["repValue"] -= 1
		
	}
	
	if isValuePresent(activeAssets, "Assets/Sec_Analyst_Card.png"){
		if turnValue["turnValue"] > soCEnabledTurn["soCEnabledTurn"] {
			enableTempSoC = true
		}
	}
	
	//TODO - Some how make the pentest v optional SoC possible?
	// Currently if pen_test present it automatically uses it before giving the option to enable SoC
	if len(activeThreats) >= 1{
		threatMitigated = false
	} else {
		if ! threatMitigated && penTestCheck{
			for _, v := range(assetCardMapping["Assets/Pen_Test_Card.png"]){
				if containsSubstring(randomThreat, v){
					threatMitigated = true
					delete(selectedAssetImages, "Assets/Pen_Test_Card.png")
				}
			}
		}
	}
	
	
	if capitalValue["capitalValue"] < 0{
		interest = 0.1 * float64(capitalValue["capitalValue"])
		
		capitalValue["capitalValue"] += int(math.Round(interest))
	}
	
	
	state[sessionName+"-reputation"] = repValue
	state[sessionName+"-turn"] = turnValue
	
	templateData := struct {
		SessionName      	string
		RandomImageURL   	string
		TestClicked      	bool
		ThreatMitigated  	bool
		Opportunities   	[]string
		OpportunityImages  	map[string]int
		AssetImages        	map[string]int
		ActiveThreats  		map[string]int
		Capital				int
		InterestCharged		int
		Reputation			int
		Turn				int
		EnableTempSoC		bool
	}{
		SessionName:      	sessionName,
		RandomImageURL:   	"Cards/Threats/" + randomThreat,
		TestClicked:      	testClicked, // Pass the TestClicked flag
		ThreatMitigated:  	threatMitigated,
		Opportunities:    	nil,
		OpportunityImages:  selectedOpportunityImages,
        AssetImages:        selectedAssetImages,
        ActiveThreats:		activeThreats,
        Capital:			capitalValue["capitalValue"],
        InterestCharged:	int(math.Round(interest)),
        Reputation:			repValue["repValue"],
        Turn:				turnValue["turnValue"],
        EnableTempSoC: 		enableTempSoC,
	}

	renderTemplate(w, "home.html", templateData)
}


func HandleOpportunities(w http.ResponseWriter, r *http.Request) {
	var nonSelectableOpportunities	[]string
	
	sessionName := r.URL.Query().Get("session")
    selectedAssetImages, _ := state[sessionName+"-assets"]
    selectedOpportunityImages, _ := state[sessionName+"-opportunities"]
    capitalValue, _ := state[sessionName+"-capital"]
	repValue, _ := state[sessionName+"-reputation"]
	lostOpportunities, okLostOpportunities := state[sessionName+"-lostOpportunities"]
	
	if !okLostOpportunities {
		lostOpportunities = make(map[string]int)
	}

    opportunitiesDir := "Cards/Opportunities"
    opportunities, err := getFilesInDirectory(opportunitiesDir, ".png")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    lostContracts, _ := getKeys(lostOpportunities)
    
    
    if len(lostContracts) >= 1{
    	currentOpportunities, _ := getKeys(selectedOpportunityImages)
    	nonSelectableOpportunities = append(lostContracts, currentOpportunities...)
    } else {
    	nonSelectableOpportunities , _ = getKeys(selectedOpportunityImages)
    }
    
    currentAssets, _ := getKeys(selectedAssetImages)

    for opportunity, _ := range opportunityCardMapping{
    	alreadySelected := isValuePresent(nonSelectableOpportunities, opportunity + "_Card.png")
		
		if alreadySelected {
			opportunities = removeItem(opportunities, opportunity + "_Card.png")
		}
		
    	if containsSubstring(opportunity, "Multimedia"){
    		if isValuePresent(currentAssets, "Assets/Firewall_Card.png"){
    			if isValuePresent(currentAssets, "Assets/IDS_Card.png") || isValuePresent(currentAssets, "Assets/IPS_Card.png"){
    				continue
    			}
    			
    		}
    		
    	}
    
    	result := compareStringSlices(opportunityCardMapping[opportunity].Requires, currentAssets)
		
		if ! result {
			opportunities = removeItem(opportunities, opportunity + "_Card.png")
		}
    	
    }

    templateData := struct {
        SessionName     string
        Opportunities   []string
        TestClicked		bool
        Capital			int
        Reputation		int
    }{
        SessionName:    sessionName,
        Opportunities:  opportunities,
        TestClicked:    false,
        Capital:		capitalValue["capitalValue"],
        Reputation:		repValue["repValue"],
    }

    renderTemplate(w, "opportunities.html", templateData)
}


func HandleAssets(w http.ResponseWriter, r *http.Request) {

	sessionName := r.URL.Query().Get("session")
    selectedAssetImages, _ := state[sessionName+"-assets"]
    selectedOpportunityImages, _ := state[sessionName+"-opportunities"]
	activeThreats, okActiveThreats := state[sessionName+"-threats"]
	capitalValue, _ := state[sessionName+"-capital"]
	repValue, _ := state[sessionName+"-reputation"]
	disableSecAnalyst, _ := state[sessionName+"-disableSecAnalyst"]
	
	if !okActiveThreats {
		activeThreats = make(map[string]int)
	}
    
	currentOpportunities, _ := getKeys(selectedOpportunityImages)
	
	opportunityDetails := r.FormValue("opportunityDetails")

	selectedOpportunities := strings.Fields(opportunityDetails)
	for _, opportunity := range selectedOpportunities {
		cost := 0
		selectedOpportunityImages[opportunity] = cost
	}
	
	if len(selectedOpportunities) >= 1{

		selectedOpportunity := strings.Split(selectedOpportunities[0], "_")[0]
		bonusPaid := isValuePresent(currentOpportunities, selectedOpportunities[0])
		
		if ! bonusPaid{
			repValue["repValue"] += opportunityCardMapping[selectedOpportunity].Bonus[0]
			capitalValue["capitalValue"] += opportunityCardMapping[selectedOpportunity].Bonus[1]
		}
	}
	
    currentAssets, _ := getKeys(selectedAssetImages)
    
    if disableSecAnalyst["disableSecAnalyst"] == 1{
    	currentAssets = append(currentAssets, "Assets/Sec_Analyst_Card.png")
    }

    selectableAssets := make(map[string]int)
    
    for k, v := range startingAssetImages{
    	
    	if ! isValuePresent(currentAssets, k){
    		selectableAssets[k] = v
    	}
    }
    
    if isValuePresent(currentAssets, "Assets/Sec_Analyst_Card.png") && isValuePresent(currentAssets, "Assets/SoC_Card.png"){
    	selectableAssets["Assets/Pen_Test_Card.png"] = 0
    } else {
    	selectableAssets["Assets/Pen_Test_Card.png"] = 10000
    }
    
    if isValuePresent(currentAssets, "Assets/Sec_Analyst_Card.png") {
    	selectableAssets["Assets/Sec_Governance_Card.png"] = 0
    	selectableAssets["Assets/Data_Backups_Card.png"] = 10000
		selectableAssets["Assets/SIEM_Card.png"] = 20000
		
		if isValuePresent(currentAssets, "Assets/SIEM_Card.png"){
			selectableAssets["Assets/SoC_Card.png"] = 90000
		}
    }
    
    for k, _ := range selectableAssets{
    	
    	if isValuePresent(currentAssets, k){
    		delete(selectableAssets, k)
    	}
    }

    templateData := struct {
        SessionName     	string
		ImageInfo   		map[string]int
        TestClicked			bool
        ActiveThreats  		map[string]int
		AssetImages        	map[string]int
        Capital				int
        Reputation			int
    }{
        SessionName:     	sessionName,
        ImageInfo:			selectableAssets,
        TestClicked:     	false,
        ActiveThreats:  	activeThreats,
        AssetImages:        selectedAssetImages,
        Capital:			capitalValue["capitalValue"],
        Reputation:			repValue["repValue"],
    }

    renderTemplate(w, "assets.html", templateData)
}


func HandleThreats(w http.ResponseWriter, r *http.Request) {
	var fallout 					[]string
	var threatsToManage 			[]string
	var uniqueThreatsToManage		[]string
	var uniqueManagedThreats		[]string
	var managedThreats 				[]string
	var partiallyManagedThreats 	[]string
	var contractLost				string
	var contractLostCondition		string
	var lostContracts				[]string
	penTestCheck := false
	totalThreatCost := 0
	
	sessionName := r.URL.Query().Get("session")
    selectedAssetImages, _ := state[sessionName+"-assets"]
    selectedOpportunityImages, _ := state[sessionName+"-opportunities"]
    activeThreats, okActiveThreats := state[sessionName+"-threats"]
	capitalValue, _ := state[sessionName+"-capital"]
	repValue, _ := state[sessionName+"-reputation"]
	soCEnabledTurn, _ := state[sessionName+"-tempSoCTurn"]
	turnValue,_ := state[sessionName+"-turn"]
	insidertLinkedTurn, _ := state[sessionName+"-insidertLinkedTurn"]
    intrustionLinkedTurn , _ := state[sessionName+"-intrustionLinkedTurn"]
    lostOpportunities, okLostOpportunities := state[sessionName+"-lostOpportunities"]
	
	if !okActiveThreats {
		activeThreats = make(map[string]int)
	}
	
	if !okLostOpportunities {
		lostOpportunities = make(map[string]int)
	}
	
	randomThreatDetails := r.FormValue("threatToManage")

	randomThreat := strings.Fields(randomThreatDetails)[0]
	
	allThreats, _ := getKeys(threatCardMapping)
	
	activeAssets := getSharedKeys(selectedAssetImages, assetCardMapping)
	
	if isValuePresent(activeAssets, "Assets/Pen_Test_Card.png"){
		activeAssets = removeItem(activeAssets, "Assets/Pen_Test_Card.png")
		penTestCheck = true
	}
	
	enableTempSoC := r.FormValue("enableTempSoC")
	
	if len(strings.Fields(enableTempSoC)) > 0{
		activeAssets = append(activeAssets, "Assets/SoC_Card.png")
		soCEnabledTurn["soCEnabledTurn"] = (turnValue["turnValue"] +1)
	}
	
	// randomThreat includes the full path so wouln't work with our threatMapping dict
	
	mitigationMapping := make(map[string]string)
	
	for _, threatMapping := range allThreats{
		if containsSubstring(randomThreat, threatMapping) {
            threatMitigated := false
            partiallyMitigated := false
            mitigationType := "2"
			for _, asset := range activeAssets{
				for _, v := range assetCardMapping[asset] {

					if containsSubstring(threatMapping, v) {
					
						if isValuePresent(requireSoCSIEM, asset){
							if isValuePresent(activeAssets, "Assets/SoC_Card.png") && isValuePresent(activeAssets, "Assets/SIEM_Card.png") {
								mitigationMapping[threatMapping] = asset
								threatMitigated = true
							} else {
								partiallyMitigated = true
								if containsSubstring(asset, "IPS"){
									mitigationType = "1"
									threatMitigated = true
								} 
							}
						} else {
							mitigationMapping[threatMapping] = asset
							threatMitigated = true
						}
					}
				}
			}
			
			if ! threatMitigated && penTestCheck{
				for _, v := range(assetCardMapping["Assets/Pen_Test_Card.png"]){
					if containsSubstring(threatMapping, v){
						threatMitigated = true
						delete(selectedAssetImages, "Assets/Pen_Test_Card.png")
					}
				}
			}
			
			if threatMitigated {
				if containsSubstring(threatMapping, "Ransomware"){
					turnValue["turnValue"] ++
					repValue["repValue"] -= 1
				}
				managedThreats = append(managedThreats, threatMapping)
			} else {
				if partiallyMitigated {
					threatsToManage = append(threatsToManage, threatMapping + ";" + mitigationType)
					partiallyManagedThreats = append(partiallyManagedThreats, threatMapping + ";" + mitigationType)
				} else {
					threatsToManage = append(threatsToManage, threatMapping)
				}
			}
        }
	}
	
	if len(activeThreats) >= 1{
	
		for threat, _ := range activeThreats{
			threatMitigated := false
			partiallyMitigated := false
			mitigationType := "2"
			for _, asset := range activeAssets {
				for _, v := range assetCardMapping[asset] {
					
					if containsSubstring(threat, v) {
					
						if isValuePresent(requireSoCSIEM, asset){
							if isValuePresent(activeAssets, "Assets/SoC_Card.png") && isValuePresent(activeAssets, "Assets/SIEM_Card.png") {
								mitigationMapping[threat] = asset
								threatMitigated = true
							} else {
								partiallyMitigated = true
								if containsSubstring( asset, "IPS"){
									mitigationType = "1"
									threatMitigated = true
								}
							}
						} else {
							mitigationMapping[threat] = asset
							threatMitigated = true
						}
					}
				}
			}
			if ! threatMitigated && penTestCheck{
				for _, v := range(assetCardMapping["Assets/Pen_Test_Card.png"]){
					if containsSubstring(threat, v){
						threatMitigated = true
						delete(selectedAssetImages, "Assets/Pen_Test_Card.png")
					}
				}
			}
			if threatMitigated {
				if containsSubstring(threat, "Ransomware"){
					turnValue["turnValue"] ++
					repValue["repValue"] -= 1
				}
				managedThreats = append(managedThreats, threat)
			} else {
				if partiallyMitigated {
					threatsToManage = append(threatsToManage, threat + ";" + mitigationType)
					partiallyManagedThreats = append(partiallyManagedThreats, threat + ";" + mitigationType)
				} else {
					threatsToManage = append(threatsToManage, threat)
				}
			}
		}
		
	}
	
	uniqueThreatsToManage = uniqueValues(threatsToManage)
	uniqueManagedThreats = uniqueValues(managedThreats)
	cleanedUniqueThreatsToManage := removeSubstrings(uniqueThreatsToManage, ";")
	
	for _, threat := range uniqueManagedThreats{
		delete(activeThreats, threat)
		cleanedUniqueThreatsToManage = removeItem(cleanedUniqueThreatsToManage, threat)
	}

	for _, threat := range cleanedUniqueThreatsToManage{
		delete(activeThreats, threat)
	}
	
	for _, rawThreat := range uniqueThreatsToManage{
		var threat string
		modifer := 0
		
		if containsSubstring(rawThreat, ";"){
			threat = strings.Split(rawThreat, ";")[0]
			modifer, _ = strconv.Atoi(strings.Split(rawThreat, ";")[1])
		} else {
			threat = rawThreat
		}
	
		fallout = threatCardMapping[threat]
		
		rep_cost, err := strconv.Atoi(fallout[0])
		if err != nil {
		    http.Error(w, err.Error(), http.StatusInternalServerError)
		    return
		}
		
		capital_cost, err := strconv.Atoi(fallout[1])
		if err != nil {
		    http.Error(w, err.Error(), http.StatusInternalServerError)
		    return
		}
		
		if modifer == 2{
			repValue["repValue"] -= (rep_cost / 2)
			capitalValue["capitalValue"] -= (capital_cost / 2)
			totalThreatCost += (capital_cost / 2)
		} else {
			repValue["repValue"] -= rep_cost
			capitalValue["capitalValue"] -= capital_cost
			totalThreatCost += capital_cost
		}
		
		rawLinkedThreats := fallout[2]
		persistantThreat := fallout[3]
		
		if rawLinkedThreats != "" {
			linkedThreats := strings.Split(rawLinkedThreats, ";")
		
			for _, linkedThreat := range linkedThreats{
				if persistantThreat == "True"{
					if containsSubstring(threat, "Insider") {
						if insidertLinkedTurn["insidertLinkedTurn"] == checkOddEven((turnValue["turnValue"] + 1)){
							activeThreats["Threats/"+linkedThreat+"_Card.png"] = 0
						}
					} else {
						if intrustionLinkedTurn["intrustionLinkedTurn"] == checkOddEven((turnValue["turnValue"] + 1)){
							activeThreats["Threats/"+linkedThreat+"_Card.png"] = 0
						}
					}
				} else {
					activeThreats["Threats/"+linkedThreat+"_Card.png"] = 0
				}
			}
		}
		
		if persistantThreat == "True"{
			if containsSubstring(threat, "Insider") {
				if insidertLinkedTurn["insidertLinkedTurn"] == 0{
					insidertLinkedTurn["insidertLinkedTurn"] = checkOddEven(turnValue["turnValue"])
				}
			} else {
				if intrustionLinkedTurn["intrustionLinkedTurn"] == 0{
					intrustionLinkedTurn["intrustionLinkedTurn"] = checkOddEven(turnValue["turnValue"])
				}
			}
			activeThreats[threat] = 1
		}
	}
	
	// Opportunity (ThreatImpact) - Fail condition / trigger, rep cost, capital cost, lose contract
	
	if len(selectedOpportunityImages) >= 1{
		for k, _ := range selectedOpportunityImages {
			mappingKey := strings.Split(k, "_")[0]
			threatImpact := opportunityCardMapping[mappingKey].ThreatImpact
			
			triggerThreats := strings.Split(threatImpact[0], ";")
			
			rep_cost, err := strconv.Atoi(threatImpact[1])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			
			capital_cost := 0
			
			if ! containsSubstring(threatImpact[2], ";"){
				capital_cost, _ = strconv.Atoi(threatImpact[2])
			} else {
				captialCostComponents := strings.Split(threatImpact[2], ";")
				
				percentageAmount, err := strconv.ParseFloat(captialCostComponents[0], 64)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				
				if captialCostComponents[1] == "Cost"{
					capital_cost = int(math.Round(percentageAmount * float64(totalThreatCost)))
				} else {
					capital_cost = int(math.Round(percentageAmount * float64(capitalValue["capitalValue"])))
				}
				
				
			}
			
			if containsSubstring(threatImpact[3], ";"){
				contractLost = strings.Split(threatImpact[3], ";")[0]
				contractLostCondition = strings.Split(threatImpact[3], ";")[1]
			} else {
				contractLost = threatImpact[3]
			}
			
			for _, trigger := range triggerThreats{
				
				if isValuePresent(cleanedUniqueThreatsToManage, "Threats/"+trigger+"_Card.png"){
					
					repValue["repValue"] -= rep_cost
					capitalValue["capitalValue"] -= capital_cost
					
					if contractLost == "True"{
						if contractLostCondition != "" {
							if isValuePresent(cleanedUniqueThreatsToManage, "Threats/"+contractLostCondition+"_Card.png"){
								lostContracts = append(lostContracts, k)
							}
						} else {
							lostContracts = append(lostContracts, k)
						}
					}
					
				}
			
			}
			
		}
	}
	
	for _, contract := range lostContracts{
		lostOpportunities[contract] = 0
		delete(selectedOpportunityImages, contract)
	}
	
	
	state[sessionName+"-threats"] = activeThreats
	state[sessionName+"-tempSoCTurn"] = soCEnabledTurn
	state[sessionName+"-reputation"] = repValue
	state[sessionName+"-capital"] = capitalValue
	state[sessionName+"-turn"] = turnValue
	state[sessionName+"-insidertLinkedTurn"] = insidertLinkedTurn
    state[sessionName+"-intrustionLinkedTurn"] = intrustionLinkedTurn
    state[sessionName+"-lostOpportunities"] = lostOpportunities
	
    templateData := struct {
        SessionName     	string
        TestClicked			bool
        ThreatsToManage   	[]string
        ManagedThreats   	[]string
        AssetImages  		map[string]int
		ActiveThreats       map[string]int
        Capital				int
        Reputation			int
    }{
        SessionName:     	sessionName,
        TestClicked:     	false,
        ThreatsToManage:	cleanedUniqueThreatsToManage,
        ManagedThreats:		uniqueManagedThreats,
        AssetImages:  		selectedAssetImages,
        ActiveThreats:      activeThreats,
        Capital:			capitalValue["capitalValue"],
        Reputation:			repValue["repValue"],
    }
	
    renderTemplate(w, "manage.html", templateData)
}
