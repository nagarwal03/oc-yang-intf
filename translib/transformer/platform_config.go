package transformer

import (
	"encoding/json"
	//"errors"
	//"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	//"reflect"
	//"sort"
	"strconv"
	"strings"

	//common_utils "github.com/Azure/sonic-mgmt-common/cvl/common_utils"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	//"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	//"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
)

const (
	PLATFORM_JSON     = "/usr/share/sonic/hwsku/platform.json"
	PLATFORM_DEF_JSON = "/usr/share/sonic/hwsku/platform-def.json"
)

type portProp struct {
	name         string
	index        string
	lanes        string
	alias        string
	valid_speeds string
	speed        string
}

type portCaps struct {
	Port    string `json:"port,omitempty"`
	Name    string `json:"name,omitempty"`
	Modes   string `json:"modes,omitempty"`
	DefMode string `json:"defmode,omitempty"`
	Pipe    string `json:"pipe,omitempty"`
}

type pipelineResources struct {
	Pipe             string `json:"pipe,omitempty"`
	PortCountLimit   string `json:"port-count-limit,omitempty"`
	CurrentPortCount string `json:"current-port-count,omitempty"`
	FrontPanelPorts  string `json:"front-panel-ports,omitempty"`
}

type dpbResources struct {
	SystemPortCountLimit   string              `json:"system-port-count-limit,omitempty"`
	SystemCurrentPortCount string              `json:"system-current-port-count,omitempty"`
	PipelineResources      []pipelineResources `json:"pipelines,omitempty"`
}

type portGroup struct {
	memberIfStart   string
	memberIfEnd     string
	validPortSpeeds map[string]string
}

var portGroups map[string]portGroup

type validPortSpeed struct {
	ifStart     int
	ifEnd       int
	validSpeeds map[int][]string
}

var validPortSpeeds []validPortSpeed

var platConfigStr map[string]map[string]string
var platDefStr map[string]map[string]map[string]string

/* For parsing FEC data from config file*/

type fec_mode_t string
type speed_t string
type interface_t string
type lane_t string

/*  interface -> lane -> speed -> list of fec values */
type fec_tbl_t map[interface_t]map[lane_t]map[speed_t][]fec_mode_t

type pipeline_info_t struct {
	max_ports float64
	ports     []string
}

type pipelines_t struct {
	total_pipelines float64
	pipelines_tbl   map[string]pipeline_info_t
}

type chip_info_t struct {
	max_ports float64
	pipelines pipelines_t
}

type chips_t struct {
	total_chips float64
	chips_tbl   map[string]chip_info_t
}

var silicon_resources chips_t
var pipelines pipelines_t

// Table of fec values when default is expected
var fec_raw_map map[string]map[string]map[string]interface{}
var default_fec_tbl fec_tbl_t

// Allowed set of FEC values
var supported_fec_tbl fec_tbl_t

// Table of autoneg values when default is expected
type autoneg_tbl_t map[string]string

var default_autoneg_tbl autoneg_tbl_t

type dpb_info_t struct {
	master         string
	phy_ports      []string
	phy_port_count int
	max_phy_speed  int
	dpb_mode_info  map[string][]int
}

var dpb_info_map map[string]dpb_info_t
var fp_port_offset int

/* Functions */

func init() {
	parsePlatformJsonFile()
	//parsePlatformDefJsonFile()
	//populate_fec_modes_to_db()
	//common_utils.Update_FEC_Cache()
}

func readPlatconfFile(path string) ([]byte, error) {
	if dir, ok := os.LookupEnv("PLATCONF_DIR"); ok {
		path = filepath.Join(dir, filepath.Base(path))
	}
	return ioutil.ReadFile(path)
}

func getSpeedFromBreakoutMode(mode string) (speed int, err error) {
	var port_count int
	speed = 0
	err = nil
	spd_idx := strings.Index(mode, "G")
	spd_start := strings.Index(mode, "x") + 1
	speed, err = strconv.Atoi(mode[spd_start:spd_idx])
	port_count, err = strconv.Atoi(mode[:spd_start-1])
	speed *= (port_count * 1000)
	return
}

func splitModes(modes string) string {
	// The example formats supported:
	// 1. 2x200G
	// 2. 4x25G[10G]
	// 3. 1x50G(2)
	// 4. 2x50G[25G](2)
	splitted := strings.Split(modes, ",")
	for idx, mode := range splitted {
		multi_speed_pos := strings.Index(mode, "[")
		if multi_speed_pos != -1 {
			ports_pos := strings.Index(mode, "x")
			lanes_pos := strings.Index(mode, "(")
			suffix := ""
			if lanes_pos != -1 {
				suffix = mode[lanes_pos:]
			}
			splitted[idx] = mode[:multi_speed_pos] + suffix + ", " +
				mode[:ports_pos+1] + mode[multi_speed_pos+1:strings.Index(mode, "]")] + suffix
		}
	}
	return strings.Join(splitted, ",")
}

func parseDPBEntry(port string, ifName string, entry map[string]string) error {
	type AmbiguousData struct {
		count      int
		lane_count int
		speed      int
	}
	supported_modes := strings.Split(entry["breakout_modes"], ",")
	if len(supported_modes) > 1 {
		var dpb_info dpb_info_t
		mode := entry["default_brkout_mode"]
		dpb_info.master = ifName
		dpb_info.phy_ports = strings.Split(entry["lanes"], ",")
		dpb_info.phy_port_count = len(dpb_info.phy_ports)
		dpb_info.dpb_mode_info = make(map[string][]int)

		if len(mode) == 0 {
			return tlerr.InvalidArgs("Invalid default breakout mode")
		}
		if strings.Contains(mode, "[") {
			mode = mode[0:strings.Index(mode, "[")]
		}
		log.Info("Default DPB mode for ", ifName, " is ", mode)
		max_bandwidth, err := getSpeedFromBreakoutMode(mode)
		if err != nil {
			log.Error("Unable to get the bandwidth from default mode ", mode)
			return err
		}
		dpb_info.max_phy_speed = max_bandwidth / dpb_info.phy_port_count

		ambiguous := make(map[string]AmbiguousData)
		for _, mode_iter := range supported_modes {
			splitedModes := strings.Split(strings.TrimSpace(splitModes(mode_iter)), ",")
			for _, smode := range splitedModes {
				smode = strings.TrimSpace(smode)
				spd_start := strings.Index(smode, "x") + 1
				port_count, _ := strconv.Atoi(smode[:spd_start-1])
				total_bandwidth, err := getSpeedFromBreakoutMode(smode)
				if err != nil {
					log.Error("Unable to get the bandwidth from mode ", mode)
					continue
				}
				log.Info("[", port, "/", ifName, "] BW ", total_bandwidth, " for ", smode)
				if total_bandwidth > max_bandwidth {
					log.Error("Total bandwidth exceeded the max, ", total_bandwidth, " > ", max_bandwidth, " for ", smode)
					continue
				}
				lane_count := 0
				lanes_pos := strings.Index(smode, "(")
				lanes_epos := strings.Index(smode, ")")
				// See if lane count is explictly mentioned.
				if lanes_pos != -1 && lanes_epos != -1 {
					lane_count, _ = strconv.Atoi(smode[lanes_pos+1 : lanes_epos])
					lane_count = lane_count / port_count
					mode := smode[:lanes_pos]
					if adata, found := ambiguous[mode]; found {
						adata.count += 1
						log.Info("Ambiguous mode ", mode, " found ", adata.count, " times - ", smode)
						ambiguous[mode] = adata
					} else {
						var adata AmbiguousData
						adata.count = 1
						adata.lane_count = lane_count
						adata.speed = total_bandwidth / port_count
						ambiguous[mode] = adata
						log.Info("Ambiguous mode ", mode, " found once - ", smode)
					}
				} else if ((total_bandwidth / port_count) % dpb_info.max_phy_speed) != 0 {
					// Check if it is possible with max lanes speed
					// NRZ case
					if dpb_info.max_phy_speed >= 50000 {
						if ((total_bandwidth / port_count) % (dpb_info.max_phy_speed / 2)) != 0 {
							if ((total_bandwidth / port_count) % (dpb_info.max_phy_speed / 5)) != 0 {
								if total_bandwidth < (max_bandwidth / dpb_info.phy_port_count) {
									lane_count = 1
									log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed/5)
								} else {
									lane_count = 1
									log.Info("[PAM4 NRZ-10G] Probable invalid DPB mode. lane speed ", dpb_info.max_phy_speed, " for mode ", smode)
								}
							} else {
								// NRZ 10G mode for 25G lanes for PAM4 ports
								lane_count = (total_bandwidth / port_count) / (dpb_info.max_phy_speed / 5)
								log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed/5)
							}
						} else {
							// NRZ mode for PAM4 ports
							lane_count = (total_bandwidth / port_count) / (dpb_info.max_phy_speed / 2)
							log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed/2)
						}
					} else if ((total_bandwidth / port_count) % (dpb_info.max_phy_speed * 2 / 5)) != 0 {
						if ((total_bandwidth / port_count) % (dpb_info.max_phy_speed * 2 / 50)) != 0 {
							log.Error("[NRZ-10G/1G] Not possible to align with lane speed ", dpb_info.max_phy_speed, " for mode ", smode)
							continue
						} else {
							lane_count = (total_bandwidth / port_count) / (dpb_info.max_phy_speed * 2 / 50)
							log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed*2/5)
						}
					} else {
						lane_count = (total_bandwidth / port_count) / (dpb_info.max_phy_speed * 2 / 5)
						log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed*2/5)
					}
				} else {
					lane_count = (total_bandwidth / port_count) / dpb_info.max_phy_speed
					log.Info("Lane count ", lane_count, " total_bandwidth ", total_bandwidth, " port_count ", port_count, " lane_speed ", dpb_info.max_phy_speed)
				}
				dpb_info.dpb_mode_info[smode] = append(dpb_info.dpb_mode_info[smode], lane_count)
				dpb_info.dpb_mode_info[smode] = append(dpb_info.dpb_mode_info[smode], total_bandwidth/port_count)
			}
		}
		for amode, adata := range ambiguous {
			if adata.count == 1 {
				_, found := dpb_info.dpb_mode_info[amode]
				if !found {
					dpb_info.dpb_mode_info[amode] = append(dpb_info.dpb_mode_info[amode], adata.lane_count)
					dpb_info.dpb_mode_info[amode] = append(dpb_info.dpb_mode_info[amode], adata.speed)
					log.Info("Non-ambigous mode ", amode, "  lane count ", adata.lane_count, " port speed: ", adata.speed)
				}
			}
		}
		dpb_info_map[port] = dpb_info
	}
	return nil
}

func parsePlatformJsonFile() error {

	file, err := readPlatconfFile(PLATFORM_JSON)

	if nil != err {
		log.Error("Dynamic port breakout not supported")
		return err
	}

	platConfigStr = make(map[string]map[string]string)
	err = json.Unmarshal([]byte(file), &platConfigStr)
	dpb_info_map = make(map[string]dpb_info_t)
	for _, entry := range platConfigStr {
		indeces := strings.Split(entry["index"], ",")
		if indeces[0] == "0" {
			fp_port_offset = 1
			log.Info("Zero based SFP index")
		}
	}
	for key, entry := range platConfigStr {
		if len(strings.Split(entry["breakout_modes"], ",")) > 1 {
			indeces := strings.Split(entry["index"], ",")
			index, _ := strconv.Atoi(indeces[0])
			port := "1/" + strconv.Itoa(index+fp_port_offset)
			parseDPBEntry(port, key, entry)
		}
	}
	return err
}

//func parsePlatformDefJsonFile() error {
//	/*
//	   Due to GoLang strict typing, we cannot marshal to a strict format until we know what the table we will be parsing is.
//	   When parsing FEC, the format is slightly different from when parsing port-group
//	*/
//	_, def_fec_ok := fec_raw_map["default-fec-mode"]
//	_, fec_ok := fec_raw_map["fec-mode"]
//	if def_fec_ok && fec_ok {
//		log.Info("platform-def.json already parsed.")
//		return nil
//	}
//	log.Info("Reading platform-def.json")
//
//	file, err := readPlatconfFile(PLATFORM_DEF_JSON)
//
//	if nil != err {
//		log.Info("Unable to read platform-def file: Platform specific properties not supported")
//		return err
//	}
//
//	var raw_map map[string]interface{}
//	json.Unmarshal([]byte(file), &raw_map)
//	if _, silicon_resources_present := raw_map["chips"]; silicon_resources_present {
//		parse_silicon_resources(raw_map["chips"].(map[string]interface{}))
//		fec_raw_map = make(map[string]map[string]map[string]interface{})
//		if def_fec, def_fec_present := raw_map["default-fec-mode"]; def_fec_present {
//			extractJsonData("default-fec-mode", def_fec.(map[string]interface{}))
//		}
//		if fec, fec_present := raw_map["fec-mode"]; fec_present {
//			extractJsonData("fec-mode", fec.(map[string]interface{}))
//		}
//		if pg, pg_present := raw_map["port-group"]; pg_present {
//			extractJsonData("port-group", pg.(map[string]interface{}))
//		}
//		if vspeeds, vspeeds_present := raw_map["native-port-supported-speeds"]; vspeeds_present {
//			extractJsonData("native-port-supported-speeds", vspeeds.(map[string]interface{}))
//		}
//	} else {
//		/* Map if for FEC parsing */
//		err = json.Unmarshal([]byte(file), &fec_raw_map)
//		if err != nil {
//			_, def_fec_ok = fec_raw_map["default-fec-mode"]
//			_, fec_ok = fec_raw_map["fec-mode"]
//			if !def_fec_ok || !fec_ok {
//				log.Error("platform-def.json parse failed: ", err)
//				log.Info("fec_raw_map  ", fec_raw_map)
//				return err
//			}
//		}
//	}
//	platDefStr = make(map[string]map[string]map[string]string)
//	json.Unmarshal([]byte(file), &platDefStr)
//	autoneg_raw_map := platDefStr["default-autoneg-mode"]
//	default_autoneg_tbl = parse_autoneg_config(autoneg_raw_map)
//
//	default_fec_tbl = make(fec_tbl_t)
//	supported_fec_tbl = make(fec_tbl_t)
//
//	/* Default table of fec */
//	default_fec_tbl = parse_fec_config(fec_raw_map["default-fec-mode"])
//	/* Supported table */
//	supported_fec_tbl = parse_fec_config(fec_raw_map["fec-mode"])
//
//	/* Check for port-group field */
//	if pg_entries, ok := fec_raw_map["port-group"]; ok {
//		parsePortGroupData(pg_entries)
//
//		/* For backward compat */
//		platDefStr = make(map[string]map[string]map[string]string)
//		platDefStr["port-group"] = make(map[string]map[string]string)
//
//		for pg_key, pg_val := range pg_entries {
//			platDefStr["port-group"][pg_key] = make(map[string]string)
//			for key, val := range pg_val {
//				/* Val is of type interface{}
//				   Need to conver to string first
//				*/
//				switch reflect.TypeOf(val).Kind() {
//				case reflect.String:
//					platDefStr["port-group"][pg_key][key] = val.(string)
//				case reflect.Slice:
//				}
//			}
//		}
//		log.Info("Parsed port-group info as ", platDefStr)
//	} else {
//		log.Info("No port-group configs to parse in platform-def")
//	}
//
//	if vspeedEntries, ok := fec_raw_map["native-port-supported-speeds"]; ok {
//		parseNativeValidSpeed(vspeedEntries)
//	}
//
//	return err
//}

func getValidSpeeds(port_i string, d *db.DB) ([]string, error) {
	var valid_speeds []string
	if len(platConfigStr) < 1 {
		parsePlatformJsonFile()
	}
	dpbEntry, err := d.GetEntry(&db.TableSpec{Name: "BREAKOUT_CFG"}, db.Key{Comp: []string{port_i}})
	if (err != nil) || (len(dpbEntry.Field["brkout_mode"]) < 1) ||
		!strings.HasPrefix(dpbEntry.Field["brkout_mode"], "1x") {
		return valid_speeds, tlerr.InvalidArgs("Unable to determine valid speeds")
	}
	//nativeName := *(utils.GetNativeNameFromName(&port_i))
	//if entry, ok := platConfigStr[nativeName]; ok {
	if entry, ok := platConfigStr[port_i]; ok {
		// Get the valid speed from default breakout mode.
		mode := entry["default_brkout_mode"]
		pos := strings.Index(mode, "G")
		if pos != -1 {
			speed, _ := strconv.Atoi(mode[2:pos])
			valid_speeds = append(valid_speeds, strconv.Itoa(speed*1000))
		} else {
			log.Error("Invalid mode: ", mode)
		}
		pos = strings.Index(mode, "[")
		epos := strings.Index(mode, "]")
		if pos != -1 && epos != -1 {
			speed, _ := strconv.Atoi(mode[pos+1 : epos-1])
			valid_speeds = append(valid_speeds, strconv.Itoa(speed*1000))
		}
	} else {
		log.Info("getValidSpeeds(", port_i, "): platform config entry not found.")
	}
	if len(valid_speeds) < 1 {
		log.Error("Could not get valid speeds from default breakout mode")
		return valid_speeds, tlerr.InvalidArgs("Unable to determine valid speeds")
	}
	return valid_speeds, nil
}



func getDefaultAutoNegMode(port_i string) (string, error) {

	//ifName := *(utils.GetNativeNameFromName(&port_i))
	//if val, ok := default_autoneg_tbl[ifName]; ok {
	if val, ok := default_autoneg_tbl[port_i]; ok {
		return val, nil
	}
	return "off", nil
}

func isPortGroupMember(ifName string) bool {
	if pgs, ok := platDefStr["port-group"]; ok {
		for id, pg := range pgs {
			memRange := strings.Split(strings.TrimLeft(pg["members"], "Ethern"), "-")
			ifNum, _ := strconv.Atoi(strings.TrimLeft(ifName, "Ethern"))
			startNum, _ := strconv.Atoi(memRange[0])
			endNum, _ := strconv.Atoi(memRange[1])
			log.Info("PG ", id, pg["members"], " ", pg["valid_speeds"], " ==> ",
				startNum, " - ", ifNum, " - ", endNum)
			if (ifNum >= startNum) && (ifNum <= endNum) {
				return true
			}
		}
	}
	return false
}

func getPortGroupMembersAfterSpeedCheck(pgid string, speed *string) ([]string, error) {
	var members []string

	if len(portGroups) > 0 {
		for id, pg := range portGroups {
			if id == pgid {
				isSpeedValid := false
				maxSpeed := 0
				for spd := range pg.validPortSpeeds {
					if *speed == spd {
						isSpeedValid = true
						break
					} else if *speed == "" || maxSpeed > 0 {
						spdi, _ := strconv.Atoi(spd)
						if spdi > maxSpeed {
							maxSpeed = spdi
							*speed = spd
							isSpeedValid = true
							log.Info("Setting probable default speed to ", *speed)
						}
					}
				}
				if !isSpeedValid {
					log.Info("speed ", *speed, " is not supported for PG#", pgid)
					return members, tlerr.NotSupported("Unsupported speed")
				}
				startNum, _ := strconv.Atoi(strings.TrimLeft(pg.memberIfStart, "Ethern"))
				endNum, _ := strconv.Atoi(strings.TrimLeft(pg.memberIfEnd, "Ethern"))
				log.Info("PG ", id, " ", pg.validPortSpeeds[*speed], " ==> ",
					startNum, " - ", endNum)
				for i := startNum; i <= endNum; i++ {
					members = append(members, "Ethernet"+strconv.Itoa(i))
				}
			}
		}
	} else {
		return members, tlerr.NotSupported("Port-group is not supported")
	}
	return members, nil
}