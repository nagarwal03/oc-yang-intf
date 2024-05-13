//                                                                            //
//  Copyright 2024 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	//"encoding/json"
	"errors"
	"strconv"
	"strings"
	//"time"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	//"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_lag_min_links_xfmr", YangToDb_lag_min_links_xfmr)
	XlateFuncBind("DbToYang_lag_min_links_xfmr", DbToYang_lag_min_links_xfmr)
	XlateFuncBind("DbToYang_intf_lag_state_xfmr", DbToYang_intf_lag_state_xfmr)
}

const (
	PORTCHANNEL_TABLE             = "PORTCHANNEL"
	DEFAULT_PORTCHANNEL_MIN_LINKS = "1"
	DEFAULT_PORTCHANNEL_SPEED     = "0"
)

/* Validate whether LAG exists in DB */
func validatePortChannel(d *db.DB, lagName string) error {

	intfType, _, ierr := getIntfTypeByName(lagName)
	if ierr != nil || intfType != IntfTypePortChannel {
		return tlerr.InvalidArgsError{Format: "Invalid PortChannel: " + lagName}
	}

	err := validateIntfExists(d, PORTCHANNEL_TABLE, lagName)
	if err != nil {
		errStr := "PortChannel: " + lagName + " does not exist"
		return tlerr.InvalidArgsError{Format: errStr}
	}

	return nil
}

func uint16Conv(sval string) (uint16, error) {
	v, err := strconv.ParseUint(sval, 10, 16)
	if err != nil {
		errStr := "Conversion of string: " + "sval" + " to int failed"
		if log.V(3) {
			log.Error(errStr)
		}
		return 0, errors.New(errStr)
	}
	return uint16(v), nil
}

func deleteLagIntfAndMembers(inParams *XfmrParams, lagName *string) error {
	log.Info("Inside deleteLagIntfAndMembers")
	var err error

	subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
	resMap := make(map[string]map[string]db.Value)
	lagMap := make(map[string]db.Value)
	lagMemberMap := make(map[string]db.Value)
	lagIntfMap := make(map[string]db.Value)
	lagMap[*lagName] = db.Value{Field: map[string]string{}}

	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	subOpMap[db.ConfigDB] = resMap
	inParams.subOpDataMap[DELETE] = &subOpMap
	/* Validate given PortChannel exists */
	intfType, _, ierr := getIntfTypeByName(*lagName)
	if ierr != nil || intfType != IntfTypePortChannel {
		return tlerr.InvalidArgsError{Format: "Invalid PortChannel: " + *lagName}
	}

	entry, err := inParams.d.GetEntry(&db.TableSpec{Name: PORTCHANNEL_TABLE}, db.Key{Comp: []string{*lagName}})
	if err != nil || !entry.IsPopulated() {
		// Not returning error from here since mgmt infra will return "Resource not found" error in case of non existence entries
		return nil
	}

	/* Validate L3 Configuration only operation is not Delete */
	if inParams.oper != DELETE {
		err = validateL3ConfigExists(inParams.d, lagName)
		if err != nil {
			return err
		}
	}

	/* Handle PORTCHANNEL_MEMBER TABLE */
	var flag bool = false
	ts := db.TableSpec{Name: intTbl.cfgDb.memberTN + inParams.d.Opts.KeySeparator + *lagName}
	lagKeys, err := inParams.d.GetKeys(&ts)
	if err == nil {
		for key := range lagKeys {
			flag = true
			log.Info("Member port", lagKeys[key].Get(1))
			memberKey := *lagName + "|" + lagKeys[key].Get(1)
			lagMemberMap[memberKey] = db.Value{Field: map[string]string{}}
		}
		if flag {
			resMap["PORTCHANNEL_MEMBER"] = lagMemberMap
		}
	}

	/* Handle PORTCHANNEL_INTERFACE TABLE */
	processIntfTableRemoval(inParams.d, *lagName, PORTCHANNEL_INTERFACE_TN, lagIntfMap)
	if len(lagIntfMap) != 0 {
		resMap[PORTCHANNEL_INTERFACE_TN] = lagIntfMap
	}

	/* Handle PORTCHANNEL TABLE */
	resMap["PORTCHANNEL"] = lagMap
	subOpMap[db.ConfigDB] = resMap
	log.Info("subOpMap: ", subOpMap)
	inParams.subOpDataMap[DELETE] = &subOpMap
	return nil
}

func getLagStateAttr(attr *string, ifName *string, lagInfoMap map[string]db.Value,
	oc_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Aggregation_State) error {
	lagEntries, ok := lagInfoMap[*ifName]
	if !ok {
		errStr := "Cannot find info for Interface: " + *ifName
		return errors.New(errStr)
	}
	switch *attr {
	case "min-links":
		links, _ := strconv.Atoi(lagEntries.Field["min-links"])
		minlinks := uint16(links)
		oc_val.MinLinks = &minlinks
	}
	return nil
}

func getLagState(inParams XfmrParams, d *db.DB, ifName *string, lagInfoMap map[string]db.Value,
	oc_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Aggregation_State) error {
	log.V(3).Info("getLagState() called")
	lagEntries, ok := lagInfoMap[*ifName]
	if !ok {
		errStr := "Cannot find info for Interface: " + *ifName
		return errors.New(errStr)
	}
	links, _ := strconv.Atoi(lagEntries.Field["min-links"])
	minlinks := uint16(links)
	oc_val.MinLinks = &minlinks

	return nil
}

/* Get PortChannel Info */
func fillLagInfoForIntf(inParams XfmrParams, d *db.DB, ifName *string, lagInfoMap map[string]db.Value, targetUri *string) error {
	var err error
	var lagMemKeys []db.Key
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	/* Get members list */
	ts := db.TableSpec{Name: PORTCHANNEL_MEMBER_TN + d.Opts.KeySeparator + *ifName}
	lagMemKeys, err = d.GetKeys(&ts)
	if err != nil {
		return err
	}
	log.Info("lag-member-table keys", lagMemKeys)

	var lagMembers []string
	var memberPortsStr strings.Builder
	for i := range lagMemKeys {
		ethName := lagMemKeys[i].Get(1)
		lagMembers = append(lagMembers, ethName)
		memberPortsStr.WriteString(ethName + ",")
	}
	lagInfoMap[*ifName] = db.Value{Field: make(map[string]string)}
	//if len(lagMembers) > 0 {
	//	lagInfoMap[*ifName].Field["member@"] = strings.Join(lagMembers, ",")
	//}
	/* Get MinLinks value */
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*ifName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		return errors.New(errStr)
	}
	var links int
	if val, ok := curr.Field["min_links"]; ok {
		min_links, err := strconv.Atoi(val)
		if err != nil {
			errStr := "Conversion of string to int failed"
			return errors.New(errStr)
		}
		links = min_links
	} else {
		log.V(3).Info("Minlinks set to 1 (dafault value)")
		min_links, err := strconv.Atoi(DEFAULT_PORTCHANNEL_MIN_LINKS)
		if err != nil {
			errStr := "Conversion of string to int failed"
			return errors.New(errStr)
		}
		links = min_links
	}
	lagInfoMap[*ifName].Field["min-links"] = strconv.Itoa(links)

	/*Get Static Value*/
	//if v, k := curr.Field["static"]; k {
	//	lagInfoMap[*ifName].Field["static"] = v
	//} else {
	//	log.V(3).Info("Mode set to LACP, default value")
	//	lagInfoMap[*ifName].Field["static"] = "false"
	//}

	/* Get gshut mode value */
	//var gshutModeVal string
	//if val, ok := curr.Field["graceful_shutdown_mode"]; ok {
	//	gshutModeVal = val
	//} else {
	//	if log.V(3) {
	//		log.Info("gshutMode set to false (default value)")
	//	}
	//	gshutModeVal = "DISABLE"
	//}
	//lagInfoMap[*ifName].Field["graceful_shutdown_mode"] = gshutModeVal

	/*Get system_mac Value*/
	//if v, k := curr.Field["system_mac"]; k {
	//	lagInfoMap[*ifName].Field["system_mac"] = v
	//} else {
	//	log.V(3).Info("No value is set")
	//	lagInfoMap[*ifName].Field["system_mac"] = ""
	//}

	log.Infof("Updated the lag-info-map for Interface: %s", *ifName)

	return err
}

// YangToDb_lag_min_links_xfmr is a Yang to DB translation overloaded method for handle min-links config
var YangToDb_lag_min_links_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	if log.V(3) {
		log.Info("Entering YangToDb_lag_min_links_xfmr")
	}
	res_map := make(map[string]string)
	var err error

	pathInfo := NewPathInfo(inParams.uri)
	ifKey := pathInfo.Var("name")

	log.Infof("Received Min links config for path: %s; template: %s vars: %v ifKey: %s", pathInfo.Path, pathInfo.YangPath, pathInfo.Vars, ifKey)

	if inParams.param == nil {
		if log.V(3) {
			log.Info("YangToDb_lag_min_links_xfmr Error: No Params")
		}
		return res_map, err
	}

	minLinks, _ := inParams.param.(*uint16)

	if int(*minLinks) > 32 || int(*minLinks) < 0 {
		errStr := "Min links value is invalid for the PortChannel: " + ifKey
		log.Info(errStr)
		err = tlerr.InvalidArgsError{Format: errStr}
		return res_map, err
	}

	res_map["min_links"] = strconv.Itoa(int(*minLinks))
	return res_map, nil
}

var DbToYang_lag_min_links_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	if log.V(3) {
		log.Info("Entering DbToYang_lag_min_links_xfmr")
	}
	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_min_links_xfmr Error: %v ", err)
		return result, err
	}
	data := (*inParams.dbDataMap)[inParams.curDb]
	links, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["min_links"]
	if ok {
		linksUint16, err := uint16Conv(links)
		if err != nil {
			return result, err
		}
		result["min-links"] = linksUint16
	} else {
		if log.V(3) {
			log.Info("min-links set to 1 (default value)")
		}
		linksUint16, err := uint16Conv(DEFAULT_PORTCHANNEL_MIN_LINKS)
		if err != nil {
			return result, err
		}
		result["min-links"] = linksUint16
	}

	return result, err
}

// DbToYang_intf_lag_state_xfmr is a DB to Yang translation overloaded method for PortChannel GET operation
var DbToYang_intf_lag_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || intfsObj.Interface == nil {
		errStr := "Failed to Get root object!"
		log.Errorf(errStr)
		return errors.New(errStr)
	}
	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")
	if _, ok := intfsObj.Interface[ifName]; !ok {
		obj, _ := intfsObj.NewInterface(ifName)
		ygot.BuildEmptyTree(obj)
	}
	intfObj := intfsObj.Interface[ifName]
	if intfObj.Aggregation == nil {
		ygot.BuildEmptyTree(intfObj)
	}
	if intfObj.Aggregation.State == nil {
		ygot.BuildEmptyTree(intfObj.Aggregation)
	}
	intfType, _, err := getIntfTypeByName(ifName)
	if intfType != IntfTypePortChannel || err != nil {
		intfTypeStr := strconv.Itoa(int(intfType))
		errStr := "TableXfmrFunc - Invalid interface type: " + intfTypeStr
		log.Warning(errStr)
		return errors.New(errStr)
	}
	/*Validate given PortChannel exists */
	err = validatePortChannel(inParams.d, ifName)
	if err != nil {
		return err
	}

	targetUriPath := pathInfo.YangPath
	log.Info("targetUriPath is ", targetUriPath)
	lagInfoMap := make(map[string]db.Value)
	ocAggregationStateVal := intfObj.Aggregation.State
	err = fillLagInfoForIntf(inParams, inParams.d, &ifName, lagInfoMap, &targetUriPath)
	if err != nil {
		log.Errorf("Failed to get info: %s failed!", ifName)
		return err
	}
	log.Info("Succesfully completed DB map population!", lagInfoMap)
	switch targetUriPath {
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/min-links":
		log.Info("Get is for min-links")
		attr := "min-links"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/lag-type":
		log.Info("Get is for lag type")
		attr := "mode"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/member":
		log.Info("Get is for member")
		attr := "member"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/aggregation/state":
		fallthrough
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state":
		log.Info("Get is for State Container!")
		err = getLagState(inParams, inParams.d, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/openconfig-interfaces-ext:reason":
		log.Info("Get is for PO reason!")

		attr := "reason"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/graceful-shutdown-mode":
		log.Info("Get is for graceful-shutdown-mode")
		attr := "graceful-shutdown-mode"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/lag-speed":
		log.Info("Get is for lag-speed")
		attr := "lag-speed"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/system-mac":
		log.Info("Get is for system-mac")
		attr := "system-mac"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	default:
		log.Infof(targetUriPath + " - Not an supported Get attribute")
	}
	return err
}

func updateMemberPortsMtu(inParams *XfmrParams, lagName *string, mtuValStr *string) error {
	log.Info("Inside updateLagIntfAndMembersMtu")
	var err error
	resMap := make(map[string]string)
	intPortChannelTbl := IntfTypeTblMap[IntfTypePortChannel]

	/* Validate given PortChannel exits */
	err = validatePortChannel(inParams.d, *lagName)
	if err != nil {
		return err
	}
	ts := db.TableSpec{Name: intPortChannelTbl.cfgDb.memberTN + inParams.d.Opts.KeySeparator + *lagName}
	lagKeys, err := inParams.d.GetKeys(&ts)
	if err == nil {
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		intfMap := make(map[string]map[string]db.Value)
		intTbl := IntfTypeTblMap[IntfTypeEthernet]
		resMap["mtu"] = *mtuValStr
		intfMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)

		for key := range lagKeys {
			portName := lagKeys[key].Get(1)
			intfMap[intTbl.cfgDb.portTN][portName] = db.Value{Field: resMap}
			log.Info("Member port ", portName, " updated with mtu ", *mtuValStr)
		}

		subOpMap[db.ConfigDB] = intfMap
		inParams.subOpDataMap[UPDATE] = &subOpMap
	}
	return err
}