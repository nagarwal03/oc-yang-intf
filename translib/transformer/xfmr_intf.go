//////////////////////////////////////////////////////////////////////////
//
// Copyright 2019 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
	"errors"
	"strconv"
	"strings"
	//"fmt"
	//"github.com/Azure/sonic-mgmt-common/translib/utils"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)
func init() {

	XlateFuncBind("intf_table_xfmr", intf_table_xfmr)
	
	XlateFuncBind("YangToDb_intf_tbl_key_xfmr", YangToDb_intf_tbl_key_xfmr)
	XlateFuncBind("DbToYang_intf_tbl_key_xfmr", DbToYang_intf_tbl_key_xfmr)

	XlateFuncBind("YangToDb_intf_eth_port_config_xfmr", YangToDb_intf_eth_port_config_xfmr)
	XlateFuncBind("DbToYang_intf_eth_port_config_xfmr", DbToYang_intf_eth_port_config_xfmr)
	
	XlateFuncBind("DbToYangPath_intf_eth_port_config_path_xfmr", DbToYangPath_intf_eth_port_config_path_xfmr)
	
	XlateFuncBind("DbToYang_intf_admin_status_xfmr", DbToYang_intf_admin_status_xfmr)

	XlateFuncBind("YangToDb_intf_enabled_xfmr", YangToDb_intf_enabled_xfmr)
	XlateFuncBind("DbToYang_intf_enabled_xfmr", DbToYang_intf_enabled_xfmr)

}

const (
	PORT_ADMIN_STATUS        = "admin_status"
	PORTCHANNEL_TN           = "PORTCHANNEL"
)

const (
	PIPE  = "|"
	COLON = ":"

	ETHERNET    = "Eth"
	MGMT        = "eth"
	VLAN        = "Vlan"
	PORTCHANNEL = "PortChannel"
	LOOPBACK    = "Loopback"
	VXLAN       = "vtep"
	MANAGEMENT  = "Management"
)

type TblData struct {
	portTN   string
	memberTN string
	intfTN   string
	keySep   string
}

type IntfTblData struct {
	cfgDb       TblData
	appDb       TblData
	stateDb     TblData
	//CountersHdl CounterData
}

var IntfTypeTblMap = map[E_InterfaceType]IntfTblData{
	IntfTypeEthernet: IntfTblData{
		cfgDb:       TblData{portTN: "PORT", intfTN: "INTERFACE", keySep: PIPE},
		appDb:       TblData{portTN: "PORT_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
		stateDb:     TblData{portTN: "PORT_TABLE", intfTN: "INTERFACE_TABLE", keySep: PIPE},
	},
	IntfTypeMgmt: IntfTblData{
		cfgDb:       TblData{portTN: "MGMT_PORT", intfTN: "MGMT_INTERFACE", keySep: PIPE},
		appDb:       TblData{portTN: "MGMT_PORT_TABLE", intfTN: "MGMT_INTF_TABLE", keySep: COLON},
		stateDb:     TblData{portTN: "MGMT_PORT_TABLE", intfTN: "MGMT_INTERFACE_TABLE", keySep: PIPE},
	},
	IntfTypePortChannel: IntfTblData{
		cfgDb:       TblData{portTN: "PORTCHANNEL", intfTN: "PORTCHANNEL_INTERFACE", memberTN: "PORTCHANNEL_MEMBER", keySep: PIPE},
		appDb:       TblData{portTN: "LAG_TABLE", intfTN: "INTF_TABLE", keySep: COLON, memberTN: "LAG_MEMBER_TABLE"},
		stateDb:     TblData{portTN: "LAG_TABLE", intfTN: "INTERFACE_TABLE", keySep: PIPE},
	},
	IntfTypeVlan: IntfTblData{
		cfgDb: TblData{portTN: "VLAN", memberTN: "VLAN_MEMBER", intfTN: "VLAN_INTERFACE", keySep: PIPE},
		appDb: TblData{portTN: "VLAN_TABLE", memberTN: "VLAN_MEMBER_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
	},
	IntfTypeLoopback: IntfTblData{
		cfgDb: TblData{portTN: "LOOPBACK", intfTN: "LOOPBACK_INTERFACE", keySep: PIPE},
		appDb: TblData{portTN: "LOOPBACK_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
	},
	IntfTypeSubIntf: IntfTblData{
		cfgDb:   TblData{portTN: "VLAN_SUB_INTERFACE", intfTN: "VLAN_SUB_INTERFACE", keySep: PIPE},
		appDb:   TblData{portTN: "PORT_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
		stateDb: TblData{portTN: "PORT_TABLE", intfTN: "INTERFACE_TABLE", keySep: PIPE},
	},
}

var dbIdToTblMap = map[db.DBNum][]string{
	db.ConfigDB: {"PORT", "MGMT_PORT", "VLAN", "PORTCHANNEL", "LOOPBACK", "VXLAN_TUNNEL", "VLAN_SUB_INTERFACE"},
	db.ApplDB:   {"PORT_TABLE", "MGMT_PORT_TABLE", "VLAN_TABLE", "LAG_TABLE"},
	db.StateDB:  {"PORT_TABLE", "MGMT_PORT_TABLE", "LAG_TABLE"},
}

type E_InterfaceType int64

const (
	IntfTypeUnset       E_InterfaceType = 0
	IntfTypeEthernet    E_InterfaceType = 1
	IntfTypeMgmt        E_InterfaceType = 2
	IntfTypeVlan        E_InterfaceType = 3
	IntfTypePortChannel E_InterfaceType = 4
	IntfTypeLoopback    E_InterfaceType = 5
	IntfTypeVxlan       E_InterfaceType = 6
	IntfTypeSubIntf     E_InterfaceType = 7
)

type E_InterfaceSubType int64

const (
	IntfSubTypeUnset       E_InterfaceSubType = 0
	IntfSubTypeVlanL2      E_InterfaceSubType = 1
	InterfaceSubTypeVlanL3 E_InterfaceSubType = 2
)


func getIntfTypeByName(name string) (E_InterfaceType, E_InterfaceSubType, error) {

	var err error
	if strings.Contains(name, ".") {
		if strings.HasPrefix(name, ETHERNET) || strings.HasPrefix(name, "Po") {
			return IntfTypeSubIntf, IntfSubTypeUnset, err
		}
	}
	if strings.HasPrefix(name, ETHERNET) {
		return IntfTypeEthernet, IntfSubTypeUnset, err
	} else {
		err = errors.New("Interface name prefix not matched with supported types")
		return IntfTypeUnset, IntfSubTypeUnset, err
	}
}

func getIntfsRoot(s *ygot.GoStruct) *ocbinds.OpenconfigInterfaces_Interfaces {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Interfaces
}

func getPortTableNameByDBId(intftbl IntfTblData, curDb db.DBNum) (string, error) {

	var tblName string

	switch curDb {
	case db.ConfigDB:
		tblName = intftbl.cfgDb.portTN
	case db.ApplDB:
		tblName = intftbl.appDb.portTN
	case db.StateDB:
		tblName = intftbl.stateDb.portTN
	default:
		tblName = intftbl.cfgDb.portTN
	}

	return tblName, nil
}

/* Perform action based on the operation and Interface type wrt Interface name key */
/* It should handle only Interface name key xfmr operations */
func performIfNameKeyXfmrOp(inParams *XfmrParams, requestUriPath *string, ifName *string, ifType E_InterfaceType, subintfid uint32) error {
	var err error
	switch inParams.oper {
	case GET:
		if ifType == IntfTypeSubIntf && subintfid == 0 {
			errStr := "Invalid interface name: " + *ifName
			log.Infof("Invalid interface name: %s for GET path: %v", *ifName, *requestUriPath)
			err = tlerr.InvalidArgsError{Format: errStr}
			return err
		}
	case DELETE:
		if *requestUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface" && subintfid != 0 {
			//subifindex := fmt.Sprint(subintfid)
			//subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
			//resMap := make(map[string]map[string]db.Value)
			//subIntfMap := make(map[string]db.Value)
			//key := *utils.GetSubInterfaceDBKeyfromParentInterfaceAndSubInterfaceID(ifName, &subifindex)
			//err = validateIntfExists(inParams.d, "VLAN_SUB_INTERFACE", key)
			//if err != nil {
			//	return nil
			//}
			//subIntfMap[key] = db.Value{Field: map[string]string{}}
			//resMap["VLAN_SUB_INTERFACE"] = subIntfMap
			//subOpMap[db.ConfigDB] = resMap
			//inParams.subOpDataMap[DELETE] = &subOpMap
			return nil
		}
		//if *requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/config/system-mac" && ifType == IntfTypePortChannel {
		//	// Ugly hack since table & key names are not resolved in delete flow, FIXME
		//	v := db.Value{Field: map[string]string{"system_mac": ""}}
		//	inParams.AddSubOpData(DELETE, db.ConfigDB, PORTCHANNEL_TN, *ifName, v)
		//}

		if *requestUriPath == "/openconfig-interfaces:interfaces/interface" {
			switch ifType {
			case IntfTypeEthernet:
				err = validateIntfExists(inParams.d, IntfTypeTblMap[IntfTypeEthernet].cfgDb.portTN, *ifName)
				if err != nil {
					// Not returning error from here since mgmt infra will return "Resource not found" error in case of non existence entries
					return nil
				}
				errStr := "Physical Interface: " + *ifName + " cannot be deleted"
				err = tlerr.InvalidArgsError{Format: errStr}
				return err
			default:
				errStr := "Invalid interface for delete:" + *ifName
				log.Error(errStr)
				return tlerr.InvalidArgsError{Format: errStr}
			}

		}
	case CREATE:
		fallthrough
	case UPDATE, REPLACE:
		if ifType == IntfTypeEthernet {
			err = validateIntfExists(inParams.d, IntfTypeTblMap[IntfTypeEthernet].cfgDb.portTN, *ifName)
			if err != nil { // Invalid Physical interface
				errStr := "Interface " + *ifName + " cannot be configured."
				return tlerr.InvalidArgsError{Format: errStr}
			}
			if inParams.oper == REPLACE {
				if strings.Contains(*requestUriPath, "/openconfig-interfaces:interfaces/interface") {
					if strings.Contains(*requestUriPath, "openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan") ||
						strings.Contains(*requestUriPath, "mapped-vlans") {
						log.Infof("allow replace operation for switched-vlan")
					} else {
						// OC interfaces yang does not have attributes to set Physical interface critical attributes like speed, alias, lanes, index.
						// Replace/PUT request without the critical attributes would end up in deletion of the same in PORT table, which cannot be allowed.
						// Hence block the Replace/PUT request for Physical interfaces alone.
						err_str := "Replace/PUT request not allowed for Physical interfaces"
						return tlerr.NotSupported(err_str)
					}
				}
			}
		}
	}
	return err
}

/* Validate whether intf exists in DB */
func validateIntfExists(d *db.DB, intfTs string, ifName string) error {
	if len(ifName) == 0 {
		return errors.New("Length of Interface name is zero")
	}

	entry, err := d.GetEntry(&db.TableSpec{Name: intfTs}, db.Key{Comp: []string{ifName}})
	if err != nil || !entry.IsPopulated() {
		errStr := "Invalid Interface:" + ifName
		if log.V(3) {
			log.Error(errStr)
		}
		return tlerr.InvalidArgsError{Format: errStr}
	}
	return nil
}



var intf_table_xfmr TableXfmrFunc = func(inParams XfmrParams) ([]string, error) {
	var tblList []string
	var err error

	pathInfo := NewPathInfo(inParams.uri)

	targetUriPath, _, _ := XfmrRemoveXPATHPredicates(inParams.uri)
	
	//targetUriPath := pathInfo.YangPath
	targetUriXpath, _, _ := XfmrRemoveXPATHPredicates(targetUriPath)
	

	ifName := pathInfo.Var("name")
	if ifName == "" {
		log.Info("TableXfmrFunc - intf_table_xfmr Intf key is not present")

		if _, ok := dbIdToTblMap[inParams.curDb]; !ok {
			if log.V(3) {
				log.Info("TableXfmrFunc - intf_table_xfmr db id entry not present")
			}
			return tblList, errors.New("Key not present")
		} else {
			return dbIdToTblMap[inParams.curDb], nil
		}
	}

	idx := pathInfo.Var("index")
	var i32 uint32
	i32 = 0
	if idx != "" {
		i64, _ := strconv.ParseUint(idx, 10, 32)
		i32 = uint32(i64)
	}

	intfType, _, ierr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		return tblList, errors.New("Invalid interface type IntfTypeUnset")
	}
	intTbl := IntfTypeTblMap[intfType]
	if log.V(3) {
		log.Info("TableXfmrFunc - targetUriPath : ", targetUriPath)
		log.Info("TableXfmrFunc - targetUriXpath : ", targetUriXpath)
	}

	subIfUri := "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/"
	rvlanUri := "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/"

	if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/config") {
		tblList = append(tblList, intTbl.cfgDb.portTN)
	} else if intfType != IntfTypeEthernet && intfType != IntfTypeMgmt &&
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet") {
		//Checking interface type at container level, if not Ethernet type return nil
		return nil, nil
	} else if intfType != IntfTypePortChannel &&
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation") {
		//Checking interface type at container level, if not PortChannel type return nil
		return nil, nil
	} else if intfType != IntfTypeVlan &&
		strings.HasPrefix(targetUriPath, "openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") {
		//Checking interface type at container level, if not Vlan type return nil
		return nil, nil
	} else if intfType != IntfTypeVxlan &&
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vxlan:vxlan-if") {
		//Checking interface type at container level, if not Vxlan type return nil
		return nil, nil
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/state/counters") {
		tblList = append(tblList, "NONE")
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/ethernet/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state") {
		tblList = append(tblList, intTbl.appDb.portTN)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces:nat-zone/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone/config") {
		tblList = append(tblList, intTbl.cfgDb.intfTN)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces:nat-zone/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone/state") {
		tblList = append(tblList, intTbl.appDb.intfTN)
	} else if strings.HasPrefix(targetUriPath, subIfUri+"ipv4/ospfv2/if-addresses/md-authentications") ||
		strings.HasPrefix(targetUriPath, rvlanUri+"ipv4/ospfv2/if-addresses/md-authentications") ||
		strings.HasPrefix(targetUriPath, subIfUri+"openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2/if-addresses/md-authentications") ||
		strings.HasPrefix(targetUriPath, rvlanUri+"openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2/if-addresses/md-authentications") {
		tblList = append(tblList, "NONE")
		if log.V(3) {
			log.Info("intf_table_xfmr - ospf md auth uri return table ", tblList)
		}
	} else if strings.HasPrefix(targetUriPath, subIfUri+"ipv4/ospfv2") ||
		strings.HasPrefix(targetUriPath, rvlanUri+"ipv4/ospfv2") ||
		strings.HasPrefix(targetUriPath, subIfUri+"ipv4/ospfv2/if-addresses/config") ||
		strings.HasPrefix(targetUriPath, rvlanUri+"ipv4/ospfv2/if-addresses/config") ||
		strings.HasPrefix(targetUriPath, subIfUri+"openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2") ||
		strings.HasPrefix(targetUriPath, rvlanUri+"openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2") {
		tblList = append(tblList, "NONE")
		if log.V(3) {
			log.Info("intf_table_xfmr - ospf uri return table ", tblList)
		}
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/config") {
		if i32 > 0 {
			tblList = append(tblList, "VLAN_SUB_INTERFACE")
		} else {
			tblList = append(tblList, intTbl.cfgDb.intfTN)
		}
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/state") {
		tblList = append(tblList, intTbl.appDb.intfTN)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses") {
		tblList = append(tblList, intTbl.cfgDb.intfTN)
	} else if inParams.oper == GET && strings.HasPrefix(targetUriXpath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/neighbors") ||
		strings.HasPrefix(targetUriXpath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/neighbors") {
		tblList = append(tblList, "NONE")
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan") {
		if IntfTypeVlan == intfType {
			if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/config") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/config") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/config") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/config") {
				tblList = append(tblList, intTbl.cfgDb.intfTN)
			} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/state") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/state") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/state") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/state") {
				tblList = append(tblList, intTbl.appDb.intfTN)
			} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses") ||
				strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses") {
				tblList = append(tblList, intTbl.cfgDb.intfTN)
			} else if inParams.oper == GET && strings.HasPrefix(targetUriXpath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/neighbors") ||
				strings.HasPrefix(targetUriXpath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/neighbors") {
				tblList = append(tblList, "NONE")
			} else {
				tblList = append(tblList, intTbl.cfgDb.intfTN)
			}
		}
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/ethernet") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet") {
		if inParams.oper != DELETE {
			tblList = append(tblList, intTbl.cfgDb.portTN)
		}
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces:nat-zone") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone") {
		tblList = append(tblList, intTbl.cfgDb.intfTN)
	} else if targetUriPath == "/openconfig-interfaces:interfaces/interface" {
		tblList = append(tblList, intTbl.cfgDb.portTN)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface") {
		if inParams.oper != DELETE {
			tblList = append(tblList, intTbl.cfgDb.portTN)
		}
	} else {
		err = errors.New("Invalid URI")
	}

	if log.V(3) {
		log.Infof("TableXfmrFunc - Uri: (%v), targetUriPath: %s, tblList: (%v)", inParams.uri, targetUriPath, tblList)
	}

	return tblList, err
}

var YangToDb_intf_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error

	pathInfo := NewPathInfo(inParams.uri)
	reqpathInfo := NewPathInfo(inParams.requestUri)
	requestUriPath := reqpathInfo.YangPath
	
	//test_var := requestUriPath
	//test_var := 

	log.Infof("YangToDb_intf_tbl_key_xfmr: inParams.uri: %s, pathInfo: %s, inParams.requestUri: %s", inParams.uri, pathInfo, requestUriPath)

	ifName := pathInfo.Var("name")
	idx := reqpathInfo.Var("index")
	var i32 uint32
	i32 = 0

	if idx != "" {
		i64, _ := strconv.ParseUint(idx, 10, 32)
		i32 = uint32(i64)
	}

	if ifName == "*" {
		return ifName, nil
	}

	if ifName != "" {
		log.Info("YangToDb_intf_tbl_key_xfmr: ifName: ", ifName)
		intfType, _, ierr := getIntfTypeByName(ifName)
		if ierr != nil {
			log.Errorf("Extracting Interface type for Interface: %s failed!", ifName)
			return "", tlerr.New(ierr.Error())
		}
		err = performIfNameKeyXfmrOp(&inParams, &requestUriPath, &ifName, intfType, i32)
		if err != nil {
			return "", tlerr.InvalidArgsError{Format: err.Error()}
		}
	}
	return ifName, err
}

var DbToYang_intf_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	/* Code for DBToYang - Key xfmr. */
	if log.V(3) {
		log.Info("Entering DbToYang_intf_tbl_key_xfmr")
	}
	res_map := make(map[string]interface{})
	log.Info("DbToYang_intf_tbl_key_xfmr: Interface Name = ", inParams.key)
	res_map["name"] = inParams.key
	return res_map, nil
}

// YangToDb_intf_eth_port_config_xfmr handles port-speed, fec, unreliable-los, auto-neg and aggregate-id config.
var YangToDb_intf_eth_port_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	var lagStr string
	memMap := make(map[string]map[string]db.Value)

	pathInfo := NewPathInfo(inParams.uri)
	requestUriPath := (NewPathInfo(inParams.requestUri)).YangPath
	uriIfName := pathInfo.Var("name")
	ifName := uriIfName

	sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
	log.Infof("YangToDb_intf_eth_port_config_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
	ifName = *sonicIfName

	intfType, _, err := getIntfTypeByName(ifName)
	if err != nil {
		errStr := "Invalid Interface"
		err = tlerr.InvalidArgsError{Format: errStr}
		return nil, err
	}
	if IntfTypeVxlan == intfType || IntfTypeVlan == intfType {
		return memMap, nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	intfObj := intfsObj.Interface[uriIfName]

	// Need to differentiate between config container delete and any attribute other than aggregate-id delete
	if inParams.oper == DELETE {
		/* Handles 3 cases
		   case 1: Deletion request at top-level container / list
		   case 2: Deletion request at ethernet container level
		   case 3: Deletion request at ethernet/config container level */

		//case 1
		if intfObj.Ethernet == nil ||
			//case 2
			intfObj.Ethernet.Config == nil ||
			//case 3
			(intfObj.Ethernet.Config != nil && requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config") {

			// Delete all the Vlans for Interface and member port removal from port-channel
			lagId, err := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
			if lagId != nil {
				log.Infof("%s is member of %s", ifName, *lagId)
			}
			if err != nil {
				errStr := "Retrieveing PortChannel associated with Interface: " + ifName + " failed!"
				return nil, errors.New(errStr)
			}
			if lagId != nil {
				lagStr = *lagId
				intTbl := IntfTypeTblMap[IntfTypePortChannel]
				tblName, _ := getMemTableNameByDBId(intTbl, inParams.curDb)

				m := make(map[string]string)
				value := db.Value{Field: m}
				m["NULL"] = "NULL"
				intfKey := lagStr + "|" + ifName
				if _, ok := memMap[tblName]; !ok {
					memMap[tblName] = make(map[string]db.Value)
				}
				memMap[tblName][intfKey] = value
			}
			return memMap, err
		}
	}

	/* Handle AggregateId config */
	if intfObj.Ethernet.Config.AggregateId != nil {
		if !strings.HasPrefix(ifName, ETHERNET) {
			return nil, errors.New("Invalid config request")
		}
		intTbl := IntfTypeTblMap[IntfTypePortChannel]
		tblName, _ := getMemTableNameByDBId(intTbl, inParams.curDb)

		switch inParams.oper {
		case CREATE:
			fallthrough
		case REPLACE:
			fallthrough
		case UPDATE:
			log.Info("Add member port")
			lagId := intfObj.Ethernet.Config.AggregateId
			lagStr = *lagId

			intfType, _, err := getIntfTypeByName(ifName)
			if intfType != IntfTypeEthernet || err != nil {
				intfTypeStr := strconv.Itoa(int(intfType))
				errStr := "Invalid interface type" + intfTypeStr
				log.Error(errStr)
				return nil, tlerr.InvalidArgsError{Format: errStr}
			}
			/* Check if PortChannel exists */
			err = validateIntfExists(inParams.d, intTbl.cfgDb.portTN, lagStr)
			if err != nil {
				return nil, err
			}

		case DELETE:
			lagId, err := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
			if lagId != nil {
				log.Infof("%s is member of %s", ifName, *lagId)
			}
			if lagId == nil || err != nil {
				return nil, nil
			}
			lagStr = *lagId
		} /* End of switch case */
		if len(lagStr) != 0 {
			m := make(map[string]string)
			value := db.Value{Field: m}
			m["NULL"] = "NULL"
			intfKey := lagStr + "|" + ifName
			if _, ok := memMap[tblName]; !ok {
				memMap[tblName] = make(map[string]db.Value)
			}
			memMap[tblName][intfKey] = value
		}
	}
	/* Handle PortSpeed config */
	if intfObj.Ethernet.Config.PortSpeed != 0 {
		res_map := make(map[string]string)
		value := db.Value{Field: res_map}
		intTbl := IntfTypeTblMap[intfType]
		if isPortGroupMember(ifName) {
			err = tlerr.InvalidArgs("Port group member. Please use port group command to change the speed")
		}
		portSpeed := intfObj.Ethernet.Config.PortSpeed
		val, ok := intfOCToSpeedMap[portSpeed]
		if ok {
			err = validateSpeed(inParams.d, ifName, val)
			if err == nil {
				res_map[PORT_SPEED] = val
				if IntfTypeMgmt != intfType {
					res_map[PORT_AUTONEG] = "off"
					res_map["adv_speeds"] = "all"
					res_map["link_training"] = "off"
					res_map["unreliable_los"] = "auto"
				}
			}
		} else {
			err = tlerr.InvalidArgs("Invalid speed %s", val)
		}

		if err == nil {
			if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
				memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
			}
			memMap[intTbl.cfgDb.portTN][ifName] = value
		}
	} else if requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/port-speed" {
		if inParams.oper == DELETE {
			updateMap := make(map[string]map[string]db.Value)
			intTbl := IntfTypeTblMap[intfType]
			res_map := make(map[string]string)
			value := db.Value{Field: res_map}
			defSpeed := getDefaultSpeed(inParams.d, ifName)
			log.Info("Default speed for ", ifName, " is ", defSpeed)
			if defSpeed != 0 {
				val := strconv.FormatInt(int64(defSpeed), 10)
				err = validateSpeed(inParams.d, ifName, val)
				if err == nil {
					res_map[PORT_SPEED] = val
				}
			}
			if IntfTypeMgmt != intfType {
				var mode string
				mode, err = getDefaultAutoNegMode(ifName)
				if err != nil {
					mode = "off"
				}
				res_map[PORT_AUTONEG] = mode
				res_map["adv_speeds"] = "all"
				res_map["link_training"] = "off"
				res_map["unreliable_los"] = "auto"
			}
			if len(res_map) > 0 {
				if _, ok := updateMap[intTbl.cfgDb.portTN]; !ok {
					updateMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
				}
				updateMap[intTbl.cfgDb.portTN][ifName] = value
				subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
				subOpMap[db.ConfigDB] = updateMap
				inParams.subOpDataMap[UPDATE] = &subOpMap
			}
		} else {
			log.Error("Unexpected oper ", inParams.oper)
		}
	}
	/* Handle Port Duplex Config */
	duplex, dup_present := yangToDbDuplexModeMap[intfObj.Ethernet.Config.DuplexMode]
	if dup_present {
		res_map := make(map[string]string)
		value := db.Value{Field: res_map}
		intTbl := IntfTypeTblMap[intfType]
		log.Info("Validate duplex of %s", duplex)
		res_map[DUPLEX_MODE] = duplex

		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	} else if requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/duplex-mode" && inParams.oper == DELETE {
		res_map := make(map[string]string)
		value := db.Value{Field: res_map}
		intTbl := IntfTypeTblMap[intfType]
		res_map[DUPLEX_MODE] = ""

		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	}
	/* Handle Port FEC config */
	_, present := yangToDbFecMap[intfObj.Ethernet.Config.PortFec]
	if present {
		res_map := make(map[string]string)
		value := db.Value{Field: res_map}
		intTbl := IntfTypeTblMap[intfType]

		portFec := intfObj.Ethernet.Config.PortFec

		if inParams.oper == DELETE {
			/* Delete implies default*/
			portFec = ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_AUTO
		}

		fec_val, ok := yangToDbFecMap[portFec]

		if !ok {
			err = tlerr.InvalidArgs("Invalid FEC %s", portFec)
			log.Infof("Did not find FEC entry")
		} else {
			/* Need the number of lanes */
			port_info, err := inParams.d.GetEntry(&db.TableSpec{Name: "PORT"}, db.Key{Comp: []string{ifName}})
			if err != nil {
				err = tlerr.NotSupported("Port info not readable")
				log.Infof("DB not readable when attempting FEC set to %s", fec_val)
			} else {
				lane_count := len(strings.Split(port_info.Get(PORT_LANES), ","))
				port_speed := port_info.Get(PORT_SPEED)

				log.Infof("Will use lane_count: %d, port_speed: %s, ifname: %s to lookup fec value %s", lane_count, port_speed, ifName, fec_val)

				if fec_val == "default" {
					log.Infof("Default FEC will be used")
					nativeName := *(utils.GetNativeNameFromName(&ifName))
					fec_val = common_utils.Get_default_fec(nativeName, lane_count, port_speed)
					log.Infof("Setting default FEC via DB write %s", fec_val)
					res_map[PORT_FEC] = fec_val
				} else {
					log.Infof("Configured fec of %s", fec_val)
					res_map[PORT_FEC] = fec_val
				}
			}
			if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
				log.Infof("Creating map entry", fec_val)
				memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
			}
			log.Infof("Finishing map assign  %s", fec_val)
			memMap[intTbl.cfgDb.portTN][ifName] = value
		}
	}

	/* Prepare the map to handle multiple entries */
	res_map := make(map[string]string)
	value := db.Value{Field: res_map}

	/* Handle AutoNegotiate config */
	if intfObj.Ethernet.Config.AutoNegotiate != nil {
		if intfType == IntfTypeMgmt || intfType == IntfTypeEthernet {
			intTbl := IntfTypeTblMap[intfType]
			autoNeg := intfObj.Ethernet.Config.AutoNegotiate
			var enStr string
			if *autoNeg {
				if IntfTypeMgmt == intfType {
					enStr = "true"
				} else {
					enStr = "on"
				}
			} else {
				if IntfTypeMgmt == intfType {
					enStr = "false"
				} else {
					enStr = "off"
				}
			}
			res_map[PORT_AUTONEG] = enStr

			if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
				memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
			}
			memMap[intTbl.cfgDb.portTN][ifName] = value
		} else {
			return nil, errors.New("AutoNegotiate config not supported for given Interface type")
		}
	}

	/* Handle Link Training config */
	if intfObj.Ethernet.Config.StandaloneLinkTraining != nil {
		intTbl := IntfTypeTblMap[intfType]
		linkTr := intfObj.Ethernet.Config.StandaloneLinkTraining
		var enStr string
		if *linkTr {
			enStr = "on"
		} else {
			enStr = "off"
		}
		res_map["link_training"] = enStr

		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	}

	/* Handle Advertised Speed config */
	if intfObj.Ethernet.Config.AdvertisedSpeed != nil {
		intTbl := IntfTypeTblMap[intfType]
		advspd := intfObj.Ethernet.Config.AdvertisedSpeed
		if *advspd != "" {
			res_map["adv_speeds"] = *advspd
		} else {
			res_map["adv_speeds"] = "all"
		}

		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	}

	/* Handle Unreliable LOS config */
	if intfObj.Ethernet.Config.UnreliableLos != ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNSET {
		intTbl := IntfTypeTblMap[intfType]
		unlos := yangToDbLosMap[intfObj.Ethernet.Config.UnreliableLos]
		res_map["unreliable_los"] = unlos

		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	}

	/* Handle diag mode config */
	_, diag_update := yangToDbDiagMap[intfObj.Ethernet.Config.DiagMode]
	if diag_update {

		if intfType == IntfTypeMgmt {
			return nil, errors.New("Diag mode not supported for given Interface type")
		}

		res_map := make(map[string]string)
		value := db.Value{Field: res_map}
		intTbl := IntfTypeTblMap[intfType]

		diagMode := intfObj.Ethernet.Config.DiagMode

		if inParams.oper == DELETE {
			/* Delete implies default*/
			diagMode = ocbinds.OpenconfigIfEthernetExt2_DIAG_MODE_TYPE_DIAG_MODE_OFF
		}

		diag, ok := yangToDbDiagMap[diagMode]

		if !ok {
			err = tlerr.InvalidArgs("Invalid diag mode %s", diagMode)
			log.Infof("Did not find diag mode valid entry")
		} else {
			res_map[PORT_DIAG_MODE] = diag

			if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
				memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
			}
			memMap[intTbl.cfgDb.portTN][ifName] = value
			log.Infof("diag mode set to %s", diag)
		}
	}

	/* Handle  */
	if intfObj.Ethernet.Config.HighWattageOpticsEnable != nil {
		intTbl := IntfTypeTblMap[intfType]
		hwoe := intfObj.Ethernet.Config.HighWattageOpticsEnable
		if *hwoe {
			res_map["high-wattage-optics-enable"] = "true"
		} else {
			res_map["high-wattage-optics-enable"] = "false"
		}
		if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
			memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
		}
		memMap[intTbl.cfgDb.portTN][ifName] = value
	}

	return memMap, err
}

// DbToYang_intf_eth_port_config_xfmr is to handle DB to yang translation of port-speed, auto-neg and aggregate-id config.
var DbToYang_intf_eth_port_config_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	intfsObj := getIntfsRoot(inParams.ygRoot)
	pathInfo := NewPathInfo(inParams.uri)
	uriIfName := pathInfo.Var("name")
	ifName := uriIfName

	sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
	log.Infof("DbToYang_intf_eth_port_config_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
	ifName = *sonicIfName

	intfType, _, err := getIntfTypeByName(ifName)
	if err != nil {
		errStr := "Invalid Interface"
		err = tlerr.InvalidArgsError{Format: errStr}
		return err
	}
	if IntfTypeVxlan == intfType {
		return nil
	}
	intTbl := IntfTypeTblMap[intfType]
	tblName := intTbl.cfgDb.portTN
	entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name: tblName}, db.Key{Comp: []string{ifName}})
	if dbErr != nil {
		errStr := "Invalid Interface"
		err = tlerr.InvalidArgsError{Format: errStr}
		return err
	}
	targetUriPath := pathInfo.YangPath
	if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config") {
		get_cfg_obj := false
		var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
		if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
			var ok bool = false
			if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
				intfObj, _ = intfsObj.NewInterface(uriIfName)
			}
			ygot.BuildEmptyTree(intfObj)
		} else {
			ygot.BuildEmptyTree(intfsObj)
			intfObj, _ = intfsObj.NewInterface(uriIfName)
			ygot.BuildEmptyTree(intfObj)
		}
		ygot.BuildEmptyTree(intfObj.Ethernet)
		ygot.BuildEmptyTree(intfObj.Ethernet.Config)

		if targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config" {
			get_cfg_obj = true
		}
		var errStr string
		if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-aggregate:aggregate-id" {
			is_id_populated := false
			intf_lagId, _ := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
			if intf_lagId != nil {
				if strings.HasPrefix(*intf_lagId, "PortChannel") {
					intfObj.Ethernet.Config.AggregateId = intf_lagId
					is_id_populated = true
				}
			}
			if !is_id_populated {
				errStr = "aggregate-id not set"
			}

			// subscribe for aggregate-id needs "Resource not found" for delete notification
			if (targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-aggregate:aggregate-id") && (!is_id_populated) {
				err = tlerr.NotFoundError{Format: "Resource not found"}
				return err
			}
		}

		if entry.IsPopulated() {
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/auto-negotiate" {
				autoNeg, ok := entry.Field[PORT_AUTONEG]
				if ok {
					var oc_auto_neg bool
					if autoNeg == "on" || autoNeg == "true" {
						oc_auto_neg = true
					} else {
						oc_auto_neg = false
					}
					intfObj.Ethernet.Config.AutoNegotiate = &oc_auto_neg
				} else {
					errStr = "auto-negotiate not set"
				}
			}
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/port-speed" {
				speed, ok := entry.Field[PORT_SPEED]
				portSpeed := ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_UNSET
				if ok {
					portSpeed, err = getDbToYangSpeed(speed)
					intfObj.Ethernet.Config.PortSpeed = portSpeed
				} else {
					errStr = "port-speed not set"
				}
			}
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-ethernet-ext2:port-fec" {
				fec, ok := entry.Field[PORT_FEC]
				portFec := ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_UNSET
				if ok {
					portFec, err = getDbToYangFec(fec)
					intfObj.Ethernet.Config.PortFec = portFec
				} else {
					errStr = "port-fec not set"
				}
			}
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-ethernet-ext2:standalone-link-training" {
				lt, ok := entry.Field["link_training"]
				if ok {
					flag := (lt == "on")
					intfObj.Ethernet.Config.StandaloneLinkTraining = &flag
				} else {
					errStr = "link_training not set"
				}
			}
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-ethernet-ext2:advertised-speed" {
				spds, ok := entry.Field["adv_speeds"]
				if ok {
					intfObj.Ethernet.Config.AdvertisedSpeed = &spds
				} else {
					errStr = "advertised-speed not set"
				}
				if spds == "all" {
					spds = ""
				}
			}
			if get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-ethernet-ext2:diag-mode" {
				diag, ok := entry.Field[PORT_DIAG_MODE]
				diagMode := ocbinds.OpenconfigIfEthernetExt2_DIAG_MODE_TYPE_DIAG_MODE_OFF
				if ok {
					diagMode, err = getDbToYangDiag(diag)
					intfObj.Ethernet.Config.DiagMode = diagMode
				} else {
					errStr = "diag-mode not set"
				}
			}
		} else {
			errStr = "Attribute not set"
		}
		if !get_cfg_obj && errStr != "" {
			err = tlerr.InvalidArgsError{Format: errStr}
		}
	}

	return err
}

var DbToYangPath_intf_eth_port_config_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) error {
	log.Info("DbToYangPath_intf_eth_port_config_path_xfmr: params: ", params)

	intfRoot := "/openconfig-interfaces:interfaces/interface"

	if (params.tblName != "PORT") && (params.tblName != "PORTCHANNEL_MEMBER") &&
		(params.tblName != "MGMT_PORT") {
		log.Info("DbToYangPath_intf_eth_port_config_path_xfmr: from wrong table: ", params.tblName)
		return nil
	}

	if (params.tblName == "PORT") && (len(params.tblKeyComp) > 0) {
		params.ygPathKeys[intfRoot+"/name"] = *utils.GetUINameFromNativeName(&params.tblKeyComp[0])
	} else if (params.tblName == "PORTCHANNEL_MEMBER") && (len(params.tblKeyComp) > 1) {
		params.ygPathKeys[intfRoot+"/name"] = *utils.GetUINameFromNativeName(&params.tblKeyComp[1])
	} else if (params.tblName == "MGMT_PORT") && (len(params.tblKeyComp) > 0) {
		params.ygPathKeys[intfRoot+"/name"] = params.tblKeyComp[0]
	} else {
		log.Info("DbToYangPath_intf_eth_port_config_path_xfmr, wrong param: tbl ", params.tblName, " key ", params.tblKeyComp)
		return nil
	}

	log.Info("DbToYangPath_intf_eth_port_config_path_xfmr: params.ygPathkeys: ", params.ygPathKeys)

	return nil
}


var DbToYang_intf_admin_status_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]

	intfType, _, ierr := getIntfTypeByName(inParams.key)
	if intfType == IntfTypeUnset || ierr != nil {
		log.Info("DbToYang_intf_admin_status_xfmr - Invalid interface type IntfTypeUnset")
		return result, errors.New("Invalid interface type IntfTypeUnset")
	}
	if IntfTypeVxlan == intfType {
		return result, nil
	}
	intTbl := IntfTypeTblMap[intfType]

	tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
	if _, ok := data[tblName]; !ok {
		log.Info("DbToYang_intf_admin_status_xfmr table not found : ", tblName)
		return result, errors.New("table not found : " + tblName)
	}
	pTbl := data[tblName]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_intf_admin_status_xfmr Interface not found : ", inParams.key)
		return result, errors.New("Interface not found : " + inParams.key)
	}
	prtInst := pTbl[inParams.key]
	adminStatus, ok := prtInst.Field[PORT_ADMIN_STATUS]
	var status ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus
	if ok {
		if adminStatus == "up" {
			status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus_UP
		} else {
			status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus_DOWN
		}
		result["admin-status"] = ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus.ΛMap(status)["E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus"][int64(status)].Name
	} else {
		log.Info("Admin status field not found in DB")
	}

	return result, err
}

var YangToDb_intf_enabled_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var ifName string
	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		return res_map, nil
	} else {
		for infK := range intfsObj.Interface {
			ifName = infK
		}
	}
	intfType, _, _ := getIntfTypeByName(ifName)
	if IntfTypeVxlan == intfType {
		return res_map, nil
	}
	enabled, _ := inParams.param.(*bool)
	var enStr string
	if *enabled {
		enStr = "up"
	} else {
		enStr = "down"
	}
	res_map[PORT_ADMIN_STATUS] = enStr

	return res_map, nil
}

var DbToYang_intf_enabled_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]

	intfType, _, ierr := getIntfTypeByName(inParams.key)
	if intfType == IntfTypeUnset || ierr != nil {
		log.Info("DbToYang_intf_enabled_xfmr - Invalid interface type IntfTypeUnset")
		return result, errors.New("Invalid interface type IntfTypeUnset")
	}
	if IntfTypeVxlan == intfType {
		return result, nil
	}

	intTbl := IntfTypeTblMap[intfType]

	tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
	if _, ok := data[tblName]; !ok {
		log.Info("DbToYang_intf_enabled_xfmr table not found : ", tblName)
		return result, errors.New("table not found : " + tblName)
	}

	pTbl := data[tblName]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_intf_enabled_xfmr Interface not found : ", inParams.key)
		return result, errors.New("Interface not found : " + inParams.key)
	}
	prtInst := pTbl[inParams.key]
	adminStatus, ok := prtInst.Field[PORT_ADMIN_STATUS]
	if ok {
		if adminStatus == "up" {
			result["enabled"] = true
		} else {
			result["enabled"] = false
		}
	} else {
		log.Info("Admin status field not found in DB")
	}
	return result, err
}
