//! Closed HostConfig visitor. No serde flatten Content buffer is created.
//! Known duplicate/missing fields keep their original refusal semantics; unknown
//! entries retain wiping keys/values for the unchanged exact policy comparison.
use super::{InputString, LaunchHostConfig};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};

impl<'de> Deserialize<'de> for LaunchHostConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Config;
        impl<'de> Visitor<'de> for Config {
            type Value = LaunchHostConfig;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Docker HostConfig")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut network_mode = None;
                let mut privileged = None;
                let mut readonly_rootfs = None;
                let mut pid_mode = None;
                let mut userns_mode = None;
                let mut cgroupns_mode = None;
                let mut ipc_mode = None;
                let mut uts_mode = None;
                let mut cap_add = None;
                let mut cap_drop = None;
                let mut security_opt = None;
                let mut binds = None;
                let mut mounts = None;
                let mut devices = None;
                let mut device_requests = None;
                let mut device_cgroup_rules = None;
                let mut volumes_from = None;
                let mut tmpfs = None;
                let mut sysctls = None;
                let mut group_add = None;
                let mut cgroup_parent = None;
                let mut runtime = None;
                let mut init = None;
                let mut masked_paths = None;
                let mut readonly_paths = None;
                let mut additional = BTreeMap::new();
                while let Some(key) = map.next_key::<InputString>()? {
                    match key.as_str() {
                        "NetworkMode" => {
                            if network_mode.is_some() {
                                return Err(de::Error::duplicate_field("NetworkMode"));
                            }
                            network_mode = Some(map.next_value()?);
                        }
                        "Privileged" => {
                            if privileged.is_some() {
                                return Err(de::Error::duplicate_field("Privileged"));
                            }
                            privileged = Some(map.next_value()?);
                        }
                        "ReadonlyRootfs" => {
                            if readonly_rootfs.is_some() {
                                return Err(de::Error::duplicate_field("ReadonlyRootfs"));
                            }
                            readonly_rootfs = Some(map.next_value()?);
                        }
                        "PidMode" => {
                            if pid_mode.is_some() {
                                return Err(de::Error::duplicate_field("PidMode"));
                            }
                            pid_mode = Some(map.next_value()?);
                        }
                        "UsernsMode" => {
                            if userns_mode.is_some() {
                                return Err(de::Error::duplicate_field("UsernsMode"));
                            }
                            userns_mode = Some(map.next_value()?);
                        }
                        "CgroupnsMode" => {
                            if cgroupns_mode.is_some() {
                                return Err(de::Error::duplicate_field("CgroupnsMode"));
                            }
                            cgroupns_mode = Some(map.next_value()?);
                        }
                        "IpcMode" => {
                            if ipc_mode.is_some() {
                                return Err(de::Error::duplicate_field("IpcMode"));
                            }
                            ipc_mode = Some(map.next_value()?);
                        }
                        "UTSMode" => {
                            if uts_mode.is_some() {
                                return Err(de::Error::duplicate_field("UTSMode"));
                            }
                            uts_mode = Some(map.next_value()?);
                        }
                        "CapAdd" => {
                            if cap_add.is_some() {
                                return Err(de::Error::duplicate_field("CapAdd"));
                            }
                            cap_add = Some(map.next_value()?);
                        }
                        "CapDrop" => {
                            if cap_drop.is_some() {
                                return Err(de::Error::duplicate_field("CapDrop"));
                            }
                            cap_drop = Some(map.next_value()?);
                        }
                        "SecurityOpt" => {
                            if security_opt.is_some() {
                                return Err(de::Error::duplicate_field("SecurityOpt"));
                            }
                            security_opt = Some(map.next_value()?);
                        }
                        "Binds" => {
                            if binds.is_some() {
                                return Err(de::Error::duplicate_field("Binds"));
                            }
                            binds = Some(map.next_value()?);
                        }
                        "Mounts" => {
                            if mounts.is_some() {
                                return Err(de::Error::duplicate_field("Mounts"));
                            }
                            mounts = Some(map.next_value()?);
                        }
                        "Devices" => {
                            if devices.is_some() {
                                return Err(de::Error::duplicate_field("Devices"));
                            }
                            devices = Some(map.next_value()?);
                        }
                        "DeviceRequests" => {
                            if device_requests.is_some() {
                                return Err(de::Error::duplicate_field("DeviceRequests"));
                            }
                            device_requests = Some(map.next_value()?);
                        }
                        "DeviceCgroupRules" => {
                            if device_cgroup_rules.is_some() {
                                return Err(de::Error::duplicate_field("DeviceCgroupRules"));
                            }
                            device_cgroup_rules = Some(map.next_value()?);
                        }
                        "VolumesFrom" => {
                            if volumes_from.is_some() {
                                return Err(de::Error::duplicate_field("VolumesFrom"));
                            }
                            volumes_from = Some(map.next_value()?);
                        }
                        "Tmpfs" => {
                            if tmpfs.is_some() {
                                return Err(de::Error::duplicate_field("Tmpfs"));
                            }
                            tmpfs = Some(map.next_value()?);
                        }
                        "Sysctls" => {
                            if sysctls.is_some() {
                                return Err(de::Error::duplicate_field("Sysctls"));
                            }
                            sysctls = Some(map.next_value()?);
                        }
                        "GroupAdd" => {
                            if group_add.is_some() {
                                return Err(de::Error::duplicate_field("GroupAdd"));
                            }
                            group_add = Some(map.next_value()?);
                        }
                        "CgroupParent" => {
                            if cgroup_parent.is_some() {
                                return Err(de::Error::duplicate_field("CgroupParent"));
                            }
                            cgroup_parent = Some(map.next_value()?);
                        }
                        "Runtime" => {
                            if runtime.is_some() {
                                return Err(de::Error::duplicate_field("Runtime"));
                            }
                            runtime = Some(map.next_value()?);
                        }
                        "Init" => {
                            if init.is_some() {
                                return Err(de::Error::duplicate_field("Init"));
                            }
                            init = Some(map.next_value()?);
                        }
                        "MaskedPaths" => {
                            if masked_paths.is_some() {
                                return Err(de::Error::duplicate_field("MaskedPaths"));
                            }
                            masked_paths = Some(map.next_value()?);
                        }
                        "ReadonlyPaths" => {
                            if readonly_paths.is_some() {
                                return Err(de::Error::duplicate_field("ReadonlyPaths"));
                            }
                            readonly_paths = Some(map.next_value()?);
                        }
                        _ => {
                            additional.insert(key, map.next_value()?);
                        }
                    }
                }
                Ok(LaunchHostConfig {
                    network_mode: network_mode
                        .ok_or_else(|| de::Error::missing_field("NetworkMode"))?,
                    privileged: privileged.ok_or_else(|| de::Error::missing_field("Privileged"))?,
                    readonly_rootfs: readonly_rootfs
                        .ok_or_else(|| de::Error::missing_field("ReadonlyRootfs"))?,
                    pid_mode: pid_mode.ok_or_else(|| de::Error::missing_field("PidMode"))?,
                    userns_mode: userns_mode
                        .ok_or_else(|| de::Error::missing_field("UsernsMode"))?,
                    cgroupns_mode: cgroupns_mode
                        .ok_or_else(|| de::Error::missing_field("CgroupnsMode"))?,
                    ipc_mode: ipc_mode.ok_or_else(|| de::Error::missing_field("IpcMode"))?,
                    uts_mode: uts_mode.ok_or_else(|| de::Error::missing_field("UTSMode"))?,
                    cap_add: cap_add.ok_or_else(|| de::Error::missing_field("CapAdd"))?,
                    cap_drop: cap_drop.ok_or_else(|| de::Error::missing_field("CapDrop"))?,
                    security_opt: security_opt
                        .ok_or_else(|| de::Error::missing_field("SecurityOpt"))?,
                    binds: binds.ok_or_else(|| de::Error::missing_field("Binds"))?,
                    mounts: mounts.unwrap_or_default(),
                    devices: devices.ok_or_else(|| de::Error::missing_field("Devices"))?,
                    device_requests: device_requests
                        .ok_or_else(|| de::Error::missing_field("DeviceRequests"))?,
                    device_cgroup_rules: device_cgroup_rules
                        .ok_or_else(|| de::Error::missing_field("DeviceCgroupRules"))?,
                    volumes_from: volumes_from
                        .ok_or_else(|| de::Error::missing_field("VolumesFrom"))?,
                    tmpfs: tmpfs.unwrap_or_default(),
                    sysctls: sysctls.unwrap_or_default(),
                    group_add: group_add.ok_or_else(|| de::Error::missing_field("GroupAdd"))?,
                    cgroup_parent: cgroup_parent
                        .ok_or_else(|| de::Error::missing_field("CgroupParent"))?,
                    runtime: runtime.ok_or_else(|| de::Error::missing_field("Runtime"))?,
                    init: init.unwrap_or_default(),
                    masked_paths: masked_paths
                        .ok_or_else(|| de::Error::missing_field("MaskedPaths"))?,
                    readonly_paths: readonly_paths
                        .ok_or_else(|| de::Error::missing_field("ReadonlyPaths"))?,
                    additional,
                })
            }
        }
        d.deserialize_map(Config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::managed_json::decode;
    fn fixture() -> serde_json::Value {
        serde_json::json!({"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,
            "PidMode":"","UsernsMode":"","CgroupnsMode":"private","IpcMode":"private","UTSMode":"",
            "CapAdd":null,"CapDrop":null,"SecurityOpt":null,"Binds":null,"Devices":[],"DeviceRequests":null,
            "DeviceCgroupRules":null,"VolumesFrom":null,"GroupAdd":null,"CgroupParent":"","Runtime":"runc",
            "MaskedPaths":null,"ReadonlyPaths":null})
    }
    #[test]
    fn closed_host_config_preserves_required_optional_duplicate_and_unknown_rules() {
        let base = fixture();
        for key in base.as_object().unwrap().keys() {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                decode::<LaunchHostConfig>(&serde_json::to_vec(&missing).unwrap()).is_err(),
                "missing {key}"
            );
            let mut duplicate = serde_json::to_vec(&base).unwrap();
            duplicate.pop();
            duplicate.extend_from_slice(
                format!(",{}:null}}", serde_json::to_string(key).unwrap()).as_bytes(),
            );
            assert!(
                decode::<LaunchHostConfig>(&duplicate).is_err(),
                "duplicate {key}"
            );
        }
        for optional in ["Mounts", "Tmpfs", "Sysctls", "Init"] {
            let mut value = base.clone();
            value[optional] = serde_json::Value::Null;
            assert!(decode::<LaunchHostConfig>(&serde_json::to_vec(&value).unwrap()).is_ok());
            let mut duplicate = serde_json::to_vec(&value).unwrap();
            duplicate.pop();
            duplicate.extend_from_slice(format!(",\"{optional}\":null}}").as_bytes());
            assert!(decode::<LaunchHostConfig>(&duplicate).is_err());
        }
        let mut extra = serde_json::to_vec(&base).unwrap();
        extra.pop();
        extra.extend_from_slice(br#", "Unknown": {"nested": [1,true,"first"]}, "Unknown": {"nested": [2,false,"last"]}}"#);
        let value: LaunchHostConfig = decode(&extra).unwrap();
        assert_eq!(value.additional.len(), 1);
        assert_eq!(
            value.additional.get("Unknown").unwrap(),
            &serde_json::json!({"nested":[2,false,"last"]})
        );
    }
}
