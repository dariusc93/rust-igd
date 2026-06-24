use crate::PortMappingProtocol;
use std::net::SocketAddr;

// Content of the request.
pub const SEARCH_REQUEST: &str = "M-SEARCH * HTTP/1.1\r
Host:239.255.255.250:1900\r
ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
Man:\"ssdp:discover\"\r
MX:3\r\n\r\n";

// SOAP action names.
pub const GET_EXTERNAL_IP_ACTION: &str = "GetExternalIPAddress";

pub const ADD_ANY_PORT_MAPPING_ACTION: &str = "AddAnyPortMapping";

pub const ADD_PORT_MAPPING_ACTION: &str = "AddPortMapping";

pub const DELETE_PORT_MAPPING_ACTION: &str = "DeletePortMapping";

pub const GET_GENERIC_PORT_MAPPING_ENTRY_ACTION: &str = "GetGenericPortMappingEntry";

/// Build the quoted `SOAPAction` header value (`"<service_type>#<action>"`) for a request.
pub fn soap_action(service_type: &str, action: &str) -> String {
    format!("\"{service_type}#{action}\"")
}

const MESSAGE_HEAD: &str = r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>"#;

const MESSAGE_TAIL: &str = r#"</s:Body>
</s:Envelope>"#;

fn format_message(body: String) -> String {
    format!("{MESSAGE_HEAD}{body}{MESSAGE_TAIL}")
}

pub fn format_get_external_ip_message(service_type: &str) -> String {
    format_message(format!(
        r#"<m:GetExternalIPAddress xmlns:m="{service_type}">
        </m:GetExternalIPAddress>"#
    ))
}

pub fn format_add_any_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewEnabled" => 1.to_string(),
                "NewExternalPort" => external_port.to_string(),
                "NewInternalClient" => local_addr.ip().to_string(),
                "NewInternalPort" => local_addr.port().to_string(),
                "NewLeaseDuration" => lease_duration.to_string(),
                "NewPortMappingDescription" => description.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{value}</{argument}>"))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:AddAnyPortMapping xmlns:u="{service_type}">
        {args}
        </u:AddAnyPortMapping>"#,
    ))
}

pub fn format_add_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewEnabled" => 1.to_string(),
                "NewExternalPort" => external_port.to_string(),
                "NewInternalClient" => local_addr.ip().to_string(),
                "NewInternalPort" => local_addr.port().to_string(),
                "NewLeaseDuration" => lease_duration.to_string(),
                "NewPortMappingDescription" => description.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{value}</{argument}>",))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:AddPortMapping xmlns:u="{service_type}">
        {args}
        </u:AddPortMapping>"#
    ))
}

pub fn format_delete_port_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewExternalPort" => external_port.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{value}</{argument}>",))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:DeletePortMapping xmlns:u="{service_type}">
        {args}
        </u:DeletePortMapping>"#
    ))
}

pub fn formate_get_generic_port_mapping_entry_message(service_type: &str, port_mapping_index: u32) -> String {
    format_message(format!(
        r#"<u:GetGenericPortMappingEntry xmlns:u="{service_type}">
        <NewPortMappingIndex>{port_mapping_index}</NewPortMappingIndex>
        </u:GetGenericPortMappingEntry>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

    #[test]
    fn soap_action_uses_service_type() {
        assert_eq!(
            soap_action(PPP, "AddPortMapping"),
            "\"urn:schemas-upnp-org:service:WANPPPConnection:1#AddPortMapping\""
        );
    }

    #[test]
    fn message_body_uses_service_type() {
        let body = format_add_port_mapping_message(
            PPP,
            &["NewProtocol".to_string(), "NewExternalPort".to_string()],
            PortMappingProtocol::TCP,
            12345,
            "192.168.1.5:80".parse().unwrap(),
            0,
            "test",
        );
        assert!(body.contains(r#"xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1""#));
        assert!(body.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(body.contains("<NewExternalPort>12345</NewExternalPort>"));
    }
}
