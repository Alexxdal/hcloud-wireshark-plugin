hcloud_protocol = Proto("HCLOUD",  "HCLOUD Protocol")


local ID_PROTO_STRING = {[0] = "MODBUS", [1] = "HCLOUD", [2] = "BROKER"}
local MSG_TYPE = {[0] = "NORMALE", [1] = "RICHIESTA", [2] = "RISPOSTA"}

local COMMAND = {[0x6400] = "CC_DEV_HELLO", [0x6500] = "CC_SET_PROTOCOL", [0x6600] = "CC_DEV_REG", 
[0x6700] = "CC_SET_DEVICE", [0x6800] = "CC_DEV_LAN_STATUS", [0x6900] = "CC_SET_LAN_STATUS", 
[0x6a00] = "CC_SET_SERVER_NODE"}

local STATUS = {[0] = "NOT_ACCEPTED", [1] = "ACCEPT"}
local ERROR = {[0] = "NO_ERROR", [1] = "BAB_NUM_PROTOCOL", [2] = "BAD_PROTOCOL", [3] = "NOTIFICATION_KEY_LIST"}


protocol_version = ProtoField.bytes("hcloud.protocol_version", "Versione")
body_len = ProtoField.bytes("hcloud.body_len", "Lunghezza")
id_proto = ProtoField.uint8("hcloud.id_proto", "Id protocollo", base.DEC, ID_PROTO_STRING)
major = ProtoField.bytes("hcloud.major", "Major")
minor = ProtoField.bytes("hcloud.minor", "Minor")
revision = ProtoField.bytes("hcloud.revision", "Revisione")
majors = ProtoField.string("hcloud.major", "Major")
minors = ProtoField.string("hcloud.minor", "Minor")
patchs = ProtoField.string("hcloud.revision", "Path")
build = ProtoField.bytes("hcloud.build", "Build")
options = ProtoField.bytes("hcloud.options", "Opzioni")
msg_type = ProtoField.uint8("hcloud.msg_type", "Tipo messaggio", base.DEC, MSG_TYPE)


command_type = ProtoField.uint16("hcloud.command_type", "Comando", base.HEX, COMMAND)
protocols = ProtoField.bytes("hcloud.protocols", "Protocolli")
set_proto_status = ProtoField.uint8("hcloud.set_proto_status", "Stato", base.HEX, STATUS)
set_proto_error = ProtoField.uint8("hcloud.set_proto_error", "Errore", base.HEX, ERROR)
alias_device = ProtoField.string("hcloud.alias_device", "Alias")
password = ProtoField.string("hcloud.password", "Password")
mac_address = ProtoField.ether("hcloud.mac_address", "Address")
code_target = ProtoField.string("hcloud.code_target", "Code target")
type_target = ProtoField.string("hcloud.type_target", "Type target")
revision_data = ProtoField.bytes("hcloud.revision_data", "Revision")


hcloud_protocol.fields = { protocol_version, body_len, id_proto, major, minor, revision, build, options, msg_type,
 command_type, protocols, set_proto_status, set_proto_error,
 alias_device, password, mac_address, code_target, type_target, revision_data, majors, minors, patchs}

function hcloud_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  pinfo.cols.protocol = hcloud_protocol.name
  
  if (length == 10) then
  local subtree = tree:add(hcloud_protocol, buffer(), "HCLOUD Header")
  subtree:add_le(protocol_version, buffer(0,1))
  subtree:add_le(body_len, buffer(1,2))
  subtree:add_le(id_proto, buffer(3,1))
  subtree:add_le(major, buffer(4,1))
  subtree:add_le(minor, buffer(5,1))
  subtree:add_le(revision, buffer(6,1))
  subtree:add_le(build, buffer(7,1))
  subtree:add_le(options, buffer(8,1))
  subtree:add_le(msg_type, buffer(9,1))
  else
  local subtree = tree:add(hcloud_protocol, buffer(), "HCLOUD Body")
  subtree:add(command_type, buffer(0,2))
	if(buffer(0,2):uint() == 0x6400) then
	subtree:add_le(protocols, buffer(2, 4))
	elseif(buffer(0,2):uint() == 0x6500) then
	subtree:add_le(set_proto_status, buffer(2,1))
	subtree:add_le(set_proto_error, buffer(3,1))
	elseif(buffer(0,2):uint() == 0x6600) then
	subtree:add(alias_device, buffer(2,32))
	subtree:add(password, buffer(34,16))
	subtree:add(mac_address, buffer(50,6))
	subtree:add(code_target, buffer(56,6))
	subtree:add(type_target, buffer(62,6))
	subtree:add(majors, buffer(68,1))
	subtree:add(minors, buffer(69,1))
	subtree:add(patchs, buffer(70,1))
	elseif(buffer(0,2):uint() == 0x6700) then
	subtree:add_le(set_proto_status, buffer(2,1))
	subtree:add_le(set_proto_error, buffer(3,1))
	end
  end
  
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(7000, hcloud_protocol)
