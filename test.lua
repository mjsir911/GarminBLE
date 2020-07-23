service_uuid_f = Field.new("btatt.service_uuid128")
btatt_handle_f = Field.new("btatt.handle")
btatt_value_f = Field.new("btatt.value")




vivofit_proto = Proto("vivofit", "Vivofit communications protocol")
vivofit_table = DissectorTable.new("vivofit.type", nil, ftypes.UINT16, base.HEX, vivofit_proto)

message_length = ProtoField.uint16("vivofit.length", "Message Length", base.DEC)
message_type = ProtoField.uint16("vivofit.type", "Message Type", base.HEX)
message_payload = ProtoField.bytes("vivofit.payload", "Message Payload")
message_checksum = ProtoField.uint16("vivofit.checksum", "Checksum", base.HEX)
message_ack = ProtoField.framenum("vivofit.ack_frame", "Acknowledgment Frame")

fragment_frames = ProtoField.framenum("vivofit.fragment", "Fragment of Packet")
fragment_reassembled = ProtoField.framenum("vivofit.reassembed_in", "Reassembly in")

vivofit_proto.fields = {
	message_length,
	message_type,
	message_payload,
	message_checksum,
	message_ack,
	fragment_frames,
	fragment_reassembled,
}
function vivofit_proto.init()
	cur_fragments = {}
	cached_reassembled = {}

	reply_table = {}
	ireply_frame_cache = {}
end

function deCOBS(buf)
	local nbuf = buf:bytes()
	assert(buf(0, 1):uint() == 0)
	local next_zero = 1
	while (nbuf:get_index(next_zero) ~= 0)
	do
		local cur_zero = next_zero
		next_zero = next_zero + nbuf:get_index(next_zero)
		nbuf:set_index(cur_zero, 0)
	end
	return ByteArray.tvb(nbuf:subset(2, nbuf:len() - 3), "de-cobs")
end

function vivofit_proto.dissector(buffer, pinfo, root)
	print(btatt_handle_f());
	if btatt_handle_f() == nil then return end
	if tostring(btatt_handle_f()) ~= "0x0000000e" and tostring(btatt_handle_f()) ~= "0x00000010" then return end
	-- if service_uuid_f() == nil then return end
	-- if tostring(service_uuid_f()) ~= "9b:01:24:01:bc:30:ce:9a:e1:11:0f:67:e4:91:ab:de" then return end
	if btatt_value_f() == nil then return end
	buffer = btatt_value_f().range

	local last_packet = buffer(buffer:len() - 1):int() == 0

	frag_cache = cached_reassembled[pinfo.number] or {}

	if not pinfo.visited then
		if cur_fragments[tostring(pinfo.src)] == nil then
			cur_fragments[tostring(pinfo.src)] = {}
		end
		local frag_group = cur_fragments[tostring(pinfo.src)]
		frag_group[#frag_group + 1] = {num = pinfo.number, buf = buffer:bytes()}
		if last_packet then
			local abuf = ByteArray.new()
			frag_cache.buf = abuf

			local frames = {}
			frag_cache.frames = frames

			for i = 1,#frag_group,1 do
				frames[i] = frag_group[i].num
				abuf:append(frag_group[i].buf)
				cached_reassembled[frag_group[i].num] = frag_cache
			end
			cur_fragments[tostring(pinfo.src)] = {}
		end
	else 
		if frag_cache.frames ~= nil and not last_packet then
			local last_frame = frag_cache.frames[#frag_cache.frames]
			root:add(fragment_reassembled, last_frame)
				:set_generated(true)
		end
	end


	if not last_packet then return end

	pinfo.cols.protocol = vivofit_proto.name
	local defragged = frag_cache.buf:tvb("Reassembled")
	buffer = deCOBS(defragged)
	local tree = root:add(vivofit_proto, buffer(), "VivoFit Protocol Data")
	local reassembled = tree:add(buffer(0), "Reassembled Segments")
		:set_generated(true)
	for i = 1,#frag_cache.frames,1 do
		local buf_offset = (i - 1) * 20
		local rest = math.min(defragged:len(), buf_offset + 20) - buf_offset
		reassembled:add(fragment_frames, defragged(buf_offset, rest), frag_cache.frames[i])
			:set_generated(true)
	end
	tree:add_le(message_length, buffer(0,2))
	tree:add_le(message_type, buffer(2,2))
	tree:add_le(message_checksum, buffer(buffer:len() - 2, 2))

	if not pinfo.visited then
		reply_table[buffer(2, 2):le_uint()] = pinfo.number
	end

	if ireply_frame_cache[pinfo.number] ~= nil then
		tree:add(message_ack, ireply_frame_cache[pinfo.number])
		:set_generated(true)
	end

	tree:add(message_payload, buffer(4, buffer:len() - 6))
	pinfo.cols.info = "Message Type: 0x" .. buffer(3, 1) .. buffer(2, 1)
	vivofit_table:try(buffer(2,2):le_uint(), buffer(4, buffer:len() - 6):tvb(), pinfo, root)
end

register_postdissector(vivofit_proto)
--
--
-- Begin Ack 0x1388
--
vivofit_ack_table = DissectorTable.new("vivofit.ack.type", nil, ftypes.UINT16, base.HEX, vivofit_proto)
vivofit_ack = Proto("vivofit.ack", "Vivofit Acknowledgment")
ack_reply_type = ProtoField.uint16("vivofit.ack.type", "Reply Type", base.HEX)
ack_reply_frame = ProtoField.framenum("vivofit.ack.reply", "Reply Frame", base.NONE, frametype.ACK)
vivofit_ack.fields = {
	ack_reply_type,
	ack_reply_frame,
}
function vivofit_ack.init()
	reply_frame_cache = {}
end
function vivofit_ack.dissector(buffer, pinfo, root)
	local tree = root:add(vivofit_ack, buffer())
	tree:add_le(ack_reply_type, buffer(0, 2))
	pinfo.cols.info = "Message reply to: 0x" .. buffer(1, 1) .. buffer(0, 1)
	if not pinfo.visited then
		reply_frame_cache[pinfo.number] = reply_table[buffer(0, 2):le_uint()]
		ireply_frame_cache[reply_table[buffer(0, 2):le_uint()]] = pinfo.number
	end
	tree:add_le(ack_reply_frame, reply_frame_cache[pinfo.number])
		:set_generated(true)
	local type = buffer(0, 2):le_uint()
	if vivofit_ack_table:get_dissector(type) ~= nil then
		vivofit_ack_table:try(type, buffer(3):tvb(), pinfo, root)
	else
		vivofit_table:try(type, buffer(3):tvb(), pinfo, root)
	end
end
vivofit_table:add(0x1388, vivofit_ack)
--
--
-- Begin System Message 0x13a6
--
vivofit_system_event = Proto("vivofit.system_event", "Vivofit System Event Message")
function vivofit_system_event.dissector(buffer, pinfo, root)
	-- print("vivofit_system_event: " .. tostring(pinfo.number))
end
vivofit_table:add(0x13a6, vivofit_system_event)
--
--
-- Begin Set Time 0x13a2
--
vivofit_set_time = Proto("vivofit.set_time", "Vivofit Set Time Message")
time_settings_count = ProtoField.uint8("vivofit.set_time.count", "Time Settings Count", base.DEC)
time_setting = ProtoField.protocol("vivofit.set_time.setting", "Time Setting")
time_setting_len = ProtoField.uint8("vivofit.set_time.setting.len", "Setting Length")
time_setting_type = ProtoField.uint8("vivofit.set_time.setting.type", "Setting Type")
time_setting_data = ProtoField.uint32("vivofit.set_time.setting.data", "Setting Data")
mytest = ProtoField.absolute_time("vivofit_set_time.setting.time", "Setting Time")
vivofit_set_time.fields = {
	time_settings_count,
	time_setting,
	time_setting_len,
	time_setting_type,
	time_setting_data,
	mytest,
}

time_base = NSTime(631065600) - NSTime()
function vivofit_set_time.dissector(buffer, pinfo, root)
	-- print("vivofit_set_time: " .. tostring(pinfo.number))
	local tree = root:add(vivofit_set_time, buffer())
	tree:add(time_settings_count, buffer(0, 1))
	local i = 1
	for _ = 1,buffer(0, 1):uint(),1 do
		local start = i
		type = buffer(i, 1)
		i = i + 1
		len = buffer(i, 1)
		i = i + 1
		data = buffer(i, len:uint())
		i = i + len:uint()
		local subtree = tree:add(time_setting, buffer(start, len:uint() + 2), "test")
		subtree:add_le(time_setting_type, type)
		subtree:add_le(time_setting_len, len)
		subtree:add_le(mytest, data, NSTime(data:le_uint()) + time_base)
		-- print(os.date())
	end
	pinfo.cols.info = "Time set message"
end
vivofit_table:add(0x13a2, vivofit_set_time)
--
--
-- Begin Device Info 0x13a0
--
vivofit_device_info = Proto("vivofit.device_info", "VivoFit Device Info")
info_proto_version = ProtoField.uint16("vivofit.device_info.proto_version", "Protocol Version")
info_product_num = ProtoField.uint16("vivofit.device_info.product_number", "Product Number")
info_unit_id = ProtoField.uint32("vivofit.device_info.unit_id", "Unit ID")
info_software_version = ProtoField.uint16("vivofit.device_info.software_version", "Software Version")
info_max_packet_size = ProtoField.uint16("vivofit.device_info.max_packet_size", "Maximum Packet Size", base.HEX)
info_name_length = ProtoField.uint8("vivofit.device_info.name.length", "Device Name Length")
info_name = ProtoField.string("vivofit.device_info.name", "Device Name", base.UTF8)
info_manufacturer_length = ProtoField.uint8("vivofit.device_info.manufacturer.length", "Device Manufacturer Length")
info_manufacturer = ProtoField.string("vivofit.device_info.manufacturer", "Device Manufacturer", base.UTF8)
info_model_length = ProtoField.uint8("vivofit.device_info.model.length", "Device Model Length")
info_model = ProtoField.string("vivofit.device_info.model", "Device Model", base.UTF8)
vivofit_device_info.fields = {
	info_proto_version,
	info_product_num,
	info_unit_id,
	info_software_version,
	info_max_packet_size,
	info_name_length,
	info_name,
	info_manufacturer_length,
	info_manufacturer,
	info_model_length,
	info_model,
}
function vivofit_device_info.dissector(buffer, pinfo, root)
	local tree = root:add(vivofit_device_info, buffer())
	tree:add_le(info_proto_version, buffer(0, 2))
	tree:add_le(info_product_num, buffer(2, 2))
	tree:add_le(info_unit_id, buffer(4, 4))
	tree:add_le(info_software_version, buffer(8, 2))
	tree:add_le(info_max_packet_size, buffer(10, 2))

	offset = 12
	tree:add_le(info_name_length, buffer(offset, 1))
	tree:add_packet_field(info_name, buffer(offset + 1, buffer(offset, 1):uint()), ENC_UTF_8)

	offset = offset + buffer(offset, 1):uint() + 1
	tree:add_le(info_manufacturer_length, buffer(offset, 1))
	tree:add_packet_field(info_manufacturer, buffer(offset + 1, buffer(offset, 1):uint()), ENC_UTF_8)

	offset = offset + buffer(offset, 1):uint() + 1
	tree:add_le(info_model_length, buffer(offset, 1))
	tree:add_packet_field(info_model, buffer(offset + 1, buffer(offset, 1):uint()), ENC_UTF_8)
	pinfo.cols.info = "Device Info"
end
vivofit_table:add(0x13a0, vivofit_device_info)
--
--
-- Begin Download Request 0x138a
--
vivofit_download_request = Proto("vivofit.download_request", "Vivofit Download Request")
download_request_filenum = ProtoField.uint16("vivofit.download_request.filenum", "File Number", base.HEX)
download_request_offset = ProtoField.uint32("vivofit.download_request.offset", "Offset")
download_request_type = ProtoField.uint8("vivofit.download_request.type", "Type", base.HEX)
download_request_data = ProtoField.framenum("vivofit.download_request.data", "Data")
-- download_request_length = ProtoField.uint32("vivofit.download_request.length", "Length")
vivofit_download_request.fields = {
	download_request_filenum,
	download_request_offset,
	download_request_type,
	download_request_data,
	-- download_request_length,
}
function vivofit_download_request.init()
	downloaded_file = nil
	-- = {
	-- 	request_frame = num
	-- 	len = num
	-- 	count = num
	-- 	data_frames = [{
	-- 		buf = buffer
	-- 		num = num
	-- 		len = number
	-- 	}]
	cached_downloads = {}
	-- = {
	-- 	num1, num2, num3 {
	-- 		buf = buffer
	-- 		frames = [{ num = number,  len = number}]
	-- 	}
	-- }
end
function vivofit_download_request.dissector(buffer, pinfo, root)
	pinfo.cols.info = "Download Request"
	local tree = root:add(vivofit_download_request, buffer())
	tree:add_le(download_request_filenum, buffer(0, 2))
	tree:add_le(download_request_offset, buffer(2, 4))
	tree:add_le(download_request_type, buffer(6, 1))

	if not pinfo.visited then
		downloaded_file = {}
		downloaded_file.request_frame = pinfo.number
		downloaded_file.data_frames = {}
		downloaded_file.count = 0
	else
		local frames = cached_downloads[pinfo.number].frames
		tree:add(download_request_data, frames[#frames].num)
			:set_generated(true)
	end
end
vivofit_table:add(0x138a, vivofit_download_request)
--
--
-- Begin Download Request Reply 0x138a-R
--
vivofit_download_request_reply = Proto("vivofit.download_request_reply", "Vivofit Download Request Reply")
download_request_reply_status = ProtoField.uint8("vivofit.download_request_reply.status", "Status", base.HEX)
download_request_reply_length = ProtoField.uint32("vivofit.download_request_reply.length", "Length")
vivofit_download_request_reply.fields = {
	download_request_reply_status,
	download_request_reply_length,
}
function vivofit_download_request_reply.dissector(buffer, pinfo, root)
	pinfo.cols.info = "Download Request Reply"
	local tree = root:add(vivofit_download_request_reply, buffer())
	tree:add_le(download_request_reply_status, buffer(0, 1))
	tree:add_le(download_request_reply_length, buffer(1, 4))

	if not pinfo.visited then
		assert(downloaded_file.request_frame ~= nil)
		downloaded_file.len = buffer(1, 4):le_uint()
	end
end
vivofit_ack_table:add(0x138a, vivofit_download_request_reply)
--
--
-- Begin File Data 0x138c
--
vivofit_file_data = Proto("vivofit.file_data", "Vivofit File Data")
file_data_flags = ProtoField.uint8("vivofit.file_data.flags", "File Data Flags", base.HEX)
file_data_crc = ProtoField.uint16("vivofit.file_data.crc", "File Data CRC", base.HEX)
file_data_offset = ProtoField.uint16("vivofit.file_data.offset", "File Data Offset")
file_data_data = ProtoField.bytes("vivofit.file_data.data", "File Data")
file_data_full = ProtoField.bytes("vivofit.file_data.data_full", "Full File Data")
file_data_fragment = ProtoField.framenum("vivofit.file_data.fragment", "File Data Fragment")
vivofit_file_data.fields = {
	file_data_flags,
	file_data_crc,
	file_data_offset,
	file_data_data,
	file_data_full,
	file_data_fragment,
}
-- if you want to decode these further, see here: https://pub.ks-and-ks.ne.jp/cycling/edge500_fit.shtml
function vivofit_file_data.dissector(buffer, pinfo, root)
	pinfo.cols.info = "File Data"
	local tree = root:add(vivofit_file_data, buffer())
	tree:add_le(file_data_flags, buffer(0, 1))
	tree:add_le(file_data_crc, buffer(1, 2))
	tree:add_le(file_data_offset, buffer(3, 4))
	tree:add_le(file_data_data, buffer(7))

	if not pinfo.visited then
		dframes = downloaded_file.data_frames 
		assert(dframes ~= nil)
		dframes[#dframes + 1] = {
			buf = buffer(7):bytes(),
			num = pinfo.number,
			len = buffer(7):bytes():len()
		}
		assert(downloaded_file.count ~= nil)
		downloaded_file.count = downloaded_file.count + buffer:bytes():len()

		assert(downloaded_file.len ~= nil)
		if downloaded_file.count >= downloaded_file.len then
			local final_data = {}

			local abuf = ByteArray.new()
			final_data.buf = abuf

			local frames = {}
			final_data.frames = frames

			cached_downloads[downloaded_file.request_frame] = final_data
			for i = 1,#dframes,1 do
				frames[i] = {
					num = dframes[i].num,
					len = dframes[i].len
				}
				abuf:append(dframes[i].buf)
				cached_downloads[dframes[i].num] = final_data
			end
			downloaded_file = nil
		end
	else
		local frames = cached_downloads[pinfo.number].frames
		if frames[#frames].num == pinfo.number then
			local data = cached_downloads[pinfo.number].buf:tvb("File Data")
			local defragged = root:add(file_data_full, data())
				:set_generated(true)

			local count = 0
			for i = 1,#frames,1 do
				defragged:add(
					file_data_fragment, 
					data(count, frames[i].len),
					frames[i].num
				):set_generated(true)
				count = count + frames[i].len
			end
		else
			root:add(file_data_fragment, frames[#frames].num)
				:set_generated(true)
		end
	end
end
vivofit_table:add(0x138c, vivofit_file_data)
--
--
-- Begin File Data Reply 0x138c-R
--
vivofit_file_data_reply = Proto("vivofit.file_data_reply", "Vivofit File Data Reply")
file_data_reply_status = ProtoField.uint8("vivofit.file_data_reply.status", "File Data Status", base.HEX)
file_data_reply_offset = ProtoField.uint16("vivofit.file_data_reply.offset", "File Data Offset")
vivofit_file_data_reply.fields = {
	file_data_reply_status,
	file_data_reply_offset,
}
function vivofit_file_data_reply.dissector(buffer, pinfo, root)
	pinfo.cols.info = "File Data Reply"
	local tree = root:add(vivofit_file_data_reply, buffer())
	tree:add_le(file_data_reply_status, buffer(0, 1))
	tree:add_le(file_data_reply_offset, buffer(1, 4))
	-- print("vivofit_system_event: " .. tostring(pinfo.number))
end
vivofit_ack_table:add(0x138c, vivofit_file_data_reply)
