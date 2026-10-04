-- ============================================================================
-- WSJT-X / MSHV Complete Wireshark Lua Dissector
-- Supports Message Types 0 through 14 including 13-byte Qt QDateTime (Type 5)
-- Author: Filip Jonckers, ON4FF (with a little help from Google Gemini)
-- ============================================================================

local wsjtx_proto = Proto("wsjtx", "WSJT-X / MSHV Protocol")

-- Header Fields
local f_magic        = ProtoField.uint32("wsjtx.magic", "Magic Header", base.HEX)
local f_schema       = ProtoField.uint32("wsjtx.schema", "Schema Version", base.DEC)
local f_type         = ProtoField.uint32("wsjtx.type", "Message Type", base.DEC, {
    [0]  = "Heartbeat",
    [1]  = "Status",
    [2]  = "Decode",
    [3]  = "Clear",
    [4]  = "Reply",
    [5]  = "QSO Logged",
    [6]  = "Close",
    [7]  = "Replay",
    [8]  = "Halt Tx",
    [9]  = "Free Text",
    [10] = "WSSD / Highlight Callsign",
    [11] = "Location",
    [12] = "Logged QSO ADIF",
    [13] = "Server Status",
    [14] = "Configure"
})
local f_client_id    = ProtoField.string("wsjtx.client_id", "Client ID")

-- Type 0: Heartbeat
local f_max_schema   = ProtoField.uint32("wsjtx.max_schema", "Max Schema Version", base.DEC)
local f_version_len  = ProtoField.uint32("wsjtx.version_len", "Version Length", base.DEC)
local f_version      = ProtoField.string("wsjtx.version", "Version")
local f_revision     = ProtoField.string("wsjtx.revision", "Revision")

-- Type 1 & Common Fields
local f_dial_freq    = ProtoField.uint64("wsjtx.dial_freq", "Dial Frequency (Hz)", base.DEC)
local f_mode         = ProtoField.string("wsjtx.mode", "Mode")
local f_dx_call      = ProtoField.string("wsjtx.dx_call", "DX Call")
local f_report       = ProtoField.string("wsjtx.report", "Report")
local f_tx_mode      = ProtoField.string("wsjtx.tx_mode", "Tx Mode")
local f_tx_enabled   = ProtoField.bool("wsjtx.tx_enabled", "Tx Enabled")
local f_transceiving = ProtoField.bool("wsjtx.transceiving", "Transceiving")
local f_decoding     = ProtoField.bool("wsjtx.decoding", "Decoding")
local f_rx_df        = ProtoField.uint32("wsjtx.rx_df", "Rx DF (Hz)", base.DEC)
local f_tx_df        = ProtoField.uint32("wsjtx.tx_df", "Tx DF (Hz)", base.DEC)
local f_de_call      = ProtoField.string("wsjtx.de_call", "DE Call")
local f_de_grid      = ProtoField.string("wsjtx.de_grid", "DE Grid")
local f_dx_grid      = ProtoField.string("wsjtx.dx_grid", "DX Grid")
local f_watchdog     = ProtoField.bool("wsjtx.watchdog", "Watchdog Timeout")
local f_sub_mode     = ProtoField.string("wsjtx.sub_mode", "Submode")
local f_fast_mode    = ProtoField.bool("wsjtx.fast_mode", "Fast Mode")
local f_spec_op_mode = ProtoField.uint8("wsjtx.spec_op_mode", "Special Op Mode", base.DEC)
local f_freq_tol     = ProtoField.uint32("wsjtx.freq_tol", "Frequency Tolerance (Hz)", base.DEC)
local f_tr_period    = ProtoField.uint32("wsjtx.tr_period", "T/R Period (s)", base.DEC)
local f_config_name  = ProtoField.string("wsjtx.config_name", "Configuration Name")
local f_tx_msg       = ProtoField.string("wsjtx.tx_msg", "Tx Message")

-- Type 2 & 4: Decode / Reply
local f_is_new       = ProtoField.bool("wsjtx.is_new", "Is New Decode")
local f_time         = ProtoField.string("wsjtx.time", "Time (UTC)")
local f_snr          = ProtoField.int32("wsjtx.snr", "SNR (dB)", base.DEC)
local f_dt           = ProtoField.double("wsjtx.dt", "Delta Time (s)")
local f_df           = ProtoField.uint32("wsjtx.df", "Delta Freq (Hz)", base.DEC)
local f_message      = ProtoField.string("wsjtx.message", "Message")
local f_low_conf     = ProtoField.bool("wsjtx.low_conf", "Low Confidence")
local f_off_air      = ProtoField.bool("wsjtx.off_air", "Off Air")

-- Type 3: Clear
local f_clear_window = ProtoField.uint8("wsjtx.clear_window", "Clear Window", base.DEC)

-- Type 5: QSO Logged
local f_time_off     = ProtoField.string("wsjtx.time_off", "Date/Time Off (UTC)")
local f_rpt_sent     = ProtoField.string("wsjtx.rpt_sent", "RST Sent")
local f_rpt_rcvd     = ProtoField.string("wsjtx.rpt_rcvd", "RST Rcvd")
local f_tx_power     = ProtoField.string("wsjtx.tx_power", "Tx Power")
local f_comments     = ProtoField.string("wsjtx.comments", "Comments")
local f_name         = ProtoField.string("wsjtx.name", "Name")
local f_time_on      = ProtoField.string("wsjtx.time_on", "Date/Time On (UTC)")
local f_op_call      = ProtoField.string("wsjtx.op_call", "Operator Call")
local f_my_call      = ProtoField.string("wsjtx.my_call", "My Call")
local f_my_grid      = ProtoField.string("wsjtx.my_grid", "My Grid")
local f_ex_sent      = ProtoField.string("wsjtx.ex_sent", "Exchange Sent")
local f_ex_rcvd      = ProtoField.string("wsjtx.ex_rcvd", "Exchange Rcvd")
local f_prop_mode    = ProtoField.string("wsjtx.prop_mode", "Propagation Mode")

-- Type 8, 9, 10, 11, 12: Other Messages
local f_auto_tx_only = ProtoField.bool("wsjtx.auto_tx_only", "Auto Tx Only")
local f_free_text    = ProtoField.string("wsjtx.free_text", "Free Text")
local f_send_text    = ProtoField.bool("wsjtx.send_text", "Send Immediately")
local f_callsign     = ProtoField.string("wsjtx.callsign", "Callsign")
local f_bg_color     = ProtoField.string("wsjtx.bg_color", "Background Color")
local f_fg_color     = ProtoField.string("wsjtx.fg_color", "Foreground Color")
local f_highlight    = ProtoField.bool("wsjtx.highlight", "Highlight Last")
local f_location     = ProtoField.string("wsjtx.location", "Location")
local f_adif_len     = ProtoField.uint32("wsjtx.adif_len", "ADIF Length", base.DEC)
local f_adif_text    = ProtoField.string("wsjtx.adif_text", "ADIF Text")

wsjtx_proto.fields = {
    f_magic, f_schema, f_type, f_client_id, f_max_schema, f_version_len, f_version,
    f_revision, f_dial_freq, f_mode, f_dx_call, f_report, f_tx_mode, f_tx_enabled,
    f_transceiving, f_decoding, f_rx_df, f_tx_df, f_de_call, f_de_grid, f_dx_grid,
    f_watchdog, f_sub_mode, f_fast_mode, f_spec_op_mode, f_freq_tol, f_tr_period,
    f_config_name, f_tx_msg, f_is_new, f_time, f_snr, f_dt, f_df, f_message,
    f_low_conf, f_off_air, f_clear_window, f_time_off, f_rpt_sent, f_rpt_rcvd,
    f_tx_power, f_comments, f_name, f_time_on, f_op_call, f_my_call, f_my_grid,
    f_ex_sent, f_ex_rcvd, f_prop_mode, f_auto_tx_only, f_free_text, f_send_text,
    f_callsign, f_bg_color, f_fg_color, f_highlight, f_location, f_adif_len, f_adif_text
}

-- ============================================================================
-- HELPER PARSERS (Qt Data Types)
-- ============================================================================

local function read_qstring(buffer, offset)
    if offset + 4 > buffer:len() then return "", offset end
    local len = buffer(offset, 4):uint()
    offset = offset + 4
    if len == 0xffffffff or len == 0 then
        return "", offset
    end
    if offset + len > buffer:len() then return "<truncated>", buffer:len() end
    local str = buffer(offset, len):string()
    return str, offset + len
end

local function read_bool(buffer, offset)
    if offset + 1 > buffer:len() then return false, offset end
    local val = buffer(offset, 1):uint() ~= 0
    return val, offset + 1
end

local function read_qtime(buffer, offset)
    if offset + 4 > buffer:len() then return "N/A", offset end
    local ms_midnight = buffer(offset, 4):uint()
    offset = offset + 4
    if ms_midnight == 0xffffffff then return "N/A", offset end
    
    local total_sec = math.floor(ms_midnight / 1000)
    local hrs = math.floor(total_sec / 3600)
    local mins = math.floor((total_sec % 3600) / 60)
    local secs = total_sec % 60
    return string.format("%02d:%02d:%02d UTC", hrs, mins, secs), offset
end

local function read_qdatetime(buffer, offset)
    if offset + 13 > buffer:len() then return "N/A", offset end
    
    local julian_day = buffer(offset, 8):int64():tonumber()
    local ms_midnight = buffer(offset + 8, 4):uint()
    offset = offset + 13

    if julian_day <= 0 then
        return "N/A", offset
    end

    -- Julian Day 2440588 = 1970-01-01 00:00:00 UTC (Unix Epoch)
    local unix_epoch_jd = 2440588
    local days_since_epoch = julian_day - unix_epoch_jd
    local epoch_seconds = (days_since_epoch * 86400) + math.floor(ms_midnight / 1000)

    local formatted_utc = os.date("!%Y-%m-%d %H:%M:%S UTC", epoch_seconds)
    return formatted_utc, offset
end

local function read_qcolor(buffer, offset)
    if offset + 14 > buffer:len() then return "N/A", offset end
    local spec = buffer(offset, 1):uint()
    local alpha = buffer(offset + 1, 2):uint()
    local red   = buffer(offset + 3, 2):uint()
    local green = buffer(offset + 5, 2):uint()
    local blue  = buffer(offset + 7, 2):uint()
    offset = offset + 14
    return string.format("#%02X%02X%02X (A:%d)", red/256, green/256, blue/256, alpha/256), offset
end

-- ============================================================================
-- MAIN DISSECTOR ENTRYPOINT
-- ============================================================================

function wsjtx_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 12 then return end

    -- Verify Magic Number (0xadbccbda)
    local magic = buffer(0, 4):uint()
    if magic ~= 0xadbccbda then return end

    pinfo.cols.protocol = "WSJT-X"

    local subtree = tree:add(wsjtx_proto, buffer(), "WSJT-X Protocol Payload")
    local offset = 0

    -- Header Processing
    subtree:add(f_magic, buffer(offset, 4))
    offset = offset + 4
    subtree:add(f_schema, buffer(offset, 4))
    offset = offset + 4

    local msg_type = buffer(offset, 4):uint()
    subtree:add(f_type, buffer(offset, 4))
    offset = offset + 4

    local client_id
    client_id, offset = read_qstring(buffer, offset)
    subtree:add(f_client_id, buffer(offset - string.len(client_id) - 4, string.len(client_id) + 4), client_id)

    -- ------------------------------------------------------------------------
    -- TYPE 0: Heartbeat
    -- ------------------------------------------------------------------------
    if msg_type == 0 then
        pinfo.cols.info = "Heartbeat (Type 0) - " .. client_id
        if offset < length then 
            subtree:add(f_max_schema, buffer(offset, 4))
            offset = offset + 4 
        end

        -- Version Field Length (4 bytes) decoded separately
        local ver_len = buffer(offset, 4):uint()
        subtree:add(f_version_len, buffer(offset, 4))
        offset = offset + 4

        local ver = ""
        if ver_len > 0 and ver_len ~= 0xffffffff then
            ver = buffer(offset, ver_len):string()
            subtree:add(f_version, buffer(offset, ver_len), ver)
            offset = offset + ver_len
        end

        local rev
        rev, offset = read_qstring(buffer, offset)
        subtree:add(f_revision, buffer(offset - string.len(rev) - 4, string.len(rev) + 4), rev)

    -- ------------------------------------------------------------------------
    -- TYPE 1: Status
    -- ------------------------------------------------------------------------
    elseif msg_type == 1 then
        pinfo.cols.info = "Status (Type 1) - " .. client_id
        local dial_freq = buffer(offset, 8):uint64():tonumber()
        subtree:add(f_dial_freq, buffer(offset, 8))
        offset = offset + 8

        local mode, dx_call, rpt, tx_mode, de_call, de_grid, dx_grid, submode, cfg, tx_msg
        local tx_en, rx_ing, dec_ing, wd, fast

        mode, offset = read_qstring(buffer, offset); subtree:add(f_mode, buffer(offset - string.len(mode) - 4, string.len(mode) + 4), mode)
        dx_call, offset = read_qstring(buffer, offset); subtree:add(f_dx_call, buffer(offset - string.len(dx_call) - 4, string.len(dx_call) + 4), dx_call)
        rpt, offset = read_qstring(buffer, offset); subtree:add(f_report, buffer(offset - string.len(rpt) - 4, string.len(rpt) + 4), rpt)
        tx_mode, offset = read_qstring(buffer, offset); subtree:add(f_tx_mode, buffer(offset - string.len(tx_mode) - 4, string.len(tx_mode) + 4), tx_mode)

        tx_en, offset = read_bool(buffer, offset); subtree:add(f_tx_enabled, buffer(offset - 1, 1), tx_en)
        rx_ing, offset = read_bool(buffer, offset); subtree:add(f_transceiving, buffer(offset - 1, 1), rx_ing)
        dec_ing, offset = read_bool(buffer, offset); subtree:add(f_decoding, buffer(offset - 1, 1), dec_ing)

        subtree:add(f_rx_df, buffer(offset, 4)); offset = offset + 4
        subtree:add(f_tx_df, buffer(offset, 4)); offset = offset + 4

        de_call, offset = read_qstring(buffer, offset); subtree:add(f_de_call, buffer(offset - string.len(de_call) - 4, string.len(de_call) + 4), de_call)
        de_grid, offset = read_qstring(buffer, offset); subtree:add(f_de_grid, buffer(offset - string.len(de_grid) - 4, string.len(de_grid) + 4), de_grid)
        dx_grid, offset = read_qstring(buffer, offset); subtree:add(f_dx_grid, buffer(offset - string.len(dx_grid) - 4, string.len(dx_grid) + 4), dx_grid)

        wd, offset = read_bool(buffer, offset); subtree:add(f_watchdog, buffer(offset - 1, 1), wd)

        if offset < length then
            submode, offset = read_qstring(buffer, offset); subtree:add(f_sub_mode, buffer(offset - string.len(submode) - 4, string.len(submode) + 4), submode)
        end
        if offset < length then
            fast, offset = read_bool(buffer, offset); subtree:add(f_fast_mode, buffer(offset - 1, 1), fast)
        end
        if offset < length then
            subtree:add(f_spec_op_mode, buffer(offset, 1)); offset = offset + 1
        end
        if offset < length then
            subtree:add(f_freq_tol, buffer(offset, 4)); offset = offset + 4
        end
        if offset < length then
            subtree:add(f_tr_period, buffer(offset, 4)); offset = offset + 4
        end
        if offset < length then
            cfg, offset = read_qstring(buffer, offset); subtree:add(f_config_name, buffer(offset - string.len(cfg) - 4, string.len(cfg) + 4), cfg)
        end
        if offset < length then
            tx_msg, offset = read_qstring(buffer, offset); subtree:add(f_tx_msg, buffer(offset - string.len(tx_msg) - 4, string.len(tx_msg) + 4), tx_msg)
        end

        pinfo.cols.info:append(string.format(" (%.3f MHz, %s)", dial_freq / 1e6, mode))

    -- ------------------------------------------------------------------------
    -- TYPE 2: Decode
    -- ------------------------------------------------------------------------
    elseif msg_type == 2 then
        local is_new, time_str, mode_str, msg_str, low_conf, off_air
        is_new, offset = read_bool(buffer, offset); subtree:add(f_is_new, buffer(offset - 1, 1), is_new)
        time_str, offset = read_qtime(buffer, offset); subtree:add(f_time, buffer(offset - 4, 4), time_str)
        
        subtree:add(f_snr, buffer(offset, 4)); offset = offset + 4
        subtree:add(f_dt, buffer(offset, 8)); offset = offset + 8
        subtree:add(f_df, buffer(offset, 4)); offset = offset + 4

        mode_str, offset = read_qstring(buffer, offset); subtree:add(f_mode, buffer(offset - string.len(mode_str) - 4, string.len(mode_str) + 4), mode_str)
        msg_str, offset = read_qstring(buffer, offset); subtree:add(f_message, buffer(offset - string.len(msg_str) - 4, string.len(msg_str) + 4), msg_str)
        
        if offset < length then
            low_conf, offset = read_bool(buffer, offset); subtree:add(f_low_conf, buffer(offset - 1, 1), low_conf)
        end
        if offset < length then
            off_air, offset = read_bool(buffer, offset); subtree:add(f_off_air, buffer(offset - 1, 1), off_air)
        end

        pinfo.cols.info = string.format("Decode (Type 2): %s - %s", time_str, msg_str)

    -- ------------------------------------------------------------------------
    -- TYPE 3: Clear
    -- ------------------------------------------------------------------------
    elseif msg_type == 3 then
        pinfo.cols.info = "Clear (Type 3)"
        if offset < length then
            subtree:add(f_clear_window, buffer(offset, 1))
        end

    -- ------------------------------------------------------------------------
    -- TYPE 4: Reply
    -- ------------------------------------------------------------------------
    elseif msg_type == 4 then
        pinfo.cols.info = "Reply (Type 4)"
        local time_str, mode_str, msg_str
        time_str, offset = read_qtime(buffer, offset); subtree:add(f_time, buffer(offset - 4, 4), time_str)
        subtree:add(f_snr, buffer(offset, 4)); offset = offset + 4
        subtree:add(f_dt, buffer(offset, 8)); offset = offset + 8
        subtree:add(f_df, buffer(offset, 4)); offset = offset + 4
        mode_str, offset = read_qstring(buffer, offset); subtree:add(f_mode, buffer(offset - string.len(mode_str) - 4, string.len(mode_str) + 4), mode_str)
        msg_str, offset = read_qstring(buffer, offset); subtree:add(f_message, buffer(offset - string.len(msg_str) - 4, string.len(msg_str) + 4), msg_str)

    -- ------------------------------------------------------------------------
    -- TYPE 5: QSO Logged (13-Byte Qt QDateTime Serialization)
    -- ------------------------------------------------------------------------
    elseif msg_type == 5 then
        pinfo.cols.info = "QSO Logged (Type 5)"

        local time_off, dx_call, dx_grid, mode, rpt_s, rpt_r, pwr, comments, name, time_on
        local op_call, my_call, my_grid, ex_s, ex_r, prop

        -- Field 4: Time Off (13-byte Qt QDateTime)
        time_off, offset = read_qdatetime(buffer, offset)
        subtree:add(f_time_off, buffer(offset - 13, 13), time_off)

        -- Field 5: DX Call
        dx_call, offset = read_qstring(buffer, offset)
        subtree:add(f_dx_call, buffer(offset - string.len(dx_call) - 4, string.len(dx_call) + 4), dx_call)

        -- Field 6: DX Grid
        dx_grid, offset = read_qstring(buffer, offset)
        subtree:add(f_dx_grid, buffer(offset - string.len(dx_grid) - 4, string.len(dx_grid) + 4), dx_grid)

        -- Field 7: Dial Freq (8 bytes)
        subtree:add(f_dial_freq, buffer(offset, 8))
        offset = offset + 8

        -- Field 8: Mode
        mode, offset = read_qstring(buffer, offset)
        subtree:add(f_mode, buffer(offset - string.len(mode) - 4, string.len(mode) + 4), mode)

        -- Field 9: Report Sent
        rpt_s, offset = read_qstring(buffer, offset)
        subtree:add(f_rpt_sent, buffer(offset - string.len(rpt_s) - 4, string.len(rpt_s) + 4), rpt_s)

        -- Field 10: Report Rcvd
        rpt_r, offset = read_qstring(buffer, offset)
        subtree:add(f_rpt_rcvd, buffer(offset - string.len(rpt_r) - 4, string.len(rpt_r) + 4), rpt_r)

        -- Field 11: Tx Power
        pwr, offset = read_qstring(buffer, offset)
        subtree:add(f_tx_power, buffer(offset - string.len(pwr) - 4, string.len(pwr) + 4), pwr)

        -- Field 12: Comments
        comments, offset = read_qstring(buffer, offset)
        subtree:add(f_comments, buffer(offset - string.len(comments) - 4, string.len(comments) + 4), comments)

        -- Field 13: Name
        name, offset = read_qstring(buffer, offset)
        subtree:add(f_name, buffer(offset - string.len(name) - 4, string.len(name) + 4), name)

        -- Field 14: Time On (13-byte Qt QDateTime)
        time_on, offset = read_qdatetime(buffer, offset)
        subtree:add(f_time_on, buffer(offset - 13, 13), time_on)

        -- Field 15: Operator Call
        op_call, offset = read_qstring(buffer, offset)
        subtree:add(f_op_call, buffer(offset - string.len(op_call) - 4, string.len(op_call) + 4), op_call)

        -- Field 16: My Call
        my_call, offset = read_qstring(buffer, offset)
        subtree:add(f_my_call, buffer(offset - string.len(my_call) - 4, string.len(my_call) + 4), my_call)

        -- Field 17: My Grid
        my_grid, offset = read_qstring(buffer, offset)
        subtree:add(f_my_grid, buffer(offset - string.len(my_grid) - 4, string.len(my_grid) + 4), my_grid)

        -- Field 18: Exchange Sent
        ex_s, offset = read_qstring(buffer, offset)
        subtree:add(f_ex_sent, buffer(offset - string.len(ex_s) - 4, string.len(ex_s) + 4), ex_s)

        -- Field 19: Exchange Rcvd
        ex_r, offset = read_qstring(buffer, offset)
        subtree:add(f_ex_rcvd, buffer(offset - string.len(ex_r) - 4, string.len(ex_r) + 4), ex_r)

        -- Field 20: Propagation Mode (Optional)
        if offset < length then
            prop, offset = read_qstring(buffer, offset)
            subtree:add(f_prop_mode, buffer(offset - string.len(prop) - 4, string.len(prop) + 4), prop)
        end

        pinfo.cols.info:append(string.format(" %s DE %s (%s)", dx_call, my_call, mode))

    -- ------------------------------------------------------------------------
    -- TYPE 6: Close
    -- ------------------------------------------------------------------------
    elseif msg_type == 6 then
        pinfo.cols.info = "Close (Type 6) - " .. client_id

    -- ------------------------------------------------------------------------
    -- TYPE 7: Replay
    -- ------------------------------------------------------------------------
    elseif msg_type == 7 then
        pinfo.cols.info = "Replay (Type 7) - " .. client_id

    -- ------------------------------------------------------------------------
    -- TYPE 8: Halt Tx
    -- ------------------------------------------------------------------------
    elseif msg_type == 8 then
        pinfo.cols.info = "Halt Tx (Type 8)"
        local auto_only
        if offset < length then
            auto_only, offset = read_bool(buffer, offset)
            subtree:add(f_auto_tx_only, buffer(offset - 1, 1), auto_only)
        end

    -- ------------------------------------------------------------------------
    -- TYPE 9: Free Text
    -- ------------------------------------------------------------------------
    elseif msg_type == 9 then
        local txt, snd
        txt, offset = read_qstring(buffer, offset)
        subtree:add(f_free_text, buffer(offset - string.len(txt) - 4, string.len(txt) + 4), txt)
        if offset < length then
            snd, offset = read_bool(buffer, offset)
            subtree:add(f_send_text, buffer(offset - 1, 1), snd)
        end
        pinfo.cols.info = "Free Text (Type 9): " .. txt

    -- ------------------------------------------------------------------------
    -- TYPE 10: WSSD / Highlight Callsign
    -- ------------------------------------------------------------------------
    elseif msg_type == 10 then
        pinfo.cols.info = "Highlight Callsign (Type 10)"
        local call, bg, fg, hl
        call, offset = read_qstring(buffer, offset)
        subtree:add(f_callsign, buffer(offset - string.len(call) - 4, string.len(call) + 4), call)
        
        bg, offset = read_qcolor(buffer, offset); subtree:add(f_bg_color, buffer(offset - 14, 14), bg)
        fg, offset = read_qcolor(buffer, offset); subtree:add(f_fg_color, buffer(offset - 14, 14), fg)

        if offset < length then
            hl, offset = read_bool(buffer, offset)
            subtree:add(f_highlight, buffer(offset - 1, 1), hl)
        end

    -- ------------------------------------------------------------------------
    -- TYPE 11: Location
    -- ------------------------------------------------------------------------
    elseif msg_type == 11 then
        local loc
        loc, offset = read_qstring(buffer, offset)
        subtree:add(f_location, buffer(offset - string.len(loc) - 4, string.len(loc) + 4), loc)
        pinfo.cols.info = "Location (Type 11): " .. loc

    -- ------------------------------------------------------------------------
    -- TYPE 12: Logged QSO (ADIF Payload)
    -- ------------------------------------------------------------------------
    elseif msg_type == 12 then
        -- ADIF Length (4 bytes) decoded separately
        local adif_len = buffer(offset, 4):uint()
        subtree:add(f_adif_len, buffer(offset, 4))
        offset = offset + 4

        local adif = ""
        if adif_len > 0 and adif_len ~= 0xffffffff then
            adif = buffer(offset, adif_len):string()
            subtree:add(f_adif_text, buffer(offset, adif_len), adif)
            offset = offset + adif_len
        end
        pinfo.cols.info = "Logged QSO ADIF (Type 12)"

    -- ------------------------------------------------------------------------
    -- TYPE 13 & 14: Server Status / Configure
    -- ------------------------------------------------------------------------
    elseif msg_type == 13 or msg_type == 14 then
        pinfo.cols.info = string.format("Message Type %d", msg_type)
    end
end

-- Register dissector to default WSJT-X / MSHV UDP ports
local udp_table = DissectorTable.get("udp.port")
udp_table:add(2237, wsjtx_proto)
udp_table:add(2238, wsjtx_proto)
