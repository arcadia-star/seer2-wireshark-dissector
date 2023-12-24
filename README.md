## Getting Started
1. Open your `<global configuration directory>/init.lua`(e.g. `C:\Program Files\Wireshark\init.lua` for windows default installation), and make sure the vairable `enable_lua` is set to `true`
2. Copy all `*.lua` in this repo to your plugin folder (for windows default installation, user plugin folder is `%APPDATA%\Wireshark\plugins` or global plugin folder is `C:\Program Files\Wireshark\plugins`).
   more details about wireshark lua configuation can be found in [here](https://gitlab.com/wireshark/wireshark/-/wikis/Lua#how-lua-fits-into-wireshark)
3. Run your wireshark and your game! Wait initialization and select your network interface in wireshark.
4. Now, your wireshark can capture game messages and automatically parse them (including encrypted)!

You can use the following filter names to filter game messages.

## Currently supported Filter list
+ `seer2msg_cleartext`
+ `seer2msg_cleartext_105`
+ `seer2msg_cleartext_106`
+ `seer2msg_cleartext_serverInfo`
+ `seer2msg_ciphertext`

you can use these filter names in wireshark filter input box.

## Identify game connection

currently,

wireshark_seer2msg_cleartext.lua parse any tcp stream with remote port 1863.

wireshark_seer2msg_cipertext.lua parse any tcp stream with remote port 1201-1276 and matched remote ip address.
