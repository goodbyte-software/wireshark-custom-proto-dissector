CFLAGS := '-Wall -O0 -g'
PORT := '9000'

# List available commands
default:
    @just --list

# Build and start client
client:
    gcc {{CFLAGS}} excom_client.c -o excom_client.elf
    socat -x TCP:localhost:{{PORT}} EXEC:./excom_client.elf

# Build and start server
server:
    gcc {{CFLAGS}} excom_server.c -o excom_server.elf
    socat -x TCP-LISTEN:{{PORT}},reuseaddr,fork EXEC:./excom_server.elf

# Start wireshark
wireshark:
    wireshark -X lua_script:./excom_protocol.lua -k -i lo -f 'port {{PORT}}'
