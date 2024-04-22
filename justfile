CFLAGS := '-Wall -O0 -g'
PORT := '9000'

# List available commands
default:
    @just --list

# Build and start client
client: (_build "excom_client")
    socat -x TCP:localhost:{{PORT}} EXEC:./excom_client.elf

# Build and start spam client variant
spam_client: (_build "excom_spam_client")
    gcc {{CFLAGS}} excom_spam_client.c -o excom_spam_client.elf
    socat -x TCP:localhost:{{PORT}} EXEC:./excom_spam_client.elf

# Build and start server
server: (_build "excom_server")
    socat -x TCP-LISTEN:{{PORT}},reuseaddr,fork EXEC:./excom_server.elf

# Start wireshark
wireshark:
    wireshark -X lua_script:./excom_protocol.lua -k -i lo -f 'port {{PORT}}'

_build BASENAME:
    gcc {{CFLAGS}} {{BASENAME}}.c -o {{BASENAME}}.elf
