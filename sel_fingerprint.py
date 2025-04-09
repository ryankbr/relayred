import asyncio
import re
import telnetlib3

async def telnet_command(ip, port=23, command="id"):
    """
    Connects to the given IP and port using telnetlib3,
    sends the provided command, and returns the full output.
    """
    reader, writer = await telnetlib3.open_connection(ip, port)
    # Send the command followed by a newline.
    writer.write(command + "\r\n")
    await writer.drain()

    # Allow some time for the command to be executed and output to accumulate.
    await asyncio.sleep(1)

    # Read up to 4096 bytes from the server.
    output = await reader.read(4096)
    writer.close()
    return output

def parse_output(output):
    """
    Parses output lines that are in the format:
      "KEY=VALUE","EXTRA"
    into a dictionary mapping KEY to a dict with keys "value" and "extra".
    """
    parsed_dict = {}
    # Regex pattern to capture:
    # group(1): the key before '='
    # group(2): the value after '=' and before the closing quote
    # group(3): the extra value inside the second set of quotes.
    pattern = re.compile(r'"([^=]+)=([^"]+)"\s*,\s*"([^"]+)"')
    
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            key = match.group(1)
            value = match.group(2)
            extra = match.group(3)
            parsed_dict[key] = {"value": value, "extra": extra}
    
    return parsed_dict

async def connect_and_run(ip, port=23):
    """
    Connects to the specified IP via telnet, runs the "id" command,
    and returns a dictionary parsed from the command output.
    """
    output = await telnet_command(ip, port, "id")
    return parse_output(output)

# Example usage:
if __name__ == '__main__':
    # Replace with the target IP address.
    target_ip = "10.190.42.105"
    result = asyncio.run(connect_and_run(target_ip))
    print(result)

